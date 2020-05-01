#define ASIO_STANDALONE
#define _WIN32_WINDOWS 1
#define _SILENCE_CXX17_ALLOCATOR_VOID_DEPRECATION_WARNING 1
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <future>
#include <iostream>
#include <openssl/x509.h>
#include <thread>

std::mutex logMutex;

class Log {
public:
    Log() : lock(mutex) {
    }

    ~Log() = default;

    typedef std::ostream& (*Manipulator)(std::ostream&);

    Log& operator<<(Manipulator pf) {
        std::cout << pf;
        return *this;
    }

    template <typename T> Log& operator<<(const T& value) {
        std::cout << value;
        return *this;
    }

private:
    static inline std::mutex mutex;
    std::lock_guard<std::mutex> lock;
};

static Log log() {
    return Log{};
}

class Session : public std::enable_shared_from_this<Session> {
public:
    explicit Session(asio::io_service& service, asio::ssl::context& context) : socket(service, context) {
        buffer.resize(1024);
    }

    virtual ~Session() {
    }

    void start() {
        auto self = shared_from_this();
        socket.async_handshake(asio::ssl::stream_base::server, [self](const asio::error_code ec) {
            if (ec) {
                log() << "server async_handshake error: " << ec.message() << std::endl;
            } else {
                log() << "server async_handshake success" << std::endl;
                self->send("Hello World from Session!");
                self->receive();
            }
        });
    }

    void send(std::string msg) {
        auto self = shared_from_this();
        auto temp = std::make_shared<std::string>(std::move(msg));
        auto src = asio::buffer(temp->data(), temp->size());
        socket.async_write_some(src, [self, temp](const asio::error_code ec, const size_t length) {
            (void)temp;
            (void)length;

            if (ec) {
                log() << "server async_write_some error: " << ec.message() << std::endl;
            } else {
                log() << "server async_write_some success: " << length << std::endl;
            }
        });
    }

    asio::ssl::stream<asio::ip::tcp::socket>& get() {
        return socket;
    }

private:
    void receive() {
        auto self = shared_from_this();
        auto dst = asio::buffer(buffer.data(), buffer.size());
        socket.async_read_some(dst, [self](const asio::error_code ec, const size_t length) {
            if (ec) {
                log() << "server async_read_some error: " << ec.message() << std::endl;
            } else {
                auto msg = std::string(self->buffer.data(), length);
                log() << "server async_read_some success: " << msg << std::endl;
                self->receive();
            }
        });
    }

    std::string buffer;
    asio::ssl::stream<asio::ip::tcp::socket> socket;
};

class Server : public std::enable_shared_from_this<Server> {
public:
    explicit Server(const int port)
        : context(asio::ssl::context::tlsv13_server),
          acceptor(service, asio::ip::tcp::endpoint(asio::ip::tcp::v6(), port)) {

        context.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                            asio::ssl::context::single_dh_use);
        context.use_certificate_chain_file("server.crt");
        context.use_private_key_file("server.key", asio::ssl::context::pem);
        context.use_tmp_dh_file("dh2048.pem");

        session = std::make_shared<Session>(service, context);
    }

    virtual ~Server() {
        stop();
    }

    void start() {
        accept();
        thread = std::thread([this]() { service.run(); });
    }

    void stop() {
        if (thread.joinable()) {
            acceptor.close();
            service.stop();
            session.reset();
            sessions.clear();
            thread.join();
        }
    }

private:
    void accept() {
        auto self = shared_from_this();
        acceptor.async_accept(session->get().lowest_layer(), [self](const asio::error_code ec) {
            if (ec) {
                log() << "server async_accept error: " << ec.message() << std::endl;
            } else {
                if (!self->acceptor.is_open()) {
                    return;
                } else {
                    log() << "server async_accept success: "
                          << self->session->get().lowest_layer().remote_endpoint().address().to_string() << std::endl;
                    self->sessions.push_back(self->session);
                    self->session = std::make_shared<Session>(self->service, self->context);
                    self->sessions.back()->start();
                }
            }

            self->accept();
        });
    }

    asio::io_service service;
    asio::ssl::context context;
    asio::ip::tcp::acceptor acceptor;
    std::thread thread;
    std::shared_ptr<Session> session;
    std::vector<std::shared_ptr<Session>> sessions;
};

static void setException(std::promise<void>& promise, const asio::error_code& ec) {
    try {
        throw std::runtime_error("client async_connect error: " + ec.message());
    } catch (std::exception_ptr& e) {
        promise.set_exception(e);
    }
}

class Client : public std::enable_shared_from_this<Client> {
public:
    explicit Client() : context(asio::ssl::context::tlsv13_client), resolver(service), socket(service, context) {
        context.load_verify_file("server.crt");
        context.set_verify_mode(asio::ssl::verify_peer);
        context.set_verify_callback(std::bind(&Client::verify, this, std::placeholders::_1, std::placeholders::_2));

        buffer.resize(1024);
    }

    virtual ~Client() {
        stop();
    }

    void connect(const std::string& address, const int port) {
        std::promise<void> promise;

        const asio::ip::tcp::resolver::query query(address, std::to_string(port));
        using Endpoints = asio::ip::tcp::resolver::iterator;

        resolver.async_resolve(query, [&](const asio::error_code ec, const Endpoints endpoints) {
            if (ec) {
                setException(promise, ec);
            } else {
                log() << "client async_resolve success: " << endpoints->endpoint().address().to_string() << std::endl;
                socket.lowest_layer().async_connect(*endpoints, [&](const asio::error_code ec) {
                    if (ec) {
                        setException(promise, ec);
                    } else {
                        log() << "client async_connect success" << std::endl;
                        socket.async_handshake(asio::ssl::stream_base::client, [&](const asio::error_code ec) {
                            if (ec) {
                                setException(promise, ec);
                            } else {
                                log() << "client async_handshake success" << std::endl;
                                receive();
                                promise.set_value();
                            }
                        });
                    }
                });
            }
        });

        thread = std::thread([this]() { service.run(); });

        auto future = promise.get_future();
        if (future.wait_for(std::chrono::milliseconds(1000)) != std::future_status::ready) {
            throw std::runtime_error("connect timeout");
        }
        future.get();
    }

    void stop() {
        if (thread.joinable()) {
            service.stop();
            thread.join();
        }
    }

    void send(std::string msg) {
        auto self = shared_from_this();
        auto temp = std::make_shared<std::string>(std::move(msg));
        auto src = asio::buffer(temp->data(), temp->size());
        socket.async_write_some(src, [self, temp](const asio::error_code ec, const size_t length) {
            (void)temp;
            (void)length;

            if (ec) {
                log() << "client async_write_some error: " << ec.message() << std::endl;
            } else {
                log() << "client async_write_some success: " << length << std::endl;
            }
        });
    }

private:
    bool verify(const bool verified, asio::ssl::verify_context& ctx) {
        char name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), name, 256);
        log() << "client verify: " << name << std::endl;

        return verified;
    }

    void receive() {
        auto self = shared_from_this();
        auto dst = asio::buffer(buffer.data(), buffer.size());
        socket.async_read_some(dst, [self](const asio::error_code ec, const size_t length) {
            if (ec) {
                log() << "client async_read_some error: " << ec.message() << std::endl;
            } else {
                auto msg = std::string(self->buffer.data(), length);
                log() << "client async_read_some success: " << msg << std::endl;
                self->receive();
            }
        });
    }

    asio::io_service service;
    asio::ssl::context context;
    asio::ip::tcp::resolver resolver;
    asio::ssl::stream<asio::ip::tcp::socket> socket;
    std::thread thread;
    std::string buffer;
};

int main(const int argc, char** argv) {
    (void)argc;
    (void)argv;

    try {
        auto server = std::make_shared<Server>(12345);
        server->start();

        auto client = std::make_shared<Client>();
        client->connect("localhost", 12345);
        client->send("Hello World from Client!");

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    } catch (std::exception& e) {
        log() << "something went wrong: " << e.what() << std::endl;
    }

    return 0;
}
