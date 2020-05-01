# Asio TLS example

This is an example that uses [asio](https://think-async.com/Asio/) network library with [openssl](https://www.openssl.org/) to create a TCP connection encrypted via TLS v1.3

## Usage

1. Generate keys and certificate using the `certs.bat` script and put them in the build working folder.
2. Compile the example (you will need [vcpkg](https://github.com/Microsoft/vcpkg) to do that!)
3. Run the example

The example will start a server with `server.crt`, `server.key`, and `dh2048.pem`, then it will start a client with `server.crt` and sends a simple `"Hello World from Client!"` message over TCP socket. No https. The application will exit after 2 seconds automatically.

## License

The Unlicense (public domain).

