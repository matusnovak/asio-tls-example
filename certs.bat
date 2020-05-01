openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=AU/ST=Some-State/L=Example/O=Example/OU=Example/CN=server"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
openssl dhparam -out dh2048.pem 2048
