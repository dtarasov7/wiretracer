mkdir -p certs && cd certs

# CA
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=fault-ca"

# Server key/csr/cert (CN=localhost, SAN=localhost,127.0.0.1)
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
cat > server.ext <<'EOF'
subjectAltName = DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 3650 -extfile server.ext

# Client key/csr/cert
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=fault-client"
cat > client.ext <<'EOF'
extendedKeyUsage = clientAuth
EOF
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 3650 -extfile client.ext
