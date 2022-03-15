openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=Test CA" -days 365 -keyout server-ca-key.pem -out server-ca-cert.pem

server_ext="
subjectAltName=DNS:example.com
"

openssl req -new -newkey rsa:2048 -nodes -subj "/CN=Test Server" -keyout server-key.pem -out server-csr.pem
openssl x509 -req -in server-csr.pem -extfile <(echo $server_ext) -CAcreateserial -days 365 -CA server-ca-cert.pem -CAkey server-ca-key.pem -out server-cert.pem

cat server-cert.pem server-ca-cert.pem > server-cert-bundle.pem


openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=Test CA" -days 365 -keyout client-ca-key.pem -out client-ca-cert.pem

client_ext="
subjectAltName=DNS:example.com
extendedKeyUsage=clientAuth
"

openssl req -new -newkey rsa:2048 -nodes -subj "/CN=Test Client" -keyout client-key.pem -out client-csr.pem
openssl x509 -req -in client-csr.pem -extfile <(echo $client_ext) -CAcreateserial -days 365 -CA client-ca-cert.pem -CAkey client-ca-key.pem -out client-cert.pem

cat client-cert.pem client-ca-cert.pem > client-cert-bundle.pem
