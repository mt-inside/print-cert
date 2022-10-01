default:
	@just --list

install-tools:
	go install golang.org/x/tools/cmd/stringer@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

generate:
	go generate ./...

lint: generate
	go fmt ./...
	go vet ./...
	staticcheck ./...
	golangci-lint run ./... # TODO: --enable-all
	go test ./...

install *ARGS: generate lint
	go install ./cmd/print-cert {{ARGS}}

print-cert *ARGS: generate lint
	go run ./cmd/print-cert {{ARGS}} localhost 8080 https

print-cert-mtls-jwt *ARGS: generate lint
	# FIXME: hard-coded path
	go run ./cmd/print-cert -k=ssl/client-key.pem -c=ssl/client-cert.pem -C=ssl/server-ca-cert.pem --bearer /home/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt -s example.com -T -B {{ARGS}} localhost 8080 https

curl-mtls-jwt-body *ARGS: generate lint
	# FIXME: hard-coded path
	# TODO: ability to send request body
	curlie --key ssl/client-key.pem --cert ssl/client-cert.pem --cacert ssl/server-ca-cert.pem --oauth2-bearer "$(cat /home/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt)" https://example.com --connect-to example.com:443:localhost:8080 --data-binary @test/body.txt
curl-mtls-self-sign-jwt-body *ARGS: generate lint
	# FIXME: hard-coded path
	# TODO: ability to send request body
	curlie --key ssl/client-key.pem --cert ssl/client-cert.pem --insecure --oauth2-bearer "$(cat /home/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt)" https://example.com --connect-to example.com:443:localhost:8080 --data-binary @test/body.txt


compare *ARGS: generate lint
	go run ./cmd/compare {{ARGS}} localhost 8080 127.0.0.1 8443 https

nginx-build:
	docker build -t nginx-mutual nginx

nginx-run:
	docker run -v ${PWD}/ssl:/etc/ssl -p 8443:443 nginx-mutual
