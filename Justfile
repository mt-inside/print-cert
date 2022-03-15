default:
	@just --list

lint:
	go fmt ./...
	go vet ./...
	golint ./...
	golangci-lint run ./...
	go test ./...

print-cert *ARGS: #lint
	go run ./cmd/print-cert {{ARGS}} localhost 8443

compare *ARGS: #lint
	go run ./cmd/single-ip {{ARGS}} localhost 8443 127.0.0.1 8080 https

nginx-build:
	docker build -t nginx-mutual nginx

nginx-run:
	docker run -v ${PWD}/ssl:/etc/ssl -p 8443:443 nginx-mutual
