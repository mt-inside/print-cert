default:
	@just --list

install-linters:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

lint:
	go fmt ./...
	go vet ./...
	#staticcheck ./... - waiting for go1.18 support
	golangci-lint run ./...
	go test ./...

print-cert *ARGS: lint
	go run ./cmd/print-cert {{ARGS}} localhost 8080 https

compare *ARGS: lint
	go run ./cmd/single-ip {{ARGS}} localhost 8080 127.0.0.1 8443 https

nginx-build:
	docker build -t nginx-mutual nginx

nginx-run:
	docker run -v ${PWD}/ssl:/etc/ssl -p 8443:443 nginx-mutual
