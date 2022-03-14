default:
	@just --list

print-cert *ARGS:
	go run ./cmd/print-cert {{ARGS}} localhost 8080

compare *ARGS:
	go run ./cmd/single-ip {{ARGS}} localhost 8080 127.0.0.1 8081 http
