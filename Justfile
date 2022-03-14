default:
	@just --list

run *ARGS:
	go run ./cmd/print-cert {{ARGS}} localhost 8080
