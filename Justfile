default:
	@just --list

print-cert *ARGS:
	go run ./cmd/print-cert {{ARGS}} localhost 8443

compare *ARGS:
	go run ./cmd/single-ip {{ARGS}} localhost 8080 127.0.0.1 8081 https

nginx-build:
	docker build -t nginx-mutual nginx

nginx-run:
	docker run -v ${PWD}/ssl:/etc/ssl -p 8443:443 nginx-mutual
