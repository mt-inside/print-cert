set dotenv-load

default:
	@just --list

DH_USER := "mtinside"
REPO := "docker.io/" + DH_USER + "/print-cert"
TAG := `git describe --tags --abbrev`
TAGD := `git describe --tags --abbrev --dirty`
CGR_ARCHS := "aarch64" # "amd64,aarch64,armv7"

install-tools:
	go install golang.org/x/tools/cmd/stringer@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

generate:
	go generate ./...

lint: generate
	goimports -local github.com/mt-inside/http-log -w .
	go vet ./...
	staticcheck ./...
	golangci-lint run ./... # TODO: --enable-all
	go test ./...

build: lint
	# We don't statically link here (although we do use CGO), so the resulting binary isn't quite the same as what ends up in the container, but close
	go build ./cmd/print-cert

build-no-cgo: lint
	# For testing; we expect it to be built *with* CGO in the wild
	CGO_ENABLED=0 go build ./cmd/print-cert

install *ARGS: generate lint
	go install ./cmd/print-cert {{ARGS}}

MELANGE := "docker run --pull always --rm --privileged -v ${PWD}:/work cgr.dev/chainguard/melange:latest"
APKO    := "docker run --pull always --rm -v ${PWD}:/work cgr.dev/chainguard/apko:latest"
APKO_SH := "docker run --pull always --rm -v ${PWD}:/work --entrypoint sh cgr.dev/chainguard/apko:latest"

melange:
	{{MELANGE}} keygen
	{{MELANGE}} build --arch {{CGR_ARCHS}} --signing-key /work/melange.rsa melange.yaml

package:
	{{APKO}} build --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}} print-cert.tar
	docker load < print-cert.tar
publish:
	{{APKO_SH}} -c \
		'echo "'${DH_TOKEN}'" | apko login docker.io -u {{DH_USER}} --password-stdin && \
		apko publish apko.yaml {{REPO}}:{{TAG}} --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}}'

print-cert *ARGS: generate lint
	go run ./cmd/print-cert {{ARGS}} localhost:8080

print-cert-mtls-jwt *ARGS: generate lint
	# FIXME: hard-coded path
	go run ./cmd/print-cert -k=ssl/client-key.pem -c=ssl/client-cert.pem -C=ssl/server-ca-cert.pem --bearer /Users/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt -s example.com -T -B {{ARGS}} localhost:8080

curl-mtls-jwt-body *ARGS: generate lint
	# FIXME: hard-coded path
	# TODO: ability to send request body
	curlie --key ssl/client-key.pem --cert ssl/client-cert.pem --cacert ssl/server-ca-cert.pem --oauth2-bearer "$(cat /Users/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt)" https://example.com --connect-to example.com:443:localhost:8080 --data-binary @test/body.txt
curl-mtls-self-sign-jwt-body *ARGS: generate lint
	# FIXME: hard-coded path
	# TODO: ability to send request body
	curlie --key ssl/client-key.pem --cert ssl/client-cert.pem --insecure --oauth2-bearer "$(cat /Users/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt)" https://example.com --connect-to example.com:443:localhost:8080 --data-binary @test/body.txt


compare *ARGS: generate lint
	go run ./cmd/compare {{ARGS}} localhost:8080 127.0.0.1:8443

nginx-build:
	docker build -t nginx-mutual nginx

nginx-run:
	docker run -v ${PWD}/ssl:/etc/ssl -p 8443:443 nginx-mutual
