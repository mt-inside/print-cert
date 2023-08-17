set dotenv-load

default:
	@just --list --unsorted --color=always

DH_USER := "mtinside"
REPO := "docker.io/" + DH_USER + "/print-cert"
TAG := `git describe --tags --always --abbrev`
TAGD := `git describe --tags --always --abbrev --dirty --broken`
CGR_ARCHS := "aarch64,amd64" # "x86,armv7"
LD_COMMON := "-ldflags \"-X 'github.com/mt-inside/print-cert/internal/build.Version=" + TAGD + "'\""
LD_STATIC := "-ldflags \"-X 'github.com/mt-inside/print-cert/internal/build.Version=" + TAGD + "' -w -linkmode external -extldflags '-static'\""
MELANGE := "melange"
APKO    := "apko"

tools-install:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/exp/cmd/...@latest
	go install github.com/kisielk/godepgraph@latest
	go install golang.org/x/tools/cmd/stringer@latest

generate:
	go generate ./...

lint: generate
	gofmt -s -w .
	goimports -local github.com/mt-inside/http-log -w .
	go vet ./...
	staticcheck ./...
	golangci-lint run ./... # TODO: --enable-all

test: lint
	go test ./... -race -covermode=atomic -coverprofile=coverage.out

render-mod-graph:
	go mod graph | modgraphviz | dot -Tpng -o mod_graph.png

render-pkg-graph:
	godepgraph -s -onlyprefixes github.com/mt-inside ./cmd/http-log | dot -Tpng -o pkg_graph.png

build-dev: test
	# Use CGO here, like in the container, so this binary is pretty representative.
	# We don't statically link here (although we do use CGO), so the resulting binary isn't quite the same as what ends up in the container, but close
	go build {{LD_COMMON}} ./cmd/print-cert

build-dev-no-cgo: test
	# For testing; we expect it to be built *with* CGO in the wild
	CGO_ENABLED=0 go build {{LD_COMMON}} ./cmd/print-cert

# Don't lint/test, because it doesn't work in various CI envs
build-ci *ARGS:
	# We use CGO, so that we get libc's sophisticated name resolution etc. This is basically pointless because we're in a container which won't have NIS/LDAP/etc set up, but maybe someone wants to mount that config in?
	# Since we use CGO, force gcc's ld, and tell it to statically link libc in, for ease of packaging in a container
	go build {{LD_STATIC}} {{ARGS}} ./cmd/print-cert

install: test
	go install {{LD_COMMON}} ./cmd/print-cert

package: test
	# if there's >1 package in this directory, apko seems to pick the _oldest_ without fail
	rm -rf ./packages/
	{{MELANGE}} bump melange.yaml {{TAGD}}
	{{MELANGE}} keygen
	{{MELANGE}} build --arch {{CGR_ARCHS}} --signing-key melange.rsa melange.yaml

image-local:
	{{APKO}} build --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}} print-cert.tar
	docker load < print-cert.tar
image-publish:
	{{APKO}} login docker.io -u {{DH_USER}} --password "${DH_TOKEN}"
	{{APKO}} publish --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}}
cosign-sign:
	# Experimental includes pushing the signature to a Rekor transparency log, default: rekor.sigstore.dev
	COSIGN_EXPERIMENTAL=1 cosign sign {{REPO}}:{{TAG}}

image-ls:
	hub-tool tag ls --platforms {{REPO}}
image-inspect:
	docker buildx imagetools inspect {{REPO}}:{{TAG}}
sbom-show:
	docker sbom {{REPO}}:{{TAG}}
snyk:
	snyk test .
	snyk container test {{REPO}}:{{TAG}}
cosign-verify:
	COSIGN_EXPERIMENTAL=1 cosign verify {{REPO}}:{{TAG}} | jq .

clean:
	rm -f coverage.out
	rm -f mod_graph.png pkg_graph.png
	rm -f sbom-*
	rm -rf packages/
	rm -f print-cert.tar
	rm -f print-cert
	rm -f melange.rsa*

print-cert *ARGS: test
	go run {{LD_COMMON}} ./cmd/print-cert {{ARGS}} localhost:8080

print-cert-mtls-jwt *ARGS: test
	# FIXME: hard-coded path
	go run {{LD_COMMON}} ./cmd/print-cert -k=ssl/client-key.pem -c=ssl/client-cert.pem -C=ssl/server-ca-cert.pem --bearer /Users/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt -s example.com -T -B {{ARGS}} localhost:8080

curl-mtls-jwt-body *ARGS: test
	# FIXME: hard-coded path
	# TODO: ability to send request body
	curlie --key ssl/client-key.pem --cert ssl/client-cert.pem --cacert ssl/server-ca-cert.pem --oauth2-bearer "$(cat /Users/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt)" https://example.com --connect-to example.com:443:localhost:8080 --data-binary @test/body.txt
curl-mtls-self-sign-jwt-body *ARGS: test
	# FIXME: hard-coded path
	# TODO: ability to send request body
	curlie --key ssl/client-key.pem --cert ssl/client-cert.pem --insecure --oauth2-bearer "$(cat /Users/matt/work/personal/talks/istio-demo-master/41/pki/one.jwt)" https://example.com --connect-to example.com:443:localhost:8080 --data-binary @test/body.txt


compare *ARGS: test
	go run {{LD_COMMON}} ./cmd/compare {{ARGS}} localhost:8080 127.0.0.1:8443

nginx-build:
	docker build -t nginx-mutual nginx

nginx-run:
	docker run -v ${PWD}/ssl:/etc/ssl -p 8443:443 nginx-mutual
