# print-cert

[![build](https://github.com/mt-inside/print-cert/actions/workflows/test.yaml/badge.svg)](https://github.com/mt-inside/print-cert/actions/workflows/test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mt-inside/print-cert.svg)](https://pkg.go.dev/github.com/mt-inside/print-cert)
[![Go Report Card](https://goreportcard.com/badge/github.com/mt-inside/print-cert)](https://goreportcard.com/report/github.com/mt-inside/print-cert)

## Use

Run from container image:
```bash
docker run -t --rm ghcr.io/mt-inside/print-cert:v0.2.2 mt165.co.uk
```

Download single, statically-linked binary
```bash
wget -O print-cert https://github.com/mt-inside/print-cert/releases/download/v0.2.2/print-cert-$(uname -s)-$(uname -m)
chmod u+x print-cert
./print-cert mt165.co.uk
```

Install from source
```bash
go install github.com/mt-inside/print-cert/cmd/print-cert@latest
${GOPATH}/bin/print-cert mt165.co.uk
```
