package main

import (
	"fmt"
	"os"

	"github.com/logrusorgru/aurora/v3"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

func main() {
	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := bios.NewTtyBios(s)

	path := os.Args[1]

	bytes, err := os.ReadFile(path)
	b.Unwrap(err)
	certs, err := codec.ParseCertificates(bytes)
	b.Unwrap(err)
	fmt.Println(s.ServingCertChain(certs))
}
