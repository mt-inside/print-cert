package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/logrusorgru/aurora/v3"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

func main() {
	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := bios.NewTtyBios(s)

	if len(os.Args) != 2 {
		fmt.Println("Usage: local-cert [file,-]")
		os.Exit(2)
	}
	path := os.Args[1]

	var bytes []byte
	var err error

	if path == "-" {
		si := bufio.NewReader(os.Stdin)
		bytes, err = io.ReadAll(si)
	} else {
		bytes, err = os.ReadFile(path)
	}
	b.Unwrap(err)

	certs, err := codec.ParseCertificates(bytes)
	b.Unwrap(err)
	fmt.Println(s.ServingCertChain(certs))
}
