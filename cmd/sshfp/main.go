//go:generate stringer -linecomment -type=sshfpKeyAlgorithm,sshfpFingerprintType

package main

import (
	"fmt"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora/v3"
	"github.com/miekg/dns"
	"github.com/peterzen/goresolver"

	"github.com/mt-inside/http-log/pkg/output"
)

func init() {
	spew.Config.DisableMethods = true
	spew.Config.DisablePointerMethods = true
}

type sshfpKeyAlgorithm uint8

const (
	sshfpKeyAlgorithmReserved sshfpKeyAlgorithm = 0 // Reserved
	sshfpKeyAlgorithmRSA      sshfpKeyAlgorithm = 1 // RSA
	sshfpKeyAlgorithmDSA      sshfpKeyAlgorithm = 2 // DSA
	sshfpKeyAlgorithmECDSA    sshfpKeyAlgorithm = 3 // ECDSA
	sshfpKeyAlgorithmEd25519  sshfpKeyAlgorithm = 4 // Ed25519
	sshfpKeyAlgorithmEd448    sshfpKeyAlgorithm = 6 // Ed448
)

type sshfpFingerprintType uint8

const (
	sshfpFingerprintTypeReserved sshfpFingerprintType = 0 // Reserved
	sshfpFingerprintTypeSHA1     sshfpFingerprintType = 1 // SHA-1
	sshfpFingerprintTypeSHA256   sshfpFingerprintType = 2 // SHA-256
)

func main() {
	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := output.NewTtyBios(s, 10)

	resolver, err := goresolver.NewResolver("/etc/resolv.conf")
	b.Unwrap(err)

	results, err := resolver.StrictNSQuery(dns.CanonicalName(os.Args[1]), dns.TypeSSHFP)
	b.Unwrap(err)

	fmt.Println("DNSSEC ok")

	for _, r := range results {
		sshfp := r.(*dns.SSHFP)
		fmt.Printf(
			"Key: %s. Fingerprint: %s %s\n",
			sshfpKeyAlgorithm(sshfp.Algorithm).String(),
			sshfpFingerprintType(sshfp.Type).String(),
			sshfp.FingerPrint,
		)
	}
}
