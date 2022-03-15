package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/logrusorgru/aurora/v3"
)

const TimeFmt = "2006 Jan _2 15:04:05"

var (
	InfoStyle   = aurora.BlackFg | aurora.BrightFg
	FailStyle   = aurora.RedFg
	OkStyle     = aurora.GreenFg
	WarnStyle   = aurora.YellowFg
	AddrStyle   = aurora.BlueFg
	VerbStyle   = aurora.MagentaFg
	NounStyle   = aurora.CyanFg
	BrightStyle = aurora.WhiteFg | aurora.BrightFg

	SInfo    = aurora.Colorize("Info:", InfoStyle)
	STrying  = aurora.Colorize("Trying:", BrightStyle)
	SOk      = aurora.Colorize("Ok:", OkStyle)
	SWarning = aurora.Colorize("Warning:", WarnStyle)
	SError   = aurora.Colorize("Error:", FailStyle)

	SYes = aurora.Colorize("yes", OkStyle)
	SNo  = aurora.Colorize("no", FailStyle)
)

func RenderYesNo(test bool) aurora.Value {
	if test {
		return SYes
	}
	return SNo
}

func RenderYesError(err error) aurora.Value {
	if err == nil {
		return SYes
	}
	return aurora.Colorize(err, FailStyle)
}

func RenderOptionalString(s string, style aurora.Color) aurora.Value {
	if s == "" {
		return aurora.Colorize("<none>", InfoStyle)
	}
	return aurora.Colorize(s, style)
}

func RenderTime(t time.Time, start bool) aurora.Value {
	if start {
		if t.After(time.Now()) {
			return aurora.Colorize(t.Format(TimeFmt), FailStyle)
		} else {
			return aurora.Colorize(t.Format(TimeFmt), OkStyle)
		}
	} else {
		if t.Before(time.Now()) {
			return aurora.Colorize(t.Format(TimeFmt), FailStyle)
		} else if t.Before(time.Now().Add(240 * time.Hour)) {
			return aurora.Colorize(t.Format(TimeFmt), WarnStyle)
		} else {
			return aurora.Colorize(t.Format(TimeFmt), OkStyle)
		}
	}
}

func RenderList(ss []string) string {
	if len(ss) == 0 {
		return aurora.Colorize("<none>", InfoStyle).String()
	}
	render := strings.Join(ss, ", ")
	// TODO broken cause the color escapes are counted in the length, and they also spill over into the ...
	if len(render) >= 80 {
		return render[:76] + "..."
	}
	return render
}

func RenderDNSList(names []string) string {
	var ss []string
	for _, name := range names {
		ss = append(ss, aurora.Colorize(name, AddrStyle).String())
	}
	return RenderList(ss)
}
func RenderIPList(ips []net.IP) string {
	var ss []string
	for _, ip := range ips {
		ss = append(ss, aurora.Colorize(ip.String(), AddrStyle).String())
	}
	return RenderList(ss)
}

func renderIssuer(cert *x509.Certificate) aurora.Value {
	if cert.Issuer.String() == cert.Subject.String() {
		return aurora.Colorize("<self-signed>", InfoStyle)
	}
	return aurora.Colorize(cert.Issuer.String(), AddrStyle)
}

func renderPublicKeyInfo(pk crypto.PublicKey) string {
	switch pubKey := pk.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA:%d", pubKey.Size()*8) // private and public are same; it's the length of the shared modulus
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA:%s", pubKey.Params().Name) // private and public are same; it's a fundamental property of the curve, implied by the curve name
	case ed25519.PublicKey:
		return fmt.Sprintf("Ed25519(%d)", ed25519.PrivateKeySize*8) // Constant size
	default:
		panic(errors.New("bottom"))
	}
}

func RenderCertBasics(cert *x509.Certificate) string {
	caFlag := aurora.Colorize("non-ca", InfoStyle)
	if cert.IsCA {
		caFlag = aurora.Colorize("ca", OkStyle)
	}

	return fmt.Sprintf(
		"[%s -> %s] key %s sig %s subj %s [%s]",
		RenderTime(cert.NotBefore, true),
		RenderTime(cert.NotAfter, false),
		aurora.Colorize(renderPublicKeyInfo(cert.PublicKey), NounStyle),
		aurora.Colorize(cert.SignatureAlgorithm, NounStyle),
		aurora.Colorize(cert.Subject.String(), AddrStyle),
		// No need to print Issuer, cause that's the Subject of the next cert in the chain
		caFlag,
	)
}

func RenderClientCertChain(certs ...*x509.Certificate) {
	for i, cert := range certs {
		fmt.Printf("\t%d: %s\n", i, RenderCertBasics(cert))
	}
	fmt.Printf("\t%d: %s\n", len(certs), renderIssuer(certs[len(certs)-1]))
}

func RenderServingCertChain(name *string, ip *net.IP, peerCerts []*x509.Certificate, verifiedCerts []*x509.Certificate) {
	var addr string
	if name != nil {
		addr = *name
	} else if ip != nil {
		addr = "[" + ip.String() + "]"
	} else {
		panic(errors.New("Need either a name or IP to check serving cert against"))
	}

	head := peerCerts[0]

	fmt.Printf("\t0 (presented): %s\n", RenderCertBasics(head))
	fmt.Printf("\t\tDNS SANs %s\n", RenderDNSList(head.DNSNames))
	fmt.Printf("\t\tIP SANs %s\n", RenderIPList(head.IPAddresses))
	fmt.Printf(
		"\t\tSNI %s in SANs? %s (CN? %s)\n",
		aurora.Colorize(*name, AddrStyle),
		RenderYesError(head.VerifyHostname(addr)),
		RenderYesNo(strings.ToLower(head.Subject.CommonName) == strings.ToLower(*name)),
	)

	certs := verifiedCerts
	if certs == nil {
		certs = peerCerts
	}

	for i := 1; i < len(certs); i++ {
		fmt.Printf("\t%d", i)

		if i < len(peerCerts) && certs[i].Equal(peerCerts[i]) {
			fmt.Printf(" (presented):")
		} else {
			fmt.Printf(" (installed):")
		}

		fmt.Printf(" %s\n", RenderCertBasics(certs[i]))
	}

	fmt.Printf("\t%d: %s\n", len(certs), renderIssuer(certs[len(certs)-1]))
}

func CheckInfo(err error) bool {
	if err != nil {
		fmt.Printf("%s %v\n", SInfo, err)
		return false
	}
	return true
}

func CheckWarn(err error) bool {
	if err != nil {
		fmt.Printf("%s %v\n", SWarning, err)
		return false
	}
	return true
}

func CheckErr(err error) {
	if err != nil {
		//panic(err) - for backtraces
		fmt.Printf("%s %v\n", SError, err)
		os.Exit(1)
	}
}

func CheckOk(ok bool) {
	if !ok {
		//panic(errors.New("Not OK!"))
		fmt.Printf("%s Not OK!\n", SError)
		os.Exit(1)
	}
}

func Banner(s string) {
	fmt.Println()
	fmt.Println(aurora.Colorize(fmt.Sprintf("== %s ==", s), BrightStyle))
	fmt.Println()
}

// TODO will be in stdlib anytime now... https://go-review.googlesource.com/c/go/+/321733/, https://github.com/golang/go/issues/46308
func versionName(tlsVersion uint16) string {
	switch tlsVersion {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		panic(errors.New("Unknown TLS version"))
	}
}
