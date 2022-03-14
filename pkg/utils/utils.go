package utils

import (
	"crypto/x509"
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
	return strings.Join(ss, ", ")
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

func RenderCertBasics(cert *x509.Certificate) string {
	caFlag := aurora.Colorize("non-ca", InfoStyle)
	if cert.IsCA {
		caFlag = aurora.Colorize("ca", OkStyle)
	}

	return fmt.Sprintf("\t[%s -> %s] %s subj %s [%s]",
		RenderTime(cert.NotBefore, true), RenderTime(cert.NotAfter, false),
		aurora.Colorize(cert.PublicKeyAlgorithm.String(), NounStyle), aurora.Colorize(cert.Subject.String(), AddrStyle),
		// No need to print Issuer, cause that's the Subject of the next cert in the chain
		caFlag,
	)
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
		fmt.Printf("%s %v\n", SError, err)
		panic(err)
		os.Exit(1)
	}
}

func Banner(s string) {
	fmt.Println()
	fmt.Println(aurora.Colorize(fmt.Sprintf("== %s ==", s), BrightStyle))
	fmt.Println()
}
