package utils

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

const TimeFmt = "2006 Jan _2 15:04:05"

var (
	InfoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	FailStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	OkStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	WarnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	AddrStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	VerbStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
	NounStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	BrightStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))

	SInfo    = InfoStyle.Copy().Bold(true).Render("Info:")
	STrying  = BrightStyle.Copy().Bold(true).Render("Trying:")
	SOk      = OkStyle.Copy().Bold(true).Render("Ok:")
	SWarning = WarnStyle.Copy().Bold(true).Render("Warning:")
	SError   = FailStyle.Copy().Bold(true).Render("Error:")

	SYes = OkStyle.Copy().Bold(true).Render("yes")
	SNo  = FailStyle.Copy().Bold(true).Render("no")
)

func RenderYesNo(test bool) string {
	if test {
		return SYes
	}
	return SNo
}

func RenderOptionalString(s string, style lipgloss.Style) string {
	if s == "" {
		return InfoStyle.Render("<none>")
	}
	return style.Render(s)
}

func RenderTime(t time.Time, start bool) string {
	if start {
		if t.After(time.Now()) {
			return FailStyle.Render(t.Format(TimeFmt))
		} else {
			return OkStyle.Render(t.Format(TimeFmt))
		}
	} else {
		if t.Before(time.Now()) {
			return FailStyle.Render(t.Format(TimeFmt))
		} else if t.Before(time.Now().Add(240 * time.Hour)) {
			return WarnStyle.Render(t.Format(TimeFmt))
		} else {
			return OkStyle.Render(t.Format(TimeFmt))
		}
	}
}

func RenderList(ss []string) string {
	if len(ss) == 0 {
		return InfoStyle.Render("<none>")
	}
	return strings.Join(ss, ", ")
}

func RenderDNSList(names []string) string {
	var ss []string
	for _, name := range names {
		ss = append(ss, AddrStyle.Render(name))
	}
	return RenderList(ss)
}
func RenderIPList(ips []net.IP) string {
	var ss []string
	for _, ip := range ips {
		ss = append(ss, AddrStyle.Render(ip.String()))
	}
	return RenderList(ss)
}

func RenderCertBasics(cert *x509.Certificate) string {
	caFlag := InfoStyle.Render("non-ca")
	if cert.IsCA {
		caFlag = OkStyle.Render("ca")
	}

	return fmt.Sprintf("\t[%s -> %s] %s subj %s [%s]",
		RenderTime(cert.NotBefore, true), RenderTime(cert.NotAfter, false),
		NounStyle.Render(cert.PublicKeyAlgorithm.String()), AddrStyle.Render(cert.Subject.String()),
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
	fmt.Println(BrightStyle.Render(fmt.Sprintf("== %s ==", s)))
	fmt.Println()
}
