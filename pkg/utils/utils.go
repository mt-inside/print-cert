package utils

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

const TimeFmt = "2006 Jan _2 15:04:05"

var (
	BrightStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Bold(true)
	InfoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Bold(true)
	AddrStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	TimeStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Bold(true)
	OkStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	WarnStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	FailStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))

	SInfo    = InfoStyle.Render("Info:")
	STrying  = BrightStyle.Render("Trying:")
	SOk      = OkStyle.Render("Ok:")
	SWarning = WarnStyle.Render("Warning:")
	SError   = FailStyle.Render("Error:")

	SYes = OkStyle.Render("yes")
	SNo  = FailStyle.Render("no")
)

func YesNo(test bool) string {
	if test {
		return SYes
	}
	return SNo
}

func RenderList(ss []string) string {
	if len(ss) == 0 {
		return InfoStyle.Render("<none>")
	}
	return AddrStyle.Render(strings.Join(ss, ", "))
}

func RenderOptionalString(s string) string {
	if s == "" {
		return InfoStyle.Render("<none>")
	}
	return BrightStyle.Render(s)
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

func RenderCertBasics(cert *x509.Certificate) string {
	return fmt.Sprintf("\t[%s -> %s] %s subj %s ca %t",
		RenderTime(cert.NotBefore, true), RenderTime(cert.NotAfter, false),
		BrightStyle.Render(cert.PublicKeyAlgorithm.String()), AddrStyle.Render(cert.Subject.String()),
		// No need to print Issuer, cause that's the Subject of the next cert in the chain
		cert.IsCA,
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
