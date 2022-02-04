package utils

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

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
		return "<none>"
	}
	return s
}

func RenderCertBasics(cert *x509.Certificate) string {
	return fmt.Sprintf("\t[%s -> %s] %s subj %s (iss %s %s) ca %t",
		TimeStyle.Render(cert.NotBefore.Format(TimeFmt)), TimeStyle.Render(cert.NotAfter.Format(TimeFmt)),
		BrightStyle.Render(cert.PublicKeyAlgorithm.String()), AddrStyle.Render(cert.Subject.String()),
		AddrStyle.Render(renderIssuer(cert)), BrightStyle.Render(cert.SignatureAlgorithm.String()),
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
