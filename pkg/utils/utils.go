package utils

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
)

const TimeFmt = "Jan _2 15:04:05 2006"

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
)

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
