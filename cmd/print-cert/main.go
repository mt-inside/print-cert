package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora/v3"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/* TODO
* - show dnssec and dane status of name
 */

func init() {
	spew.Config.DisableMethods = true
	spew.Config.DisablePointerMethods = true
}

func main() {

	cmd := &cobra.Command{
		Use:  "addr port scheme",
		Args: cobra.ExactArgs(3),
		Run:  appMain,
	}

	cmd.Flags().StringP("sni", "s", "", "SNI ServerName")
	cmd.Flags().StringP("host", "a", "", "HTTP Host / :authority header")
	cmd.Flags().StringP("path", "p", "/", "HTTP path to request")
	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA file")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate file")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key file")
	cmd.Flags().BoolP("kerberos", "n", false, "Negotiate Kerberos auth")
	cmd.Flags().BoolP("print-body", "b", false, "Print the returned HTTP body")
	cmd.Flags().BoolP("http-11", "", false, "Force http1.1 (no attempt to negotiate http2")
	viper.BindPFlag("sni", cmd.Flags().Lookup("sni"))
	viper.BindPFlag("host", cmd.Flags().Lookup("host"))
	viper.BindPFlag("path", cmd.Flags().Lookup("path"))
	viper.BindPFlag("ca", cmd.Flags().Lookup("ca"))
	viper.BindPFlag("cert", cmd.Flags().Lookup("cert"))
	viper.BindPFlag("key", cmd.Flags().Lookup("key"))
	viper.BindPFlag("kerberos", cmd.Flags().Lookup("kerberos"))
	viper.BindPFlag("printBody", cmd.Flags().Lookup("print-body"))
	viper.BindPFlag("http11", cmd.Flags().Lookup("http11"))

	err := cmd.Execute()
	if err != nil {
		fmt.Println("Error during execution: %v", err)
	}
}

func appMain(cmd *cobra.Command, args []string) {

	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := output.NewTtyBios(s)

	addr := args[0]
	port := args[1]
	scheme := args[2]
	if !(scheme == "http" || scheme == "https") {
		b.CheckErr(fmt.Errorf("Unknown scheme: %s", scheme))
	}

	var ip net.IP

	b.Banner("DNS")

	ip = net.ParseIP(addr)
	if ip == nil {
		ips := probes.CheckDNS2(s, b, addr)
		for _, ip := range ips {
			revName := probes.CheckRevDNS2(s, b, ip)
			probes.CheckDnsConsistent(s, b, addr, revName)
		}
	} else {
		name := probes.CheckRevDNS2(s, b, ip)
		probes.CheckDNS2(s, b, name)
		// Kinda incorrect to check the consistency here. We just do the double reverse as a helpful way to maybe find peers if the IP we've been given
	}

	host := viper.GetString("host")
	if host == "" {
		host = addr
	}
	sni := viper.GetString("sni")
	if sni == "" {
		sni = host
	}

	var client *http.Client
	switch scheme {
	case "http":
		client = probes.GetPlaintextClient(s, b)
	case "https":
		client = probes.GetTLSClient(s, b, sni, viper.GetString("ca"), viper.GetString("cert"), viper.GetString("key"), viper.GetBool("kerberos"), viper.GetBool("http11"))
	}

	req, cancel := probes.GetHttpRequest(s, b, scheme, addr, port, host, viper.GetString("path"))
	defer cancel()

	rawBody := probes.CheckTls(
		s, b,
		client,
		req,
	)

	if viper.GetBool("printBody") {
		fmt.Println(string(rawBody))
	}

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}
