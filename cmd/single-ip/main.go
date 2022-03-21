package main

import (
	"fmt"
	"net"
	"os"

	"github.com/logrusorgru/aurora/v3"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/print-cert/pkg/probes"
	dmp "github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {

	cmd := &cobra.Command{
		Use:  "f5Name f5Port nsIP f5Port scheme",
		Args: cobra.ExactArgs(5),
		Run:  appMain,
	}

	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate file")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate file")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key file")
	cmd.Flags().BoolP("print-body", "b", false, "Print the returned HTTP body")
	viper.BindPFlag("ca", cmd.Flags().Lookup("ca"))
	viper.BindPFlag("cert", cmd.Flags().Lookup("cert"))
	viper.BindPFlag("key", cmd.Flags().Lookup("key"))
	viper.BindPFlag("printBody", cmd.Flags().Lookup("print-body"))

	err := cmd.Execute()
	if err != nil {
		fmt.Println("Error during execution: %v", err)
	}
}

func appMain(cmd *cobra.Command, args []string) {

	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := output.NewTtyBios(s)

	f5Host := args[0]
	f5Port := args[1]
	nsIp := net.ParseIP(args[2])
	nsPort := args[3]
	scheme := args[4]

	if nsIp == nil {
		b.CheckErr(fmt.Errorf("Invalid IP: %s", args[2]))
	}
	if !(scheme == "http" || scheme == "https") {
		b.CheckErr(fmt.Errorf("Unknown scheme: %s", scheme))
	}

	fmt.Printf("Testing NetScaler VIP %v against F5 service %v\n", s.Addr(nsIp.String()), s.Addr(f5Host))

	/* Check DNS */

	b.Banner("DNS")

	f5Ip := probes.CheckDns(s, b, f5Host)
	f5RevHost := probes.CheckRevDns(s, b, f5Ip)
	probes.CheckDnsConsistent(s, b, f5Host, f5RevHost)

	nsHost := probes.CheckRevDns(s, b, nsIp)
	nsRevIp := probes.CheckDns(s, b, nsHost)
	probes.CheckDnsConsistent(s, b, nsIp.String(), nsRevIp.String())

	//do for f5 and ns. For ns, don't rely on the dns so use f5host

	/* Check F5 */

	b.Banner("Existing F5")
	var f5Body []byte

	switch scheme {
	case "http":
		client := probes.GetPlaintextClient(s, b)
		req, cancel := probes.GetHttpRequest(s, b, scheme, f5Host, f5Port, f5Host, viper.GetString("path"))
		defer cancel()
		f5Body = probes.CheckTls(s, b, client, req)
	case "https":
		client := probes.GetTLSClient(s, b, f5Host, viper.GetString("ca"), viper.GetString("cert"), viper.GetString("key"), viper.GetBool("kerberos"), viper.GetBool("http11"))
		req, cancel := probes.GetHttpRequest(s, b, scheme, f5Host, f5Port, f5Host, viper.GetString("path"))
		defer cancel()
		f5Body = probes.CheckTls(s, b, client, req)
	}

	/* Check NetScaler */

	b.Banner("New NetScaler")
	var nsBody []byte

	switch scheme {
	case "http":
		client := probes.GetPlaintextClient(s, b)
		req, cancel := probes.GetHttpRequest(s, b, scheme, nsIp.String(), nsPort, f5Host, viper.GetString("path"))
		defer cancel()
		nsBody = probes.CheckTls(s, b, client, req)
	case "https":
		client := probes.GetTLSClient(s, b, f5Host, viper.GetString("ca"), viper.GetString("cert"), viper.GetString("key"), viper.GetBool("kerberos"), viper.GetBool("http11"))
		req, cancel := probes.GetHttpRequest(s, b, scheme, nsIp.String(), nsPort, f5Host, viper.GetString("path"))
		defer cancel()
		nsBody = probes.CheckTls(s, b, client, req)
	}

	/* Body diff */

	b.Banner("Differences")

	if viper.GetBool("printBody") {
		fmt.Println("NETSCALER response body:")
		fmt.Println(string(nsBody))
	}

	differ := dmp.New()
	diffs := differ.DiffMain(string(f5Body), string(nsBody), true) // TODO try-decode as utf8

	if !(len(diffs) == 1 && diffs[0].Type == dmp.DiffEqual) {
		b.PrintErr("response bodies differ")
		fmt.Println(differ.DiffPrettyText(diffs))
	} else {
		b.PrintInfo("response bodies equal")
	}

	/* Fin */

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}

/*
   fun as ./script.go

   current:
   * hit it with an http/s GET /
   * show redirects
   * show server and other fun headers
   new:
   * hit new ip (arg) with same tcp, http etc
   * use host header from current dns
   * diff replies

   run me in jenkins as a regression test
*/
