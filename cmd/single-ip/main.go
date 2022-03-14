package main

import (
	"fmt"
	"net"
	"os"

	"github.com/mt-inside/go-usvc"
	dmp "github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mt-inside/print-cert/pkg/utils"
	. "github.com/mt-inside/print-cert/pkg/utils"
)

func main() {

	cmd := &cobra.Command{
		Use:  "f5Name f5Port nsIP f5Port scheme",
		Args: cobra.ExactArgs(5),
		Run:  appMain,
	}

	cmd.Flags().StringP("cert", "c", "", "Path to TLS certificate file")
	cmd.Flags().StringP("key", "k", "", "Path to TLS key file")
	cmd.Flags().BoolP("print-body", "b", false, "Print the returned HTTP body")
	viper.BindPFlag("cert", cmd.Flags().Lookup("cert"))
	viper.BindPFlag("key", cmd.Flags().Lookup("key"))
	viper.BindPFlag("printBody", cmd.Flags().Lookup("print-body"))

	CheckErr(cmd.Execute())
}

func appMain(cmd *cobra.Command, args []string) {

	log := usvc.GetLogger(false, 0)

	f5Host := args[0]
	f5Port := args[1]
	nsIp := net.ParseIP(args[2])
	nsPort := args[3]
	scheme := args[4]

	if nsIp == nil {
		CheckErr(fmt.Errorf("Invalid IP: %s", args[2]))
	}
	if !(scheme == "http" || scheme == "https") {
		CheckErr(fmt.Errorf("Unknown scheme: %s", scheme))
	}

	fmt.Printf("Testing NetScaler VIP %v against F5 service %v\n", AddrStyle.Render(nsIp.String()), AddrStyle.Render(f5Host))

	/* Check DNS */

	Banner("DNS")

	f5Ip := CheckDns(f5Host)
	f5RevHost := CheckRevDns(f5Ip)
	checkDnsConsistent(f5Host, f5RevHost)

	nsHost := CheckRevDns(nsIp)
	nsRevIp := CheckDns(nsHost)
	checkDnsConsistent(nsIp.String(), nsRevIp.String())

	//do for f5 and ns. For ns, don't rely on the dns so use f5host

	/* Check F5 */

	Banner("Existing F5")
	var f5Body []byte

	switch scheme {
	case "http":
		client := utils.GetPlaintextClient(log)
		req, cancel := utils.GetHttpRequest(log, scheme, f5Host, f5Port, f5Host, viper.GetString("path"))
		defer cancel()
		f5Body = utils.CheckTls(log, client, req)
	case "https":
		client := utils.GetTLSClient(log, f5Host, viper.GetString("cert"), viper.GetString("key"), viper.GetBool("kerberos"), viper.GetBool("http11"))
		req, cancel := utils.GetHttpRequest(log, scheme, f5Host, f5Port, f5Host, viper.GetString("path"))
		defer cancel()
		f5Body = utils.CheckTls(log, client, req)
	}

	/* Check NetScaler */

	Banner("New NetScaler")
	var nsBody []byte

	switch scheme {
	case "http":
		client := utils.GetPlaintextClient(log)
		req, cancel := utils.GetHttpRequest(log, scheme, nsIp.String(), nsPort, f5Host, viper.GetString("path"))
		defer cancel()
		nsBody = utils.CheckTls(log, client, req)
	case "https":
		client := utils.GetTLSClient(log, f5Host, viper.GetString("cert"), viper.GetString("key"), viper.GetBool("kerberos"), viper.GetBool("http11"))
		req, cancel := utils.GetHttpRequest(log, scheme, nsIp.String(), nsPort, f5Host, viper.GetString("path"))
		defer cancel()
		nsBody = utils.CheckTls(log, client, req)
	}

	/* Body diff */

	Banner("Differences")

	if viper.GetBool("printBody") {
		fmt.Println("NETSCALER response body:")
		fmt.Println(string(nsBody))
	}

	differ := dmp.New()
	diffs := differ.DiffMain(string(f5Body), string(nsBody), true) // TODO try-decode as utf8

	if !(len(diffs) == 1 && diffs[0].Type == dmp.DiffEqual) {
		fmt.Printf("%s response bodies differ\n", SError)
		fmt.Println(differ.DiffPrettyText(diffs))
	} else {
		fmt.Printf("%s response bodies equal\n", SOk)
	}

	/* Fin */

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}

func checkDnsConsistent(orig string, rev string) {
	if rev != orig {
		fmt.Printf("\t%s dns inconsistency: %s != %s\n", SWarning, AddrStyle.Render(orig), AddrStyle.Render(rev))
	}
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
