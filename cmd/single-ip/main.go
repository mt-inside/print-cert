package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/mt-inside/go-usvc"
	dmp "github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"bitbucket.mwam.local/infra/lb-checker/pkg/utils"
	. "bitbucket.mwam.local/infra/lb-checker/pkg/utils"
)

func main() {

	cmd := &cobra.Command{
		Use:  "f5Name nsIP port scheme",
		Args: cobra.ExactArgs(4),
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
	nsIp := net.ParseIP(args[1])
	port := os.Args[3]
	scheme := os.Args[4]

	if nsIp == nil {
		CheckErr(fmt.Errorf("Invalid IP: %s", os.Args[0]))
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

	f5L4Addr := net.JoinHostPort(f5Host, port)
	switch scheme {
	case "http":
		checkTcp(f5L4Addr)
	case "https":
		utils.CheckTls(log, f5L4Addr, f5Host, viper.GetString("cert"), viper.GetString("key"))
	}

	f5L7Addr := &url.URL{
		Scheme: scheme,
		Host:   f5L4Addr,
		Path:   "/",
	}
	utils.CheckHttp(log, f5L7Addr, f5Host, viper.GetString("cert"), viper.GetString("key"))

	/* Check NetScaler */

	Banner("New NetScaler")

	nsL4Addr := net.JoinHostPort(nsIp.String(), port)
	switch scheme {
	case "http":
		checkTcp(nsL4Addr)
	case "https":
		utils.CheckTls(log, nsL4Addr, f5Host, viper.GetString("cert"), viper.GetString("key"))
	}

	nsL7Addr := &url.URL{
		Scheme: scheme,
		Host:   nsL4Addr,
		Path:   "/",
	}
	utils.CheckHttp(log, nsL7Addr, f5Host, viper.GetString("cert"), viper.GetString("key"))

	/* Body diff */

	Banner("Differences")

	f5Body := utils.GetBody(log, f5L7Addr, f5Host, viper.GetString("cert"), viper.GetString("key"))
	nsBody := utils.GetBody(log, nsL7Addr, f5Host, viper.GetString("cert"), viper.GetString("key"))

	if viper.GetBool("printBody") {
		fmt.Println("NETSCALER response body:")
		fmt.Println(nsBody)
	}

	differ := dmp.New()
	diffs := differ.DiffMain(f5Body, nsBody, true)

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

func checkTcp(l4Addr string) {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Printf("%s TCP connection with %s...\n", STrying, AddrStyle.Render(l4Addr))
	conn, err := d.DialContext(ctx, "tcp", l4Addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Printf("%s established TCP connection with %s\n", OkStyle.Render("Ok:"), AddrStyle.Render(l4Addr))
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
