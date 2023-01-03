package main

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unicode/utf8"

	"github.com/logrusorgru/aurora/v3"
	dmp "github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
)

func main() {

	cmd := &cobra.Command{
		Use:  "reference-target[:port] comparison-target[:port]",
		Args: cobra.ExactArgs(2),
		Run:  appMain,
	}

	/* Request */
	cmd.Flags().StringP("sni", "s", "", "TLS SNI ServerName")
	cmd.Flags().StringP("host", "a", "", "HTTP Host / :authority header")
	cmd.Flags().StringP("path", "p", "/", "HTTP path to request")
	cmd.Flags().Duration("timeout", 5*time.Second, "Timeout for each individual network operation")
	cmd.Flags().BoolP("http-11", "", false, "Force http1.1 (no attempt to negotiate http2")

	/* Output */
	cmd.Flags().BoolP("dns", "d", false, "Show detailed DNS testing for the given addr (note: this is just indicative; the system resolver is used to make the actual connection)")
	cmd.Flags().BoolP("dns-full", "D", false, "Show detailed DNS testing for the given addr (note: this is just indicative; the system resolver is used to make the actual connection)")
	cmd.Flags().BoolP("tls", "t", false, "Print important agreed TLS parameters")
	cmd.Flags().BoolP("tls-full", "T", false, "Print all agreed TLS parameters")
	cmd.Flags().BoolP("head", "m", false, "Print important HTTP response metadata")
	cmd.Flags().BoolP("head-full", "M", false, "Print all HTTP response metadata")

	/* TLS and auth */
	cmd.Flags().BoolP("no-tls", "P", false, "Make a plaintext 'HTTP' connection rather than a TLS 'HTTPS' connection")
	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate file")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate file")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key file")
	cmd.Flags().String("bearer", "", "Path to file whose contents should be used as Authorization: Bearer token")
	cmd.Flags().BoolP("kerberos", "n", false, "Negotiate Kerberos auth")

	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		panic(errors.New("can't set up flags"))
	}

	err = cmd.Execute()
	if err != nil {
		fmt.Println("error during execution:", err)
	}
}

func appMain(cmd *cobra.Command, args []string) {

	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := output.NewTtyBios(s)

	/* Reference server */
	refTarget := args[0]
	/* Comparison */
	newTarget := args[1]

	requestData := state.RequestDataFromViper(s, b, probes.DnsResolverName)

	/* Begin */

	fmt.Printf("Testing new host %v against reference host %v\n", s.Addr(newTarget), s.Addr(refTarget))

	/* Check reference */

	b.Banner("Reference host")

	refRtData := state.DeriveRoundTripData(s, b, refTarget, viper.GetString("host"), viper.GetString("sni"), viper.GetString("path"), !viper.GetBool("no-tls"))
	refBody := probes.Probe(s, b, requestData, refRtData, viper.GetBool("dns-full"), true)

	/* Check new */

	b.Banner("New IP")

	newRtData := state.DeriveRoundTripData(s, b, newTarget, viper.GetString("host"), viper.GetString("sni"), viper.GetString("path"), !viper.GetBool("no-tls"))
	newBody := probes.Probe(s, b, requestData, newRtData, viper.GetBool("dns-full"), true)

	/* Body diff */

	b.Banner("Body Differences")

	if !utf8.Valid(refBody) || !utf8.Valid(newBody) {
		b.PrintWarn("one or more response bodies aren't valid utf-8; diff engine might do unexpected things")
	}
	differ := dmp.New()
	diffs := differ.DiffMain(string(refBody), string(newBody), true)

	if len(diffs) == 1 && diffs[0].Type == dmp.DiffEqual {
		b.PrintInfo("response bodies equal")
	} else {
		b.PrintWarn("response bodies differ")
		fmt.Println(differ.DiffPrettyText(diffs))
	}

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
