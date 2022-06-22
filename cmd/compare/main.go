package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/logrusorgru/aurora/v3"
	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/print-cert/pkg/probes"
	dmp "github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {

	cmd := &cobra.Command{
		Use:  "reference-dns-name reference-port new-ip new-port scheme",
		Args: cobra.ExactArgs(5),
		Run:  appMain,
	}

	/* Request */
	cmd.Flags().StringP("path", "p", "/", "HTTP path to request")
	cmd.Flags().Duration("timeout", 5*time.Second, "Timeout for each individual network operation")
	cmd.Flags().BoolP("http-11", "", false, "Force http1.1 (no attempt to negotiate http2")

	/* Output */
	cmd.Flags().BoolP("dns", "d", false, "Show detailed DNS testing for the given addr (note: this is just indicative; the system resolver is used to make the actual connection)")
	cmd.Flags().BoolP("tls", "t", true, "Print important agreed TLS parameters")
	cmd.Flags().BoolP("tls-full", "T", false, "Print all agreed TLS parameters")
	cmd.Flags().BoolP("head", "m", true, "Print important HTTP response metadata")
	cmd.Flags().BoolP("head-full", "M", false, "Print all HTTP response metadata")
	cmd.Flags().BoolP("body", "b", false, "Print truncated HTTP response body")
	cmd.Flags().BoolP("body-full", "B", false, "Print full HTTP response body")

	/* TLS and auth */
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

	refName := args[0]
	refPort := args[1]
	newIp := net.ParseIP(args[2])
	newPort := args[3]
	scheme := args[4]

	if newIp == nil {
		b.CheckErr(fmt.Errorf("invalid IP: %s", args[2]))
	}
	if !(scheme == "http" || scheme == "https") {
		b.CheckErr(fmt.Errorf("unknown scheme: %s", scheme))
	}

	var clientPair *tls.Certificate
	if viper.Get("cert") != "" || viper.Get("key") != "" {
		pair, err := tls.LoadX509KeyPair(viper.Get("cert").(string), viper.Get("key").(string))
		b.CheckErr(err)
		clientPair = &pair
	}

	var servingCA *x509.Certificate
	if viper.Get("ca") != "" {
		bytes, err := ioutil.ReadFile(viper.Get("ca").(string))
		b.CheckErr(err)
		servingCA, err = codec.ParseCertificate(bytes)
		b.CheckErr(err)
	}

	var bearerToken string
	if viper.Get("bearer") != "" {
		bytes, err := ioutil.ReadFile(viper.Get("bearer").(string))
		b.CheckErr(err)
		bearerToken = strings.TrimSpace(string(bytes))
	}

	/* Begin */

	fmt.Printf("Testing new IP %v against reference host %v\n", s.Addr(newIp.String()), s.Addr(refName))

	/* Check reference */

	b.Banner("Reference host")
	refBody := doChecks(s, b, scheme, refName, refPort, refName, refName, servingCA, clientPair, bearerToken)

	/* Check new */

	b.Banner("New IP")
	newBody := doChecks(s, b, scheme, newIp.String(), newPort, refName, refName, servingCA, clientPair, bearerToken)

	/* Body diff */

	b.Banner("Differences")

	if viper.GetBool("body") || viper.GetBool("body-full") {
		fmt.Println()
		fmt.Println("NEW response body:")

		bodyLen := len(newBody)
		printLen := usvc.MinInt(bodyLen, 72)
		if viper.GetBool("body-full") {
			printLen = bodyLen
		}

		fmt.Printf("%v", string(newBody[0:printLen])) // assumes utf8
		if bodyLen > printLen {
			fmt.Printf("<%d bytes elided>", bodyLen-printLen)
		}
		if bodyLen > 0 {
			fmt.Println()
		}
	}

	if !utf8.Valid(refBody) || !utf8.Valid(newBody) {
		b.PrintWarn("one or more response bodies aren't valid utf-8; diff engine might do unexpected things")
	}
	differ := dmp.New()
	diffs := differ.DiffMain(string(refBody), string(newBody), true)

	if !(len(diffs) == 1 && diffs[0].Type == dmp.DiffEqual) {
		b.PrintWarn("response bodies differ")
		fmt.Println(differ.DiffPrettyText(diffs))
	} else {
		b.PrintInfo("response bodies equal")
	}

	/* Fin */

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}

func doChecks(s output.TtyStyler, b output.Bios, scheme, target, port, sni, host string, servingCA *x509.Certificate, clientPair *tls.Certificate, bearerToken string) (body []byte) {
	if viper.GetBool("dns") {
		probes.DNSInfo(s, b, viper.GetDuration("timeout"), target)
	}

	switch scheme {
	case "http":
		client := probes.GetPlaintextClient(s, b, viper.GetDuration("timeout"))
		req, cancel := probes.GetHTTPRequest(
			s, b,
			viper.GetDuration("timeout"),
			scheme, target, port, host, viper.GetString("path"),
			bearerToken,
		)
		defer cancel()
		// TODO: better name: doesn't always do TLS
		body = probes.CheckTLS(
			s, b,
			client, req,
			viper.GetBool("head"), viper.GetBool("head-full"),
		)
	case "https":
		client := probes.GetTLSClient(
			s, b,
			viper.GetDuration("timeout"),
			sni,
			servingCA, clientPair,
			viper.GetBool("kerberos"), viper.GetBool("http11"),
			viper.GetBool("tls"), viper.GetBool("tls-full"),
		)
		req, cancel := probes.GetHTTPRequest(
			s, b,
			viper.GetDuration("timeout"),
			scheme, target, port, host, viper.GetString("path"),
			bearerToken,
		)
		defer cancel()
		body = probes.CheckTLS(
			s, b,
			client, req,
			viper.GetBool("head"), viper.GetBool("head-full"),
		)
	}

	return
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
