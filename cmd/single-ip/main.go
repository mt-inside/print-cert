package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"github.com/logrusorgru/aurora/v3"
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

	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate file")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate file")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key file")
	cmd.Flags().BoolP("print-body", "b", false, "Print the returned HTTP body")
	cmd.Flags().DurationP("timeout", "t", 5*time.Second, "Timeout for each individual network operation")
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

	/* Begin */

	fmt.Printf("Testing new IP %v against reference host %v\n", s.Addr(newIp.String()), s.Addr(refName))

	/* Check DNS */

	b.Banner("DNS")

	probes.DNSInfo(s, b, viper.GetDuration("timeout"), refName)

	probes.DNSInfo(s, b, viper.GetDuration("timeout"), newIp.String())

	//do for base and new. For new, don't rely on the dns so use refName

	/* Check reference */

	b.Banner("Reference host")
	var refBody []byte

	switch scheme {
	case "http":
		client := probes.GetPlaintextClient(s, b, viper.GetDuration("timeout"))
		req, cancel := probes.GetHTTPRequest(
			s, b,
			viper.GetDuration("timeout"),
			scheme, refName, refPort, refName, viper.GetString("path"),
		)
		defer cancel()
		refBody = probes.CheckTLS(s, b, client, req)
	case "https":
		client := probes.GetTLSClient(
			s, b,
			viper.GetDuration("timeout"),
			refName,
			servingCA, clientPair,
			viper.GetBool("kerberos"), viper.GetBool("http11"),
		)
		req, cancel := probes.GetHTTPRequest(
			s, b,
			viper.GetDuration("timeout"),
			scheme, refName, refPort, refName, viper.GetString("path"),
		)
		defer cancel()
		refBody = probes.CheckTLS(s, b, client, req)
	}

	/* Check new */

	b.Banner("New IP")
	var newBody []byte

	switch scheme {
	case "http":
		client := probes.GetPlaintextClient(s, b, viper.GetDuration("timeout"))
		req, cancel := probes.GetHTTPRequest(
			s, b,
			viper.GetDuration("timeout"),
			scheme, newIp.String(), newPort, refName, viper.GetString("path"),
		)
		defer cancel()
		newBody = probes.CheckTLS(s, b, client, req)
	case "https":
		client := probes.GetTLSClient(
			s, b,
			viper.GetDuration("timeout"),
			refName,
			servingCA, clientPair,
			viper.GetBool("kerberos"), viper.GetBool("http11"),
		)
		req, cancel := probes.GetHTTPRequest(
			s, b,
			viper.GetDuration("timeout"),
			scheme, newIp.String(), newPort, refName, viper.GetString("path"),
		)
		defer cancel()
		newBody = probes.CheckTLS(s, b, client, req)
	}

	/* Body diff */

	b.Banner("Differences")

	if viper.GetBool("print-body") {
		fmt.Println("NEW response body:")
		fmt.Println(string(newBody))
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
