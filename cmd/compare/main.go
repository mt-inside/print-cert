package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/logrusorgru/aurora/v3"
	dmp "github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

func main() {

	cmd := &cobra.Command{
		Use:  "reference-dns-name reference-port new-ip new-port",
		Args: cobra.ExactArgs(4),
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

	requestData := state.NewRequestData()

	/* Reference server */
	refTarget := args[0]
	refPort, err := strconv.ParseUint(args[1], 10, 16)
	b.CheckErr(err)
	/* Comparison */
	newTarget := args[2]
	newPort, err := strconv.ParseUint(args[3], 10, 16)
	b.CheckErr(err)

	requestData.Timeout = viper.GetDuration("timeout")
	requestData.DnsSystemResolver = probes.DnsResolverName

	// TODO: think about this. Compar doen't take --host or --sni, but maybe it should (would only need one value, not for both sides)
	// - but for now we just use the ref's name. This means ref must NOT be an IP (or if it is, don't use as SNI)
	// - new can actually be IP or name (will be called as ref name)
	// Update: yes, this should take --sni and --host. ref and new can be names/IPs, pass them to exactly the same functions as << (and build one dD between them - dD is written in nasty places, check that out cause it won't work)
	requestData.HttpHost = viper.GetString("host")
	if requestData.HttpHost == "" {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
		if refPort == 80 || refPort == 443 {
			requestData.HttpHost = refTarget // my reading of the spec is that it's not an error to include 80 or 443 but I can imagine some servers getting confused
		} else {
			requestData.HttpHost = net.JoinHostPort(refTarget, strconv.FormatUint(refPort, 10))
		}
	}

	// RFC 6066 §3 (https://www.rfc-editor.org/rfc/rfc6066)
	// - DNS names only
	// - No ports
	// - No literal IPs
	requestData.TlsServerName = viper.GetString("sni")
	if requestData.TlsServerName == "" {
		// If SNI isn't explicitly set, try to do something useful by falling back to the specified HTTP Host
		// Can only use explicit Hosts, not one we've derived (which could contain a port and/or could be an IP), or target (which could be an IP)
		requestData.TlsServerName = viper.GetString("host")
	}

	// Name to validate received certs against - fall back some non-empty string, even if it is an IP
	requestData.TlsValidateName = requestData.TlsServerName
	if requestData.TlsValidateName == "" {
		requestData.TlsValidateName = refTarget
	}

	requestData.TlsEnabled = !viper.GetBool("no-tls")
	requestData.HttpMethod = "GET"

	requestData.AuthKrb = viper.GetBool("kerberos")
	requestData.HttpForce11 = viper.GetBool("http-11")

	if viper.Get("cert") != "" || viper.Get("key") != "" {
		pair, err := tls.LoadX509KeyPair(viper.Get("cert").(string), viper.Get("key").(string))
		b.CheckErr(err)
		requestData.TlsClientPair = &pair
	}

	if viper.Get("ca") != "" {
		bytes, err := os.ReadFile(viper.Get("ca").(string))
		b.CheckErr(err)
		requestData.TlsServingCA, err = codec.ParseCertificate(bytes)
		b.CheckErr(err)
	}

	if viper.Get("bearer") != "" {
		bytes, err := os.ReadFile(viper.Get("bearer").(string))
		b.CheckErr(err)
		requestData.AuthBearerToken = strings.TrimSpace(string(bytes))
	}

	/* Begin */

	fmt.Printf("Testing new host %v against reference host %v\n", s.Addr(newTarget), s.Addr(refTarget))

	/* Check reference */

	b.Banner("Reference host")

	refResponseData := state.NewResponseData()
	probes.Probe(s, b, requestData, refResponseData, refTarget, refPort, viper.GetString("path"), viper.GetBool("dns") || viper.GetBool("dns-full"), true)

	refResponseData.Print(
		s, b,
		requestData,
		// TODO: if none of these are set, default to dns,tls,head,body. Can't set their default flag values cause then they can't be turned off. See how http-log does it
		viper.GetBool("dns"), viper.GetBool("dns-full"),
		viper.GetBool("tls"), viper.GetBool("tls-full"),
		viper.GetBool("head"), viper.GetBool("head-full"),
		viper.GetBool("body"), viper.GetBool("body-full"),
		// TODO: make printing of request info optional (can be inferred from the args but can be useful to have it spelled out)
		// TODO: make it possible to turn b.Trace output on/off
	)

	/* Check new */

	b.Banner("New IP")

	newResponseData := state.NewResponseData()
	probes.Probe(s, b, requestData, newResponseData, newTarget, newPort, viper.GetString("path"), viper.GetBool("dns") || viper.GetBool("dns-full"), true)

	newResponseData.Print(
		s, b,
		requestData,
		// TODO: if none of these are set, default to dns,tls,head,body. Can't set their default flag values cause then they can't be turned off. See how http-log does it
		viper.GetBool("dns"), viper.GetBool("dns-full"),
		viper.GetBool("tls"), viper.GetBool("tls-full"),
		viper.GetBool("head"), viper.GetBool("head-full"),
		viper.GetBool("body"), viper.GetBool("body-full"),
		// TODO: make printing of request info optional (can be inferred from the args but can be useful to have it spelled out)
		// TODO: make it possible to turn b.Trace output on/off
	)

	/* Body diff */

	b.Banner("Body Differences")

	refBody := refResponseData.BodyBytes
	newBody := newResponseData.BodyBytes

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
