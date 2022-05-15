package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora/v3"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/* TODO
* - show dane and other stati of name
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

	/* Request */
	cmd.Flags().StringP("sni", "s", "", "SNI ServerName")
	cmd.Flags().StringP("host", "a", "", "HTTP Host / :authority header")
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
	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key")
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

	/* Deal with args */

	addr := args[0]
	port := args[1]
	scheme := args[2]
	if !(scheme == "http" || scheme == "https") {
		b.CheckErr(fmt.Errorf("unknown scheme: %s", scheme))
	}

	host := viper.GetString("host")
	if host == "" {
		host = addr
	}
	sni := viper.GetString("sni")
	if sni == "" {
		sni = host
	}

	/* Load TLS material */

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

	/* Load other request files */

	var bearerToken string
	if viper.Get("bearer") != "" {
		bytes, err := ioutil.ReadFile(viper.Get("bearer").(string))
		b.CheckErr(err)
		bearerToken = strings.TrimSpace(string(bytes))
	}

	/* Build clients */

	var client *http.Client
	switch scheme {
	case "http":
		client = probes.GetPlaintextClient(s, b, viper.GetDuration("timeout"))
	case "https":
		// it's ok to pass nil servingCA and/or clientPair
		client = probes.GetTLSClient(
			s, b,
			viper.GetDuration("timeout"),
			sni,
			servingCA, clientPair,
			viper.GetBool("kerberos"), viper.GetBool("http-11"),
			viper.GetBool("tls"), viper.GetBool("tls-full"),
		)
	}

	req, cancel := probes.GetHTTPRequest(
		s, b,
		viper.GetDuration("timeout"),
		scheme, addr, port, host, viper.GetString("path"),
		bearerToken,
	)
	defer cancel()

	/* Execute  */

	if viper.GetBool("dns") {
		probes.DNSInfo(s, b, viper.GetDuration("timeout"), addr)
	}

	// TODO: passing [tls,head][-full] into these functions is hideous.
	// This needs an outputter like http-log's (shouldn't share/duplicate any code but will use a lot of high-level stuff from the styler like styleHeaderArray())
	// The outputter should be constructed over all the tls-full etc, then it can be unconditiionally called and choose what to print
	// Pro: the functions on the outputter should be focussed on feeding info *into* it, like "ingestTLSConnState()", "ingestHTTPResponse()" (should do some parsing like looking for hsts header and promoting to struct field)
	// - there's then one "printAll()" function which looks at all the tls-full etc flags and prints everything
	// - it can be clever and eg use hsts info from http header in the TLS output section
	// - make sure the controlflow is such that this is always called to do what it can no matter if we bail out on an abort or an error
	// - can do other clever stuff like (in http-log) not printing SNI in tls-agreed if we have the tls-negotiation flag set because that will have done it
	rawBody := probes.CheckTLS(
		s, b,
		client, req,
		viper.GetBool("head"), viper.GetBool("head-full"),
	)

	if viper.GetBool("body") || viper.GetBool("body-full") {
		fmt.Println()

		bodyLen := len(rawBody)
		printLen := output.Min(bodyLen, 72)
		if viper.GetBool("body-full") {
			printLen = bodyLen
		}

		fmt.Printf("%v", string(rawBody[0:printLen])) // assumes utf8
		if bodyLen > printLen {
			fmt.Printf("<%d bytes elided>", bodyLen-printLen)
		}
		if bodyLen > 0 {
			fmt.Println()
		}
	}

	fmt.Println()

	os.Exit(0)
}
