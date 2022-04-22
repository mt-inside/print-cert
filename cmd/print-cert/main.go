package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
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
	cmd.Flags().DurationP("timeout", "t", 5*time.Second, "Timeout for each individual network operation")
	cmd.Flags().BoolP("http-11", "", false, "Force http1.1 (no attempt to negotiate http2")

	/* Output */
	cmd.Flags().BoolP("show-dns", "d", false, "Show detailed DNS testing for the given addr (note: this is just indicative; the system resolver is used to make the actual connection)")
	cmd.Flags().BoolP("print-body", "b", false, "Print the returned HTTP body")

	/* TLS and auth */
	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key")
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

	addr := args[0]
	port := args[1]
	scheme := args[2]
	if !(scheme == "http" || scheme == "https") {
		b.CheckErr(fmt.Errorf("unknown scheme: %s", scheme))
	}

	if viper.GetBool("show-dns") {
		probes.DNSInfo(s, b, viper.GetDuration("timeout"), addr)
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
		)
	}

	req, cancel := probes.GetHTTPRequest(
		s, b,
		viper.GetDuration("timeout"),
		scheme, addr, port, host, viper.GetString("path"),
	)
	defer cancel()

	rawBody := probes.CheckTLS(
		s, b,
		client,
		req,
	)

	if viper.GetBool("print-body") {
		fmt.Println(string(rawBody))
	}

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}
