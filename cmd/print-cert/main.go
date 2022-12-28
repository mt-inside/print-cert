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

	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
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
	cmd.Flags().StringP("sni", "s", "", "TLS SNI ServerName")
	cmd.Flags().StringP("host", "a", "", "HTTP Host / :authority header")
	cmd.Flags().StringP("path", "p", "/", "HTTP path to request")
	cmd.Flags().Duration("timeout", 5*time.Second, "Timeout for each individual network operation")
	cmd.Flags().BoolP("http-11", "", false, "Force http1.1 (no attempt to negotiate http2")

	/* Output */
	cmd.Flags().BoolP("dns", "d", false, "Print important DNS info")
	cmd.Flags().BoolP("dns-full", "D", false, "Show detailed DNS testing for the given addr (note: this is just indicative; the system resolver is used to make the actual connection)")
	cmd.Flags().BoolP("tls", "t", false, "Print important agreed TLS parameters")
	cmd.Flags().BoolP("tls-full", "T", false, "Print all agreed TLS parameters")
	cmd.Flags().BoolP("head", "m", false, "Print important HTTP response metadata")
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

	// Need arch:
	// - commander object that run a probe. Needs to be able to re-enter itself for redirects. Also needs to be drivable eg from a cli that runs it every 5s
	// - needs an actual -L / --follow-redirects CLI option
	// - "arg" stuff like TLS certs shouldn't be re-loaded, and tty stylers shouldn't be re-made, but state-holding objects should be new
	// - but target IP and port need to be changable (so they can be given from whatever DNS system in chosen ,and also varied by the compare front-end)
	// - factor to Plaintext and TLS prober (same object as probeData). Construct over daemonData? internal methods to get transport, client, etc. Interface for Probe(), Print()

	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := output.NewTtyBios(s)

	// TODO: all arg parsing to a fn mapping args[] (& viper) to daemonData

	daemonData := state.NewDaemonData()

	/* Deal with args */
	// TODO: factor this out to internal/ and share with compar

	target := args[0]
	port, err := strconv.ParseUint(args[1], 10, 16)
	b.CheckErr(err)
	// TODO: turn this into a --no-tls arg
	// - then test all print flags with --no-tls
	scheme := args[2]
	if !(scheme == "http" || scheme == "https") {
		b.CheckErr(fmt.Errorf("unknown scheme: %s", scheme))
	}

	daemonData.Timeout = viper.GetDuration("timeout")
	daemonData.DnsSystemResolver = probes.DnsResolverName

	daemonData.HttpHost = viper.GetString("host")
	if daemonData.HttpHost == "" {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
		if port == 80 || port == 443 {
			daemonData.HttpHost = target // my reading of the spec is that it's not an error to include 80 or 443 but I can imagine some servers getting confused
		} else {
			daemonData.HttpHost = net.JoinHostPort(target, strconv.FormatUint(port, 10))
		}
	}

	// RFC 6066 §3 (https://www.rfc-editor.org/rfc/rfc6066)
	// - DNS names only
	// - No ports
	// - No literal IPs
	daemonData.TlsServerName = viper.GetString("sni")
	if daemonData.TlsServerName == "" {
		// If SNI isn't explicitly set, try to do something useful by falling back to the specified HTTP Host
		// Can only use explicit Hosts, not one we've derived (which could contain a port and/or could be an IP), or target (which could be an IP)
		daemonData.TlsServerName = viper.GetString("host")
	}

	// Name to validate received certs against - fall back some non-empty string, even if it is an IP
	daemonData.TlsValidateName = daemonData.TlsServerName
	if daemonData.TlsValidateName == "" {
		daemonData.TlsValidateName = target
	}

	daemonData.HttpMethod = "GET"

	daemonData.AuthKrb = viper.GetBool("kerberos")
	daemonData.HttpForce11 = viper.GetBool("http-11")

	/* Load TLS material */

	if viper.Get("cert") != "" || viper.Get("key") != "" {
		pair, err := tls.LoadX509KeyPair(viper.Get("cert").(string), viper.Get("key").(string))
		b.CheckErr(err)
		daemonData.TlsClientPair = &pair
	}

	if viper.Get("ca") != "" {
		bytes, err := os.ReadFile(viper.Get("ca").(string))
		b.CheckErr(err)
		daemonData.TlsServingCA, err = codec.ParseCertificate(bytes)
		b.CheckErr(err)
	}

	/* Load other request files */

	if viper.Get("bearer") != "" {
		bytes, err := os.ReadFile(viper.Get("bearer").(string))
		b.CheckErr(err)
		daemonData.AuthBearerToken = strings.TrimSpace(string(bytes))
	}

	/* Execute */

	probeData := state.NewProbeData()
	probes.Probe(s, b, daemonData, probeData, scheme, target, port, viper.GetString("path"), viper.GetBool("body") || viper.GetBool("body-full"))

	/* Print */

	// TODO: passing [tls,head][-full] into these functions is hideous.
	// This needs an outputter like http-log's (shouldn't share/duplicate any code but will use a lot of high-level stuff from the styler like styleHeaderArray())
	// The outputter should be constructed over all the tls-full etc, then it can be unconditiionally called and choose what to print
	// Pro: the functions on the outputter should be focussed on feeding info *into* it, like "ingestTLSConnState()", "ingestHTTPResponse()" (should do some parsing like looking for hsts header and promoting to struct field)
	// - there's then one "printAll()" function which looks at all the tls-full etc flags and prints everything
	// - it can be clever and eg use hsts info from http header in the TLS output section
	// - make sure the controlflow is such that this is always called to do what it can no matter if we bail out on an abort or an error
	// - can do other clever stuff like (in http-log) not printing SNI in tls-agreed if we have the tls-negotiation flag set because that will have done it

	probeData.Print(
		s, b,
		daemonData,
		// TODO: if none of these are set, default to dns,tls,head,body. Can't set their default flag values cause then they can't be turned off. See how http-log does it
		viper.GetBool("dns"), viper.GetBool("dns-full"),
		viper.GetBool("tls"), viper.GetBool("tls-full"),
		viper.GetBool("head"), viper.GetBool("head-full"),
		viper.GetBool("body"), viper.GetBool("body-full"),
		// TODO: make printing of request info optional (can be inferred from the args but can be useful to have it spelled out)
		// TODO: make it possible to turn b.Trace output on/off
	)

	os.Exit(0)
}
