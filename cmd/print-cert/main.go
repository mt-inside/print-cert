package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/mt-inside/print-cert/pkg/state"

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
		Use:  "addr port",
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
	cmd.Flags().BoolP("dns", "d", false, "Print important DNS info")
	cmd.Flags().BoolP("dns-full", "D", false, "Show detailed DNS testing for the given addr (note: this is just indicative; the system resolver is used to make the actual connection)")
	cmd.Flags().BoolP("tls", "t", false, "Print important agreed TLS parameters")
	cmd.Flags().BoolP("tls-full", "T", false, "Print all agreed TLS parameters")
	cmd.Flags().BoolP("head", "m", false, "Print important HTTP response metadata")
	cmd.Flags().BoolP("head-full", "M", false, "Print all HTTP response metadata")
	cmd.Flags().BoolP("body", "b", false, "Print truncated HTTP response body")
	cmd.Flags().BoolP("body-full", "B", false, "Print full HTTP response body")

	/* TLS and auth */
	cmd.Flags().BoolP("no-tls", "P", false, "Make a plaintext 'HTTP' connection rather than a TLS 'HTTPS' connection")
	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key")
	cmd.Flags().String("bearer", "", "Path to file whose contents should be used as Authorization: Bearer token")
	cmd.Flags().BoolP("kerberos", "n", false, "Negotiate Kerberos auth")

	/* Command */
	cmd.Flags().IntP("interval", "r", 0, "Repeat the probe every n seconds. Not provided / 0 means don't repeat")

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
	// - factor to Plaintext and TLS prober (same object as responseData). Construct over requestData? internal methods to get transport, client, etc. Interface for Probe(), Print()

	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := output.NewTtyBios(s)

	target := args[0]
	port, err := strconv.ParseUint(args[1], 10, 16)
	b.CheckErr(err)
	requestData := state.RequestDataFromViper(s, b, target, port, probes.DnsResolverName)
	// TODO test all print flags with --no-tls

	/* Execute */

	period := viper.GetUint("interval")
	for {
		responseData := state.NewResponseData() // TODO: is / should be made in Probe()
		// FIXME: requestData is written by redirect. Have a deepcopy method and give it a copy
		probes.Probe(s, b, requestData, responseData, target, port, viper.GetString("path"), viper.GetBool("dns-full"), viper.GetBool("body") || viper.GetBool("body-full"))
		if period == 0 {
			break
		}
		fmt.Println()
		fmt.Println()
		time.Sleep(time.Duration(period) * time.Second)
	}

	os.Exit(0)
}
