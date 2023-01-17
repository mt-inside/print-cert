package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/mt-inside/print-cert/pkg/state"
	"github.com/mt-inside/print-cert/pkg/utils"

	hlu "github.com/mt-inside/http-log/pkg/utils"

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
		Use:   "print-cert target[:port]", // TODO: from binary name constant. Yes, should contain argv[0] (this is parsed out and used as Cobra's idea of what we're called)
		Short: "TODO short",               // Not ever shown for a binary? Only to summarise this Command in one line if it were a sub-command?
		Long:  "Note: all summaries are enabled by default. Disable with --foo=false",
		Example: "print-cert localhost:8080 --trace --timestamps rel -d=false -B\n" + // TODO: from binary name constant
			"https://office.com/setup => print-cert -L office.com --path /setup\n" +
			"http://neverssl.com => print-cert --no-tls neverssl.com",
		Version: "TODO from build",
		Args:    cobra.ExactArgs(1),
		// We don't use the RunE version of this, because we bail early (os.Exit) if we hit any errors. Ideally we'd bubble them all up to here and return them, but if we do that, Cobra prints Usage, which is totally not what you want if there's been like a connection failure. There's a Command::SilenceErrors flag, but it also stops the usage being printed on an arg parse error
		Run: appMain,
	}

	// pflag doesn't support flag groups, but we can at least preserve a grouped order
	cmd.Flags().SortFlags = false

	/* Request */
	cmd.Flags().StringP("sni", "", "", "TLS SNI ServerName")
	cmd.Flags().StringP("host", "", "", "HTTP Host / :authority header")
	cmd.Flags().StringP("path", "", "/", "HTTP path to request")
	cmd.Flags().DurationP("timeout", "", 5*time.Second, "Timeout for each individual network operation")

	/* TLS and auth */
	cmd.Flags().BoolP("no-tls", "p", false, "Make a plaintext 'HTTP' connection rather than a TLS 'HTTPS' connection")
	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key")
	cmd.Flags().String("bearer", "", "Path to file whose contents should be used as Authorization: Bearer token")
	cmd.Flags().BoolP("kerberos", "", false, "Negotiate Kerberos auth")
	cmd.Flags().BoolP("http-11", "", false, "Force http1.1 (no attempt to negotiate http2")

	/* Output */
	// t for Transport or TCP
	cmd.Flags().BoolP("transport", "t", true, "Print important transport (TCP) info")
	cmd.Flags().BoolP("transport-full", "T", false, "Print all transport (TCP) info")
	cmd.Flags().BoolP("dns", "d", true, "Print important DNS info")
	cmd.Flags().BoolP("dns-full", "D", false, "Show detailed DNS testing for the given addr (note: this is just indicative; the system resolver is used to make the actual connection)")
	// s for SSL
	cmd.Flags().BoolP("tls", "s", true, "Print important agreed TLS parameters")
	cmd.Flags().BoolP("tls-full", "S", false, "Print all agreed TLS parameters")
	// m for Metadata
	cmd.Flags().BoolP("http", "m", true, "Print important HTTP response metadata")
	cmd.Flags().BoolP("http-full", "M", false, "Print all HTTP response metadata")
	cmd.Flags().BoolP("body", "b", true, "Print truncated HTTP response body")
	cmd.Flags().BoolP("body-full", "B", false, "Print full HTTP response body")

	// Recall: it's --foo=false for Viper, not --no-foo
	cmd.Flags().BoolP("requests", "V", true, "Print summary of the requests being sent. Nothing that can't be inferred from the arguments provided, but this option spells it out")
	cmd.Flags().StringP("timestamps", "", "none", "Print timestamps: none, abs, rel.")
	cmd.Flags().BoolP("trace", "v", false, "Trace requests/responses as they happen, in addition to printing info at the end")

	/* Command */
	cmd.Flags().BoolP("location", "L", false, "Follow redirects")
	cmd.Flags().IntP("interval", "r", 0, "Repeat the probe every n seconds. Not provided / 0 means don't repeat")

	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		panic(errors.New("can't set up flags"))
	}

	// Execute() prints any errors it hits so there's no need for us to deal with them
	_ = cmd.Execute()
}

func appMain(cmd *cobra.Command, args []string) {

	// TODO Need arch:
	// - needs an actual -L / --follow-redirects CLI option

	// TODO: think about arch parity between this and http-log
	// - "golang aparatus" strapped up to fill out state objects
	//   - via ingest functions eg IngestTlsCS - a bunch of codec should be state-object members?
	//   - (optional) trace as things are happening
	// - something that prints that state (along with request/daemonState)
	//   - NOT a state obj member, but an outputter like http-log
	//   - print-cert probably also wants a logger version too, so it can be automated easily
	// - all of this uses styler / bios (and are allowed to print themselves, esp the strings that styler returns)

	// TODO: styler and bios to a TUI package
	// - styler should only return strings (use stringbuffer)
	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := output.NewTtyBios(s, hlu.Ternary(viper.GetBool("trace"), 10, 0))

	tcpTarget := args[0]
	if !utils.ServerNameConformant(viper.GetString("sni")) {
		b.PrintErr("SNI ServerName cannot be an IP or contain a port number. Ignoring supplied value.")
	}

	if viper.GetBool("no-tls") && (viper.GetBool("tls") || viper.GetBool("tls-full")) {
		b.PrintWarn("tls printing options have no effect when TLS is disabled")
	}

	// Shame pflag can't do this for us.
	timestamps := viper.GetString("timestamps")
	if timestamps != "none" && timestamps != "abs" && timestamps != "rel" {
		b.PrintErr("--timestamps value invalid")
	}

	requestData := state.RequestDataFromViper(s, b, probes.DnsResolverName)
	printOpts := state.PrintOptsFromViper()

	/* Execute */

	period := viper.GetUint("interval")
	for {
		rtData := state.DeriveRoundTripData(s, b, tcpTarget, viper.GetString("host"), viper.GetString("sni"), viper.GetString("path"), !viper.GetBool("no-tls"))
		probes.Probe(s, b, requestData, rtData, printOpts, viper.GetBool("dns-full"), printOpts.Body || printOpts.BodyFull)
		if period == 0 {
			break
		}
		fmt.Println()
		fmt.Println()
		time.Sleep(time.Duration(period) * time.Second)
	}
}
