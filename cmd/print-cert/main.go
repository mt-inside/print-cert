package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/scope"

	"github.com/mt-inside/print-cert/internal/build"
	"github.com/mt-inside/print-cert/pkg/probes"
	"github.com/mt-inside/print-cert/pkg/state"
	"github.com/mt-inside/print-cert/pkg/utils"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/zaplog"

	"github.com/mt-inside/http-log/pkg/output"
)

/* TODO
* - show dane and other stati of name
*
* - use multierror lib to gather all errors (at the end of main, if >0 don't actually execute).
*   - have a bios function to print all of them as err/warn/etc
 */

func init() {
	spew.Config.DisableMethods = true
	spew.Config.DisablePointerMethods = true
}

func main() {

	cmd := &cobra.Command{
		Use:   build.Name + " target[:port]", // Yes, should contain argv[0] (this is parsed out and used as Cobra's idea of what we're called)
		Short: "TODO short",                  // Not ever shown for a binary? Only to summarise this Command in one line if it were a sub-command?
		Long:  "Note: all summaries are enabled by default. Disable with --foo=false",
		Example: build.Name + " localhost:8080 -v debug --timestamps rel -d=false -B\n" +
			"https://office.com/setup => " + build.Name + " -L office.com --path /setup\n" +
			"http://neverssl.com => " + build.Name + " --no-tls neverssl.com",
		Version: build.Version,
		Args:    cobra.ExactArgs(1),
		// We don't use the RunE version of this, because we bail early (os.Exit) if we hit any errors. Ideally we'd bubble them all up to here and return them, but if we do that, Cobra prints Usage, which is totally not what you want if there's been like a connection failure. There's a Command::SilenceErrors flag, but it also stops the usage being printed on an arg parse error
		// TODO: I think the proper way to use this is to have a RunE, which returns an errors for extended args validation only. Then call into the main logic (in /pkg) and don't bubble those errors
		Run: appMain,
	}

	// Print our version if the user gets the flags wrong
	// - parse errors call Usage()
	// - -h calls Help(), which calls Usage()
	defaultUsage := cmd.UsageFunc()
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		fmt.Println(build.NameAndVersion())
		fmt.Println()
		return defaultUsage(c)
	})

	// pflag doesn't support flag groups, but we can at least preserve a grouped order
	cmd.Flags().SortFlags = false

	/* Request */
	cmd.Flags().StringP("sni", "", "", "TLS SNI ServerName")
	cmd.Flags().StringP("host", "", "", "HTTP Host / :authority header")
	cmd.Flags().StringP("method", "", "GET", "HTTP method")
	cmd.Flags().StringP("path", "", "/", "HTTP path to request")
	cmd.Flags().StringP("req-body", "", "", "HTTP body to send in request")
	cmd.Flags().StringSliceP("req-header", "", []string{}, "HTTP headers to send in request, format: key=value")
	// TODO: timeout=0 should mean inf; currently something times out instantly - check everything we pass this to and see what their semantics are. Might have to pass Duration::MAX to some of them
	cmd.Flags().DurationP("timeout", "", 5*time.Second, "Timeout for each individual network operation")

	/* TLS and auth */
	cmd.Flags().BoolP("no-tls", "p", false, "Make a plaintext 'HTTP' connection rather than a TLS 'HTTPS' connection")
	cmd.Flags().StringP("ca", "C", "", "Path to TLS server CA certificate")
	cmd.Flags().StringP("cert", "c", "", "Path to TLS client certificate")
	cmd.Flags().StringP("key", "k", "", "Path to TLS client key")
	cmd.Flags().StringP("tls-algo", "K", "", "Algorithm to use for generating self-signed client cert")
	cmd.Flags().String("auth-basic", "", "Username/password pair for HTTP basic auth, of the form user:password")
	cmd.Flags().String("auth-bearer", "", "Path to file whose contents should be used as Authorization: Bearer token")
	cmd.Flags().BoolP("auth-kerberos", "", false, "Negotiate Kerberos auth")
	cmd.Flags().BoolP("http-11", "", false, "Force http1.1 (disallow TLS ALPN negitiation of http2)")
	cmd.Flags().BoolP("http-3", "", false, "Force http3 (attempts QUIC/UDP connection ONLY)")

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
	cmd.Flags().BoolP("requests", "V", false, "Print summary of the requests being sent. Nothing that can't be inferred from the arguments provided, but this option spells it out")
	cmd.Flags().StringP("timestamps", "", "none", "Print timestamps: none, abs, rel.")
	cmd.Flags().StringP("verbosity", "v", "error", "Trace requests/responses as they happen, in addition to printing info at the end")

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

	log := zaplog.New()
	scope.UseLogger(log)
	switch strings.ToLower(viper.GetString("verbosity")) {
	case "debug":
		scope.SetAllScopes(telemetry.LevelDebug)
	case "info":
		scope.SetAllScopes(telemetry.LevelInfo)
	case "error":
		scope.SetAllScopes(telemetry.LevelError)
	case "none":
		scope.SetAllScopes(telemetry.LevelNone)
	default:
		scope.SetAllScopes(telemetry.LevelError)
		log.Error("Unknown log level", fmt.Errorf("log level %s invalid", viper.GetString("verbosity")))
	}

	// TODO: styler and bios to a TUI package
	// - styler should only return strings (use stringbuffer)
	s := output.NewTtyStyler(aurora.NewAurora(true))
	b := bios.NewTtyBios(s)

	tcpTarget := args[0]
	if !utils.ServerNameConformant(viper.GetString("sni")) {
		b.PrintErr("SNI ServerName cannot be an IP or contain a port number. Ignoring supplied value.")
		os.Exit(1)
	}

	if viper.GetBool("no-tls") && (viper.GetBool("tls") || viper.GetBool("tls-full")) {
		// TODO: get this by default with no-tls, cause tls is default on. Do like http-log does (?) and default all off in viper, then set a default set iff they're all off
		b.PrintWarn("TLS printing options have no effect when TLS is disabled")
	}

	// TODO mutex --http-3 and --no-tls
	// h2 and h3 require tls (see http-log)
	// On upgrades:
	// - h1 -> h2 - not so much an upgrade, negotiated by ALPN. Think there's also another way for the server to heavily hint at a move to h2?
	// - h1/2 -> h3 - alt-svc header
	// printing
	// - dns module should look for https and SVCB RRs, print them
	// - -m (httpSummary) should extract, parse, and call out any h3 upgrade offers from alt-svc
	//   - and should also note DNS signals of h3 availability
	// philosphy: we're a low-level transport inspector, not a client; we don't do redirects unless told (mantra: don't make >1 connection)
	// What we do with flags etc
	// - just go straight to h3 if --http-3 (even if no DNS)
	// - look for DNS records, and do h3 if they say so, unless --no-http-3
	// - follow alt-svc if redirects are enabled (message that alt-svc not followed if they're off, like with location header)
	// - ie with no flags, you'll get one connection, but it'll be what a client would have done
	// - but with flags can force h1 (tcp & no alpn to h2), h1/h2 (tcp despite any dns/alt-svc), h3

	// TODO: mutex --http-11 and --no-tls, as, while it's possible, Go's client just won't do it (see plaintext.go)

	// Shame pflag can't do this for us.
	timestamps := viper.GetString("timestamps")
	if timestamps != "none" && timestamps != "abs" && timestamps != "rel" {
		b.PrintErr("--timestamps value invalid")
		os.Exit(1)
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
