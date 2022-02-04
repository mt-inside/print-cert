package main

import (
	"fmt"
	"net"
	"os"

	"bitbucket.mwam.local/infra/lb-checker/pkg/utils"
	. "bitbucket.mwam.local/infra/lb-checker/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/* TODO
* - when checking SAN validity, also check subj (need to parse that CN)
* - show key len
* - show dnssec and dane status of name
* - use -h for sni, unless -s is given
* - use "-a http" to do an http get /, print server, content-type, body-len (for this, drop the manual NextProtos, give the tls config to an http transport, give that to http client, and use that to do the get. Somewhere (the response object?) you can get hold of the conn object
* - see if the address parses as an IP. IP or name, print the reverse (and go again and again until you see one you've seen before, print them all)
 */

func main() {

	cmd := &cobra.Command{
		Use:  "addr port",
		Args: cobra.ExactArgs(2),
		Run:  appMain,
	}

	cmd.Flags().StringP("sni", "s", "", "SNI ServerName")
	cmd.Flags().StringP("host", "a", "", "HTTP Host / :authority header")
	viper.BindPFlag("sni", cmd.Flags().Lookup("sni"))
	viper.BindPFlag("host", cmd.Flags().Lookup("host"))

	CheckErr(cmd.Execute())
}

func appMain(cmd *cobra.Command, args []string) {

	addr := args[0]
	port := args[1]

	var ip net.IP
	var name string

	Banner("DNS")

	ip = net.ParseIP(addr)
	if ip == nil {
		name = addr
		ip = CheckDns(name)
		CheckRevDns(ip)
	} else {
		name = CheckRevDns(ip)
		CheckDns(name)
	}

	Banner("TLS")

	// f5RevHost := checkRevDns(f5Ip)
	// checkDnsConsistent(f5Host, f5RevHost)

	// nsHost := checkRevDns(nsIp)
	// nsRevIp := checkDns(nsHost)
	// checkDnsConsistent(nsIp.String(), nsRevIp.String())

	/* Check F5 */

	host := viper.GetString("host")
	if host == "" {
		host = addr
	}
	sni := viper.GetString("sni")
	if sni == "" {
		sni = host
	}
	utils.CheckTls2(addr, port, sni, host)

	/* Fin */

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}
