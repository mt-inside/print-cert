package main

import (
	"fmt"
	"net"
	"os"

	"bitbucket.mwam.local/infra/lb-checker/pkg/utils"
	. "bitbucket.mwam.local/infra/lb-checker/pkg/utils"
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

	if len(os.Args) != 3 {
		fmt.Println("Usage: addr port")
		os.Exit(1)
	}

	addr := os.Args[1]
	port := os.Args[2]

	var ip net.IP
	var host string

	ip = net.ParseIP(addr)
	if ip == nil {
		host = addr
		ip = CheckDns(host)
		CheckRevDns(ip)
	} else {
		host = CheckRevDns(ip)
		CheckDns(host)
	}

	/* Check DNS */

	Banner("DNS")

	// f5RevHost := checkRevDns(f5Ip)
	// checkDnsConsistent(f5Host, f5RevHost)

	// nsHost := checkRevDns(nsIp)
	// nsRevIp := checkDns(nsHost)
	// checkDnsConsistent(nsIp.String(), nsRevIp.String())

	/* Check F5 */

	tcpAddr := net.JoinHostPort(addr, port)
	utils.CheckTls2(tcpAddr, addr) // TODO support -h host, for when giving an ip

	/* Fin */

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}
