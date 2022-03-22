package probes

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/mt-inside/http-log/pkg/output"
)

type resolvConf struct {
	servers []string
	search  []string
	ndots   int
}

// Heavily inspired by https://cs.opensource.google/go/go/+/refs/tags/go1.18:src/net/dnsconfig_unix.go;l=67;drc=refs%2Ftags%2Fgo1.18
func parseResolvConf(b output.Bios) resolvConf {
	rc := resolvConf{search: defaultSearch(b), ndots: 1}

	fd, err := os.Open("/etc/resolv.conf")
	b.CheckErr(err)

	scanner := bufio.NewScanner(fd)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment
			continue
		}

		fields := strings.FieldsFunc(line, func(r rune) bool {
			return strings.ContainsRune(" \r\t\n", r)
		})
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "nameserver":
			if net.ParseIP(fields[1]) != nil {
				rc.servers = append(rc.servers, net.JoinHostPort(fields[1], "53"))
			}

		case "domain": // search path is just this domain
			rc.search = []string{dns.Fqdn(fields[1])}

		case "search": // search path is all these domains
			rc.search = nil // clear default search domain
			for _, d := range fields[1:] {
				rc.search = append(rc.search, dns.Fqdn(d))
			}

		case "options":
			for _, str := range fields[1:] {
				switch {
				case strings.HasPrefix(str, "ndots:"):
					rc.ndots, err = strconv.Atoi(str[len("ndots"):])
					b.CheckErr(err)
				default:
					b.PrintWarn("unknown option in resolv.conf")
					// TODO support more options
				}
			}
		}
	}

	return rc
}

func defaultSearch(b output.Bios) []string {
	h, err := os.Hostname()
	b.CheckErr(err)

	if i := strings.IndexByte(h, '.'); i >= 0 && i < len(h)-1 {
		return []string{dns.Fqdn(h[i+1:])}
	}

	return []string{"."}
}
