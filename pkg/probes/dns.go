package probes

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/peterzen/goresolver"
)

func DNSInfo(s output.TtyStyler, b output.Bios, addr string) {
	ip := net.ParseIP(addr)
	if ip == nil {
		ips, fqdn := queryDNS(s, b, addr)
		for _, ip := range ips {
			revNames := queryRevDNS(s, b, ip)
			if len(revNames) > 0 {
				checkDNSConsistent(s, b, fqdn, revNames)
			}
		}
	} else {
		names := queryRevDNS(s, b, ip)
		for _, name := range names {
			ips, _ := queryDNS(s, b, name)
			if len(ips) > 0 {
				checkRevDNSConsistent(s, b, ip, ips)
			}
		}
	}
}

/* Testing:
* - www.wikipedia.org has CNAME
* - cloudflare.net is DNSSEC
* - localhost is in Files
* - google.com has ipv6 & v4
 */
func queryDNS(s output.TtyStyler, b output.Bios, name string) ([]net.IP, string) {

	/* TODO: be clear that this is just printing info.
	 * - This only looks in DNS, like say nslookup does.
	 * - We should (and do) give the /name/ to http client so it can resolve multiple and do failover
	 * - upshot of that is that it uses the system resolver (go's or libc depending on CGO)
	 * - This is what we want, so that we also get files etc and anything else they've added into nsswitch
	 * eg we can't stop it trying localhost.$domain, because it doesn't know "localhost" is special - it's only special cause it's in /etc/hosts.
	 * - what's actually weird here is that lookup suceedes, stop it doing so (try on other machines, might be a systemd-resolved quirk?
	 * - then, if DNS lookups fail, call the system resolver (net.LookupHost) and show its answer if it gives one, along with a note that the name is coming from some non-DNS source (varying dpeding on CGO - detect GCO and either print go resolver's list of sources or just say "it's up to your libc")
	 */
	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	b.CheckErr(err)

	names := dnsConfig.NameList(name)

	c := dns.Client{
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	}

	var server string
	var fqdn string
	var in *dns.Msg // Just takes the value of the last one in the loop, ie the v6 AAAA answer, but servers are authoritative for /zones/ so if it's auth for v6 is it for v4 too (cause we're talking forward zones)
	var answers []dns.RR
serversLoop:
	for _, serverHost := range dnsConfig.Servers {
		server = net.JoinHostPort(serverHost, dnsConfig.Port)
		b.Trace("Trying DNS server", "addr", server)

		for _, name := range names {
			b.Trace("Trying search path item", "fqdn", name)

			/* v4 */

			m := new(dns.Msg)
			// By default this sets the flag to ask whatever server is configured to recurse for us. We could manually recurse, either continually against the system server (thus using its cache), or from the root servers down. However both are a huge amount of work for no gain
			m.SetQuestion(name, dns.TypeA)

			in, _, err = c.Exchange(m, server)
			if err != nil {
				continue serversLoop
			}

			answers = append(answers, in.Answer...)

			/* v6 */

			m = new(dns.Msg)
			m.SetQuestion(name, dns.TypeAAAA)

			in, _, err = c.Exchange(m, server)
			if err != nil {
				continue serversLoop
			}

			answers = append(answers, in.Answer...)

			if len(answers) > 0 {
				fqdn = name
				break serversLoop
			}
		}

		//assert(len(answers) == 0)
		// Not fatal cause we're only printing for information
		b.PrintWarn(fmt.Sprintf("%s: NXDOMAIN", s.Addr(name)))
		return []net.IP{}, name
	}
	if err != nil {
		b.PrintWarn("All DNS servers failed.")
		return []net.IP{}, name
	}

	/* Validate DNSSEC. Options:
	 * - implement DNSSEC validation manually (using the dns library and doing all the RRSIG, DNSKEY, DS queries right up to the root). This is a massive amount of work
	 * - use this goresolver library to do that for us (but don't use it for the main queries cause we want more control and visbility)
	 * - use the system resolver to do it (local stub / router / ISP / whatever) - set the EDNS0 flag in the question and see if the right flag is in the answer
	 *
	 * Choice: 2 - goresolver is known to do it properly (recursive resolvers are known to *strip* DNSSEC-related records, let alone not validate them properly).
	 */

	resolver, err := goresolver.NewResolver("/etc/resolv.conf")
	b.CheckErr(err)

	_, dnssecErr := resolver.StrictNSQuery(fqdn, dns.TypeA)

	/* Print */

	as := printCnameChain(s, b, fqdn, answers, dnssecErr)

	// Authoritative means that the server you're talking to *hosts* that zone - honestly unlikely as you're probably talking to a local stub resolver, or a caching resolver on a home router / ISP.
	fmt.Printf(
		"\tDNS Server: %s, authoritative? %s\n",
		s.Addr(server),
		s.YesInfo(in.Authoritative),
	)

	return as, fqdn
}

func printCnameChain(s output.TtyStyler, b output.Bios, question string, answers []dns.RR, dnssecErr error) []net.IP {

	/* Algo notes
	 * - CNAMEs can only point to one thing, thus there can only be one "chain" with no branching along the way
	 * - exception is the last "link" which is the A record(s)
	 * - CNAMEs can point to other CNAMEs, though it's rare
	 * - I've not seen any DNS server flatten CNAME chains yet
	 * - TTL on all returned records will be the same, as they all come in one Answer. Even if you query part-way down the chain to get the end of the chain into the cache, querying further back in the chain will re-assert the later records into the cache, setting their TTLs to be the same as the new ones.
	 */

	/* Index */

	cnames := map[string]string{}
	var as []net.IP
	for _, ans := range answers {
		switch t := ans.(type) {
		case *dns.CNAME:
			cnames[t.Hdr.Name] = t.Target
		case *dns.A:
			as = append(as, t.A)
		case *dns.AAAA:
			as = append(as, t.AAAA)
		}
	}

	/* Print */

	fmt.Printf("%s ->", s.Addr(question))
	cname := question
	for {
		if target, found := cnames[cname]; found {
			fmt.Printf(" %s ->", s.Addr(target))
			cname = target
		} else {
			break
		}
	}

	fmt.Printf(" %s", s.List(output.Slice2Strings(as), s.AddrStyle))

	fmt.Printf(" (dnssec? %s, ttl remaining %s)\n",
		s.YesError(dnssecErr),
		time.Duration(answers[0].Header().Ttl)*time.Second,
	)

	return as
}

func queryRevDNS(s output.TtyStyler, b output.Bios, ip net.IP) []string {

	revIp, err := dns.ReverseAddr(ip.String())
	b.CheckErr(err)

	b.Trace("Resolving in reverse-zone", "address", revIp)

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	b.CheckErr(err)

	c := dns.Client{
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	}

	var server string
	var in *dns.Msg
	var answers []dns.RR
serversLoop:
	for _, serverHost := range dnsConfig.Servers {
		server = net.JoinHostPort(serverHost, dnsConfig.Port)
		b.Trace("Trying DNS server", "addr", server)

		m := new(dns.Msg)
		// By default this sets the flag to ask whatever server is configured to recurse for us. We could manually recurse, either continually against the system server (thus using its cache), or from the root servers down. However both are a huge amount of work for no gain
		m.SetQuestion(revIp, dns.TypePTR)

		in, _, err = c.Exchange(m, server)
		if err != nil {
			continue serversLoop
		}

		answers = append(answers, in.Answer...)

		if len(answers) > 0 {
			break serversLoop
		}

		//assert(len(in.Answer) == 0)
		b.PrintInfo(fmt.Sprintf("%s: NXDOMAIN", s.Addr(ip.String()))) // Info-level cause reverse DNS is never set up properly
		return []string{}
	}
	if err != nil {
		b.PrintWarn("All DNS servers failed.")
		return []string{}
	}

	/* Validate DNSSEC */

	resolver, err := goresolver.NewResolver("/etc/resolv.conf")
	b.CheckErr(err)

	_, dnssecErr := resolver.StrictNSQuery(in.Question[0].Name, dns.TypePTR)

	/* Print */

	var ends []string
	for _, ans := range answers {
		if ptr, ok := ans.(*dns.PTR); ok {
			if ptr.Hdr.Name != revIp {
				// Because chains are (I think) permitted, we theoretically have a tree structure. Make sure it's flat for now
				panic(errors.New("PTR chain"))
			}
			ends = append(ends, ptr.Ptr)
		} else {
			// Don't think anything stops CNAMEs in this mix
			panic(errors.New("non-PTR record returned"))
		}
	}

	fmt.Printf(
		"%s -> %s (dnssec? %s, ttl remaining %s)\n",
		s.Addr(ip.String()),
		s.List(ends, s.AddrStyle),
		s.YesError(dnssecErr),
		time.Duration(in.Answer[0].Header().Ttl)*time.Second,
	)

	// Authoritative means that the server you're talking to *hosts* that zone - honestly unlikely as you're probably talking to a local stub resolver, or a caching resolver on a home router / ISP.
	fmt.Printf(
		"\tDNS Server: %s, authoritative? %s\n",
		s.Addr(server),
		s.YesInfo(in.Authoritative),
	)

	return ends
}

func checkDNSConsistent(s output.TtyStyler, b output.Bios, orig string, revs []string) {
	for _, rev := range revs {
		if rev == orig {
			return
		}
	}
	b.PrintWarn(fmt.Sprintf("dns inconsistency: %s not in %s\n", s.Addr(orig), s.List(revs, s.AddrStyle)))
}
func checkRevDNSConsistent(s output.TtyStyler, b output.Bios, orig net.IP, revs []net.IP) {
	for _, rev := range revs {
		if rev.Equal(orig) {
			return
		}
	}
	b.PrintWarn(fmt.Sprintf("dns inconsistency: %s not in %s\n", s.Addr(orig.String()), s.List(output.Slice2Strings(revs), s.AddrStyle)))
}
