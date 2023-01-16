package probes

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/peterzen/goresolver"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/utils"
)

func dnsSystem(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) {
	host, _ := utils.SplitHostMaybePort(rtData.TransportTarget)
	// LookupAddr and LookupIP now equivalent except signature (https://golang-nuts.narkive.com/s2corx0l/go-nuts-net-lookuphost-vs-net-lookupip)
	ip := net.ParseIP(host)
	if ip != nil {
		names, err := net.LookupAddr(ip.String())
		b.CheckErr(err)
		responseData.DnsSystemResolves = names
		b.TraceWithName("dns", "Provided target %s is already an IP.", ip)
	} else {
		ips, err := net.LookupIP(host)
		b.CheckErr(err)
		responseData.DnsSystemResolves = utils.MapToString(ips)
		ip = ips[0]
		b.TraceWithName("dns", "Connection will use first-returned system-resolved IP", "IP", ip)
	}
}

/* DNSInfo prints detailed results from forward and reverse zone resolution of the given address. addr can be either a hostname or an IPv4/6
 * Note: This only looks in DNS, like say nslookup does.
 * - We should (and do) give the /name/ to http client so it can resolve multiple and do failover
 * - upshot of that is that it uses the system resolver (go's or libc depending on CGO)
 * - This is what we want, because we also get files etc and anything else they've added into nsswitch
 * Downside is we can't stop it trying localhost.$domain, because it doesn't know "localhost" is special - it's only special cause it's in /etc/hosts, and we can't avoid the fact that a lot of DNS servers respond for localhost.foo. when they shouldn't
 */
// FIXME: blows up when there's no internet (ie responses are empty / nil)
func dnsManual(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) {
	// TODO: Ideally we'd save all this info in responseData and then print in Print(), but it's a lot of effort and this always runs in a separate phase
	// - this is probably needed, cause DANE etc should print with tls(?)
	b.Banner("DNS - extra manual resolution")
	s.Info("This section is for information only; its results are not used to determine connection address.")
	s.Info("These are hand-cranked DNS queries. DNS is hard; the results may be plain wrong.")
	s.Info("This is DNS-only, ie no attempt to even query files, let alone any other nsswitch stuff.")

	// TODO: add geoip / ASN lookup (a la envbin)

	host, _ := utils.SplitHostMaybePort(rtData.TransportTarget)
	ip := net.ParseIP(host)
	if ip != nil {
		// It's an IP: do reverse lookup
		names := queryRevDNS(s, b, requestData.Timeout, ip)
		for _, name := range names {
			ips, _ := queryDNS(s, b, requestData.Timeout, name)
			if len(ips) > 0 {
				checkRevDNSConsistent(s, b, ip, ips)
			}
		}
	} else {
		// It's not an IP; assume it's a name: do forwards lookup
		ips, fqdn := queryDNS(s, b, requestData.Timeout, host)
		for _, ip := range ips {
			revNames := queryRevDNS(s, b, requestData.Timeout, ip)
			if len(revNames) > 0 {
				checkDNSConsistent(s, b, fqdn, revNames)
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
func queryDNS(s output.TtyStyler, b output.Bios, timeout time.Duration, name string) ([]net.IP, string) {

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	b.CheckErr(err)

	names := dnsConfig.NameList(name)

	c := dns.Client{
		Dialer: &net.Dialer{Timeout: timeout},
	}

	var server string
	var fqdn string
	var in *dns.Msg // Just takes the value of the last one in the loop, ie the v6 AAAA answer, but servers are authoritative for /zones/ so if it's auth for v6 is it for v4 too (cause we're talking forward zones)
	var answers []dns.RR
serversLoop:
	for _, serverHost := range dnsConfig.Servers {
		server = net.JoinHostPort(serverHost, dnsConfig.Port)
		b.TraceWithName("dns", "Trying server", "addr", server)

		for _, name := range names {
			b.TraceWithName("dns", "Trying search path item", "fqdn", name)

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
	 * - 1. implement DNSSEC validation manually (using the dns library and doing all the RRSIG, DNSKEY, DS queries right up to the root). This is a massive amount of work
	 * - 2. use goresolver library to do that for us (but don't use it for the main queries cause we want more control and visbility)
	 * - 3. use the system resolver to do it (local stub / router / ISP / whatever) - set the EDNS0 flag in the question and see if the right flag is in the answer
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

func queryRevDNS(s output.TtyStyler, b output.Bios, timeout time.Duration, ip net.IP) []string {

	revIP, err := dns.ReverseAddr(ip.String())
	b.CheckErr(err)

	b.TraceWithName("dns", "Resolving in reverse-zone", "address", revIP)

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	b.CheckErr(err)

	c := dns.Client{
		Dialer: &net.Dialer{Timeout: timeout},
	}

	var server string
	var in *dns.Msg
	var answers []dns.RR
serversLoop:
	for _, serverHost := range dnsConfig.Servers {
		server = net.JoinHostPort(serverHost, dnsConfig.Port)
		b.TraceWithName("dns", "Trying server", "addr", server)

		m := new(dns.Msg)
		// By default this sets the flag to ask whatever server is configured to recurse for us. We could manually recurse, either continually against the system server (thus using its cache), or from the root servers down. However both are a huge amount of work for no gain
		m.SetQuestion(revIP, dns.TypePTR)

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
			if ptr.Hdr.Name != revIP {
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
