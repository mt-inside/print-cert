package probes

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/peterzen/goresolver"

	"github.com/mt-inside/go-usvc"
	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/utils"

	"github.com/mt-inside/print-cert/pkg/state"
)

func dnsSystem(
	s output.TtyStyler,
	b bios.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) {
	// TODO: http-log should do a reverse DNS lookup on the caller, but no more. (well, maybe geoip / AS lookup...)
	// - should be a flag, cause that's a network request which might be firewalled and might take time

	host, _ := utils.SplitHostMaybePort(rtData.TransportTarget)
	// LookupAddr and LookupIP now equivalent except signature (https://golang-nuts.narkive.com/s2corx0l/go-nuts-net-lookuphost-vs-net-lookupip)
	ip := net.ParseIP(host)
	if ip != nil {
		names, err := net.LookupAddr(ip.String())
		b.CheckPrintErr(err) // TODO: should save the errors rather than print here, and print at op time
		if err != nil {
			return
		}
		responseData.DnsSystemResolves = names
		log.Info("Provided target %s is already an IP", "IP", ip)
	} else {
		ips, err := net.LookupIP(host)
		b.CheckPrintErr(err)
		if err != nil {
			return
		}
		responseData.DnsSystemResolves = utils.MapToString(ips)
		ip = ips[0]
		log.Info("Connection will use first-returned system-resolved IP", "IP", ip)
	}
}

/* DNSInfo prints detailed results from forward and reverse zone resolution of the given address. addr can be either a hostname or an IPv4/6
 * Note: This only looks in DNS, like say nslookup does.
 * - We should (and do) give the /name/ to http client so it can resolve multiple and do failover
 * - upshot of that is that it uses the system resolver (go's or libc depending on CGO)
 * - This is what we want, because we also get files etc and anything else they've added into nsswitch
 * Downside is we can't stop it trying localhost.$domain, because it doesn't know "localhost" is special - it's only special cause it's in /etc/hosts, and we can't avoid the fact that a lot of DNS servers respond for localhost.foo. when they shouldn't
 */
func dnsManual(
	s output.TtyStyler,
	b bios.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) {
	var op output.IndentingBuilder

	// TODO: Ideally we'd save all this info in responseData and then print in Print(), but it's a lot of effort and this always runs in a separate phase
	// - this is probably needed, cause DANE etc should print with tls(?)
	op.Block(s.Banner("DNS - extra manual resolution"))
	op.Line(s.Info("This section is for information only; its results are not used to determine connection address."))
	op.Line(s.Info("These are hand-cranked DNS queries. DNS is hard; the results may be plain wrong."))
	op.Line(s.Info("This is DNS-only, ie no attempt to even query files, let alone any other nsswitch stuff."))

	// TODO: add geoip / ASN lookup (a la envbin)

	host, _ := utils.SplitHostMaybePort(rtData.TransportTarget)
	ip := net.ParseIP(host)
	if ip != nil {
		// It's an IP: do reverse lookup
		names := queryRevDNS(s, b, requestData.Timeout, ip)
		if len(names) > 0 {
			op.Line("Checking forward zone and consistency for preferred answer")
		}
		for _, name := range names {
			ips, _ := queryDNS(s, b, requestData.Timeout, name)
			if len(ips) > 0 {
				checkRevDNSConsistent(s, b, ip, ips)
			}
		}
	} else {
		// It's not an IP; assume it's a name: do forwards lookup
		ips, fqdn := queryDNS(s, b, requestData.Timeout, host)
		if len(ips) > 0 {
			op.Line("Checking reverse zone and consistency for preferred answer")
		}
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
* - add 108.162.193.144 (theo.ns.cloudflare.com) as a system dns server then try barnard.empty.org.uk, is cool
 */
func queryDNS(s output.TtyStyler, b bios.Bios, timeout time.Duration, query string) ([]net.IP, string) {
	var op output.IndentingBuilder

	log.Info("Doing forwards resolution", "name", query)

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	b.Unwrap(err)

	// Note that when you "turn the wifi off", at least on macos, resolv.conf is rewritten with no servers, so this loop just doesn't run
	if len(dnsConfig.Servers) == 0 {
		op.Line(s.RenderWarn("No DNS servers configured. No internet?"))
	}

	c := dns.Client{
		Dialer: &net.Dialer{Timeout: timeout},
	}

	queries := dnsConfig.NameList(query)

	var preferredFqdn string = query
	var preferredAddrs []net.IP

	for _, serverHost := range dnsConfig.Servers {
		server := net.JoinHostPort(serverHost, dnsConfig.Port)
		serverHit := false
		log.Debug("Trying server", "addr", server)

		op.Linef("Server %s", s.Addr(server))
		op.Indent()

		for _, name := range queries {
			var queryAnswers []dns.RR
			var queryCnames map[string]string
			var queryAddrs []net.IP

			log.Debug("Trying search path item", "fqdn", name)

			/* v4 */

			m := new(dns.Msg)
			// By default this sets the flag to ask whatever server is configured to recurse for us. We could manually recurse, either continually against the system server (thus using its cache), or from the root servers down. However both are a huge amount of work for no gain
			m.SetQuestion(name, dns.TypeA)

			in, _, err := c.Exchange(m, server)
			if err != nil {
				op.Line(s.RenderWarn("Error: " + err.Error()))
				// It's UDP; just continue in the face of errors
			} else {
				queryAnswers = append(queryAnswers, in.Answer...)
			}

			/* v6 */

			m = new(dns.Msg)
			m.SetQuestion(name, dns.TypeAAAA)

			in, _, err = c.Exchange(m, server)
			if err != nil {
				op.Line(s.RenderWarn("Error: " + err.Error()))
			} else {
				queryAnswers = append(queryAnswers, in.Answer...)
			}

			// We've tried all the domains on the search path, and there haven't been any errors, just no results, so it's an NXDOMAIN.
			// - I believe this is the same as system resolution, ie next server won't be tried if there's an empty result but no error
			// Not fatal cause we're only printing for information
			if len(queryAnswers) > 0 {
				serverHit = true

				queryCnames, queryAddrs = buildCnameChain(queryAnswers)

				/* Validate DNSSEC. Options:
				 * - 1. implement DNSSEC validation manually (using the `dns` library and doing all the RRSIG, DNSKEY, DS queries right up to the root). This is a massive amount of work
				 * - 2. use goresolver library (itself based on `dns`) to do that for us (but don't use it for the main queries cause we want more control and visbility)
				 * - 3. use the system resolver to do it (local stub / router / ISP / whatever) - set the EDNS0 flag in the question and see if the right flag is in the answer
				 *
				 * Choice: 2 - goresolver is known to do it properly (recursive resolvers are known to *strip* DNSSEC-related records, let alone not validate them properly).
				 *
				 * We show DNSSEC status per server, becuase though it should be the same for all (there should be one authoritative server for the zone, and a bunch of recursive/caching servers also hosting it), some caching resolvers strip dnssec info so it's useful to see that.
				 * We show DNSSEC status per search-path item because DNSSEC is per zone.
				 */
				// TODO: this library won't let us give it, or get at, the `dns` library's ClientConfig, so we can't pick which server we wanna query. Fork / PR library?
				// Hack: redirect go's log package to null for the duration of these calls, cause this library logs.
				usvc.DisableGoLog()
				resolver, err := goresolver.NewResolver("/etc/resolv.conf")
				b.Unwrap(err)
				_, dnssecErr := resolver.StrictNSQuery(name, dns.TypeA)
				// usvc.InterceptGoLog(b.GetLogger()) TODO: reimpl this with tet/telemetry log

				/* Print */

				op.Tabs()
				op.Print(renderCnameChain(s, b, name, queryCnames, queryAddrs))
				// Authoritative means that the server you're talking to *hosts* that zone - honestly unlikely as you're probably talking to a local stub resolver, or a caching resolver on a home router / ISP.
				op.Printf(" (authoritative? %s, ttl remaining %s, dnssec? %s)",
					s.YesInfo(in.Authoritative),                             // Authority is per zone, so using this last result is fine, as we loop per search domain
					time.Duration(queryAnswers[0].Header().Ttl)*time.Second, // Each record could theoretically have different TTLs, but they're usually set zone-wide
					s.YesError(dnssecErr),
				)
				op.NewLine()

				/* Latch */

				// Latch the FQDN and results given by the first server, first search domain that gives one, as that's what the system would use
				if len(preferredAddrs) == 0 {
					preferredFqdn = name
					preferredAddrs = queryAddrs
				}
			}
		}
		if !serverHit {
			op.Linef("%s: NXDOMAIN", s.Addr(query))
		}

		op.Dedent()
	}

	op.Output()

	return preferredAddrs, preferredFqdn // in the case we didn't get any addrs, preferredFqdn will be the original query `name`
}

// While it's at it, filters out all the CNAME records, returning only A and AAAAs
func buildCnameChain(records []dns.RR) (map[string]string, []net.IP) {

	/* Algo notes
	 * - CNAMEs can only point to one thing, thus there can only be one "chain" with no branching along the way
	 * - exception is the last "link" which is the A record(s)
	 * - CNAMEs can point to other CNAMEs, though it's rare
	 * - I've not seen any DNS server flatten CNAME chains yet
	 * - TTL on all returned records will be the same, as they all come in one Answer. Even if you query part-way down the chain to get the end of the chain into the cache, querying further back in the chain will re-assert the later records into the cache, setting their TTLs to be the same as the new ones.
	 */

	cnames := map[string]string{}
	var as []net.IP
	for _, ans := range records {
		switch t := ans.(type) {
		case *dns.CNAME:
			cnames[t.Hdr.Name] = t.Target
		case *dns.A:
			as = append(as, t.A)
		case *dns.AAAA:
			as = append(as, t.AAAA)
		}
	}

	return cnames, as
}

func renderCnameChain(s output.TtyStyler, b bios.Bios, question string, cnames map[string]string, addrs []net.IP) string {
	op := ""

	op += fmt.Sprintf("%s ->", s.Addr(question))
	cname := question
	for {
		if target, found := cnames[cname]; found {
			op += fmt.Sprintf(" %s ->", s.Addr(target))
			cname = target
		} else {
			break
		}
	}

	op += fmt.Sprintf(" %s", s.List(utils.MapToString(addrs), output.AddrStyle))

	return op
}

func queryRevDNS(s output.TtyStyler, b bios.Bios, timeout time.Duration, ip net.IP) []string {
	var op output.IndentingBuilder

	revIP, err := dns.ReverseAddr(ip.String())
	b.CheckPrintErr(err)

	log.Info("Resolving in reverse-zone", "address", revIP)

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	b.CheckPrintErr(err)

	// Note that when you "turn the wifi off", at least on macos, resolv.conf is rewritten with no servers, so this loop just doesn't run
	if len(dnsConfig.Servers) == 0 {
		op.Line(s.RenderWarn("No DNS servers configured. No internet?"))
	}

	c := dns.Client{
		Dialer: &net.Dialer{Timeout: timeout},
	}

	var preferredNames []string

	for _, serverHost := range dnsConfig.Servers {
		server := net.JoinHostPort(serverHost, dnsConfig.Port)
		log.Debug("Trying server", "addr", server)

		op.Linef("Server %s", s.Addr(server))
		op.Indent()

		var queryAnswers []dns.RR

		m := new(dns.Msg)
		// By default this sets the flag to ask whatever server is configured to recurse for us. We could manually recurse, either continually against the system server (thus using its cache), or from the root servers down. However both are a huge amount of work for no gain
		m.SetQuestion(revIP, dns.TypePTR)

		in, _, err := c.Exchange(m, server)
		if err != nil {
			b.PrintWarn("Error: " + err.Error())
		} else {
			queryAnswers = append(queryAnswers, in.Answer...)
		}

		if len(queryAnswers) > 0 {
			queryNames := buildPtrEnds(queryAnswers, revIP)

			/* Validate DNSSEC */

			resolver, err := goresolver.NewResolver("/etc/resolv.conf")
			b.CheckPrintErr(err)

			_, dnssecErr := resolver.StrictNSQuery(in.Question[0].Name, dns.TypePTR)

			/* Print */

			op.Tabs()
			op.Printf(
				"%s -> %s",
				s.Addr(ip.String()),
				s.List(queryNames, output.AddrStyle),
			)
			op.Printf(
				" (authoritative? %s, ttl remaining %s, dnssec? %s)",
				s.YesInfo(in.Authoritative),
				time.Duration(in.Answer[0].Header().Ttl)*time.Second,
				s.YesError(dnssecErr),
			)
			op.NewLine()

			/* Latch */

			if len(preferredNames) == 0 {
				preferredNames = queryNames
			}
		} else {
			op.Linef("%s: NXDOMAIN", s.Addr(ip.String()))
		}

		op.Dedent()
	}

	return preferredNames
}

func buildPtrEnds(answers []dns.RR, query string) (ends []string) {

	for _, ans := range answers {
		if ptr, ok := ans.(*dns.PTR); ok {
			if ptr.Hdr.Name != query {
				// Because chains are (I think) permitted, we theoretically have a tree structure. Make sure it's flat for now
				panic(errors.New("PTR chain"))
			}
			ends = append(ends, ptr.Ptr)
		} else {
			// Don't think anything stops CNAMEs in this mix
			panic(errors.New("non-PTR record returned"))
		}
	}

	return
}

func checkDNSConsistent(s output.TtyStyler, b bios.Bios, orig string, revs []string) {
	for _, rev := range revs {
		if rev == orig {
			return
		}
	}
	b.PrintWarn(fmt.Sprintf("dns inconsistency: %s not in %s", s.Addr(orig), s.List(revs, output.AddrStyle)))
}
func checkRevDNSConsistent(s output.TtyStyler, b bios.Bios, orig net.IP, revs []net.IP) {
	for _, rev := range revs {
		if rev.Equal(orig) {
			return
		}
	}
	b.PrintWarn(fmt.Sprintf("dns inconsistency: %s not in %s", s.Addr(orig.String()), s.List(utils.MapToString(revs), output.AddrStyle)))
}
