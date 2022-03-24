package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/MarshallWace/go-spnego"
	"github.com/miekg/dns"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/peterzen/goresolver"
)

/* TODO:
* - single, configurable timeout for all network operations
 */

/* Testing:
* - www.wikipedia.org has CNAME
* - cloudflare.net is DNSSEC
* - localhost is in Files
* - google.com has ipv6 & v4
 */
func CheckDNS2(s output.TtyStyler, b output.Bios, name string) ([]net.IP, string) {

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

			var err error

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

		if len(answers) == 0 {
			// Not fatal cause we're only printing for information
			b.PrintWarn("NXDOMAIN")
		}
	}
	if len(answers) == 0 {
		b.PrintWarn("All DNS servers returned no answers or failed.")
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

	fmt.Printf(" %s", s.List(output.IPs2Strings(as), s.AddrStyle))

	fmt.Printf(" (dnssec? %s, ttl remaining %s)\n",
		s.YesError(dnssecErr),
		time.Duration(answers[0].Header().Ttl)*time.Second,
	)

	return as
}

func CheckRevDNS2(s output.TtyStyler, b output.Bios, ip net.IP) []string {

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

		var err error

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

		if len(in.Answer) == 0 {
			b.PrintWarn("NXDOMAIN")
		}
	}
	if len(answers) == 0 {
		b.PrintWarn("All DNS servers failed.")
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

func CheckDnsConsistent(s output.TtyStyler, b output.Bios, orig string, rev string) {
	if rev != orig {
		b.PrintWarn(fmt.Sprintf("dns inconsistency: %s != %s\n", s.Addr(orig), s.Addr(rev)))
	}
}

func GetPlaintextClient(s output.TtyStyler, b output.Bios) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
					// Note: happens "after creating the network connection but before actually dialing."
					Control: func(network, address string, rawConn syscall.RawConn) error {
						b.Banner("TCP")
						b.Trace("Dialing", "addr", address)

						return nil
					},
				}
				conn, err := dialer.DialContext(ctx, network, address)
				b.CheckErr(err)

				fmt.Printf("L4 connected %s -> %s\n", s.Addr(conn.LocalAddr().String()), s.Addr(conn.RemoteAddr().String()))

				return conn, err
			},
			ResponseHeaderTimeout: 5 * time.Second,
			DisableCompression:    true,
		},
	}

	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		fmt.Printf("Redirected to %s\n", s.Addr(req.URL.String()))

		fmt.Printf("\tUpdating SNI ServerName to %s\n", s.Addr(req.URL.Host))
		c.Transport.(*http.Transport).TLSClientConfig.ServerName = req.URL.Host

		fmt.Printf("\tUpdating HTTP Host header to %s\n", s.Addr(req.URL.Host))
		req.Host = req.URL.Host

		// TODO: should re-do DNS checks here cause it can get interesting (try: amazon.com - redirects to www.amazon.com, which is a long CNAME chain)

		return nil
	}

	return c
}
func GetTLSClient(s output.TtyStyler, b output.Bios, sni, caPath, certPath, keyPath string, krb, http11 bool) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
					// Note: happens "after creating the network connection but before actually dialing."
					Control: func(network, address string, rawConn syscall.RawConn) error {
						b.Banner("TCP")
						b.Trace("Dialing", "addr", address)

						return nil
					},
				}
				conn, err := dialer.DialContext(ctx, network, address)
				b.CheckErr(err)

				fmt.Printf("L4 connected %s -> %s\n", s.Addr(conn.LocalAddr().String()), s.Addr(conn.RemoteAddr().String()))

				return conn, err
			},
			TLSHandshakeTimeout:   5 * time.Second, // assume this is just the TLS handshake ie tcp handshake is covered by the dialer
			ResponseHeaderTimeout: 5 * time.Second,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // deliberate, qv
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         sni, // SNI for TLS vhosting
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					b.Trace("Asked for a TLS client certificate")

					if certPath == "" || keyPath == "" {
						b.PrintWarn("Asked to present a client cert but none configured (-c/-k). Not presenting a cert, this might cause the server to abort the handshake.")
						return &tls.Certificate{}, nil
					}

					/* Load from disk */
					pair, err := tls.LoadX509KeyPair(certPath, keyPath)
					b.CheckErr(err)

					/* Parse */
					var certs []*x509.Certificate
					for _, bytes := range pair.Certificate {
						cert, err := x509.ParseCertificate(bytes)
						b.CheckErr(err)
						certs = append(certs, cert)
					}

					/* Print */
					fmt.Println("Presenting client cert chain")
					s.ClientCertChain(certs)

					/* Hand to http client */
					return &pair, err
				},
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					b.Trace("Hook: TLS built-in cert verification finished (no-op in our config)")

					if len(verifiedChains) > 0 {
						panic("Shouldn't see this cause we set InsecureSkipVerify")
					}

					return nil
				},
				VerifyConnection: func(cs tls.ConnectionState) error {
					b.Trace("Hook: all TLS cert verification finished")
					b.Banner("TLS")

					fmt.Printf("%s handshake complete\n", s.Noun(output.TLSVersionName(cs.Version)))
					fmt.Printf("\tCypher suite %s\n", s.Noun(tls.CipherSuiteName(cs.CipherSuite)))

					// TODO this ^^ is the agreed-upon symmetic scheme? Print the key-exchange also used to get it - DH or ECDH. Already printing the signature scheme (RSA, ECDSA, etc) when we print certs
					fmt.Printf("\tALPN proto %s\n", s.OptionalString(cs.NegotiatedProtocol, s.NounStyle))
					fmt.Printf("\tOCSP info stapled to response? %s\n", s.YesNo(len(cs.OCSPResponse) > 0))
					fmt.Println()

					/* Print cert chain */

					fmt.Println("Received serving cert chain")

					// This verification would normally happen automatically, and we'd be given these chains as args to VerifyPeerCertificate()
					// However a failed validation would cause client.Do() to return early with that error, and we want to carry on
					// This we set InsecureSkipVerify to stop the early bail out, and basically recreate the default checks ourselves
					opts := x509.VerifyOptions{
						DNSName:       cs.ServerName,
						Intermediates: x509.NewCertPool(),
					}
					if caPath != "" {
						bytes, err := ioutil.ReadFile(caPath)
						b.CheckErr(err)

						roots := x509.NewCertPool()
						ok := roots.AppendCertsFromPEM(bytes)
						b.CheckOk(ok)
						opts.Roots = roots
					}
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}

					chains, err := cs.PeerCertificates[0].Verify(opts)
					if err != nil {
						s.ServingCertChain(&cs.ServerName, nil, cs.PeerCertificates, nil)
						fmt.Println()
					} else {
						for _, chain := range chains {
							s.ServingCertChain(&cs.ServerName, nil, cs.PeerCertificates, chain)
							fmt.Println()
						}
					}

					fmt.Println("\tCert valid?", s.YesError(err))
					fmt.Println()

					return nil
				},
			},
			ForceAttemptHTTP2: !http11, // Because we provide our own TLSClientConfig, golang defaults to no ALPN, we have to insist. Note that just setting TLSClientConfig.NextProtos isn't enough; this flag adds upgrade handler functions and other stuff
		},
	}

	if krb {
		c.Transport = &spnego.Transport{NoCanonicalize: true, Transport: *c.Transport.(*http.Transport)}
	}

	// Really ugly that this can't be set in the literal (so that it can reference and reach into the client and mutate it)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		fmt.Printf("Redirected to %s\n", s.Addr(req.URL.String()))

		fmt.Printf("\tUpdating SNI ServerName to %s\n", s.Addr(req.URL.Host))
		c.Transport.(*http.Transport).TLSClientConfig.ServerName = req.URL.Host

		fmt.Printf("\tUpdating HTTP Host header to %s\n", s.Addr(req.URL.Host))
		req.Host = req.URL.Host

		// TODO: should re-do DNS checks here cause it can get interesting (try: amazon.com - redirects to www.amazon.com, which is a long CNAME chain)

		return nil
	}

	return c
}

func GetHttpRequest(s output.TtyStyler, b output.Bios, scheme, addr, port, host, path string) (*http.Request, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	addrPort := net.JoinHostPort(addr, port)
	hostPort := net.JoinHostPort(host, port)

	pathParts, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	l7Addr := url.URL{
		Scheme:   scheme,
		Host:     addrPort,
		Path:     pathParts.EscapedPath(),
		RawQuery: pathParts.RawQuery,
		Fragment: pathParts.EscapedFragment(),
	}
	req, err := http.NewRequestWithContext(ctx, "GET", l7Addr.String(), nil)
	b.CheckErr(err)
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
	if port == "443" {
		req.Host = host
	} else {
		req.Host = hostPort
	}

	return req, cancel
}

func CheckTls(s output.TtyStyler, b output.Bios, client *http.Client, req *http.Request) []byte {

	b.Banner("Request")

	fmt.Printf("Beginning request...\n")
	host, port, err := net.SplitHostPort(req.URL.Host)
	b.CheckErr(err)
	systemRemoteIPs, err := net.LookupHost(host) // ie what the system resolver comes up with, as that's what the http client will use, and it includes files and other nsswitch stuff not just what we manually find in DNS
	b.CheckErr(err)
	fmt.Printf("\tTCP addresses: %s\n", s.List(output.ZipHostsPort(systemRemoteIPs, port), s.AddrStyle))
	if req.URL.Scheme == "https" {
		fmt.Printf("\tTLS handshake: SNI ServerName %s\n", s.Addr(client.Transport.(*http.Transport).TLSClientConfig.ServerName))
	}
	fmt.Printf("\tHTTP request: Host %s | %s %s\n", s.Addr(req.Host), s.Verb(req.Method), s.UrlPath(req.URL))

	resp, err := client.Do(req)
	b.CheckErr(err)
	defer resp.Body.Close()

	/* == HTTP == */

	b.Banner("HTTP")

	fmt.Printf("%s", s.Noun(resp.Proto))
	if resp.StatusCode < 400 {
		fmt.Printf(" %s", s.Ok(resp.Status))
	} else if resp.StatusCode < 500 {
		fmt.Printf(" %s", s.Warn(resp.Status))
	} else {
		fmt.Printf(" %s", s.Fail(resp.Status))
	}
	fmt.Printf(" from %s", s.OptionalString(resp.Header.Get("server"), s.NounStyle))
	fmt.Println()

	fmt.Printf("\tHSTS? %s\n", s.YesNo(resp.Header.Get("Strict-Transport-Security") != ""))
	// CORS headers aren't really meaningful cause they'll only be sent if the request includes an Origin header

	fmt.Printf("\tclaimed %s bytes of %s\n", s.Bright(strconv.FormatInt(int64(resp.ContentLength), 10)), s.Noun(resp.Header.Get("content-type")))
	if resp.Uncompressed {
		fmt.Printf("\tcontent was transparently decompressed; length information will not be accurate\n")
	}

	rawBody, err := ioutil.ReadAll(resp.Body)
	b.CheckErr(err)
	fmt.Printf("\tactual %s bytes of body read\n", s.Bright(strconv.FormatInt(int64(len(rawBody)), 10)))

	return rawBody
}
