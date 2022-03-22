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

// TODO print local socket addr - can't find it on the RawConn or the Dialer (localaddr remains nil even after connection)

/* Testing:
* - www.wikipedia.org has CNAME
* - cloudflare.net is DNSSEC
 */
func CheckDNS2(s output.TtyStyler, b output.Bios, name string) net.IP {

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	b.CheckErr(err)

	server := net.JoinHostPort(dnsConfig.Servers[0], dnsConfig.Port) // TODO: what do with multiple servers? Think we're meant to try them in order until one suceeds?

	b.PrintInfo(fmt.Sprintf("DNS Server: %s", s.Addr(server)))

	names := dnsConfig.NameList(name)

	c := dns.Client{
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	}

	var in *dns.Msg
	for _, name := range names {
		b.PrintInfo(fmt.Sprintf("Trying FQDN on search path: %s", s.Addr(name)))

		m := new(dns.Msg)
		// By default this sets the flag to ask whatever server is configured to recurse for us. We could manually recurse, either continually against the system server (thus using its cache), or from the root servers down. However both are a huge amount of work for no gain
		m.SetQuestion(name, dns.TypeA)

		var err error
		in, _, err = c.Exchange(m, server)
		b.CheckErr(err)

		// TODO: answers coming back non-authoritative - this is because we're asking a local recursive resolver, not hitting the actual orgs' servers?

		if len(in.Answer) > 0 {
			break
		}
	}

	if len(in.Answer) == 0 {
		b.PrintErr("NXDOMAIN")
	}

	printCnameChain(s, in.Question[0].Name, in)

	checkDnssec(s, b, in.Question[0].Name)

	return nil // FIXME
}

func checkDnssec(s output.TtyStyler, b output.Bios, name string) {
	/* Validate DNSSEC. Options:
	 * - implement DNSSEC validation manually (using the dns library and doing all the RRSIG, DNSKEY, DS queries right up to the root). This is a massive amount of work
	 * - use this goresolver library to do that for us (but don't use it for the main queries cause we want more control and visbility)
	 * - use the system resolver to do it (local stub / router / ISP / whatever) - set the EDNS0 flag in the question and see if the right flag is in the answer
	 *
	 * Choice: 2 - goresolver is known to do it properly (recursive resolvers are known to *strip* DNSSEC-related records, let alone not validate them properly).
	 */

	resolver, err := goresolver.NewResolver("/etc/resolv.conf")
	b.CheckErr(err)

	_, err = resolver.StrictNSQuery(name, dns.TypeA)

	fmt.Printf("DNSSEC? %s\n", s.YesError(err))
}

func printCnameChain(s output.TtyStyler, question string, resp *dns.Msg) {

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
	for _, ans := range resp.Answer {
		switch t := ans.(type) {
		case *dns.CNAME:
			cnames[t.Hdr.Name] = t.Target
		case *dns.A:
			as = append(as, t.A)
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

	// Authoritative means that the server you're talking to *hosts* that zone - honestly unlikely as you're probably talking to a local stub resolver, or a caching resolver on a home router / ISP.
	fmt.Printf(" (ttl remaining %s, authoritative? %s)\n",
		time.Duration(resp.Answer[0].Header().Ttl)*time.Second,
		s.YesInfo(resp.Authoritative),
	)
}

func CheckDns(s output.TtyStyler, b output.Bios, name string) net.IP {
	// TODO use manual DNS code (means parsing resolv.conf, copy code from system resolver to own file to vendor it) to
	// - show all CNAMEs
	// - show all the search domains tried (verbose mode)
	// - which one worked, thus FQDN
	// - DNSSEC?
	// - DANE (replacement), etc?
	// TODO use the result of this routine as the socket connection address (ie what does in the URL's Host - always set http host even if not overridden)
	ips, err := net.LookupIP(name)
	if ok := b.CheckWarn(err); !ok {
		return net.IPv4(0, 0, 0, 0)
	}
	if len(ips) > 1 {
		b.CheckInfo(errors.New("Host resolves to >1 IP"))
	}
	fmt.Printf("%s resolves to %s\n", s.Addr(name), s.List(output.IPs2Strings(ips), s.AddrStyle))

	//TODO: work out what to do here? Return them all, the reverse them all? Might diverge?
	return ips[0]
}

func CheckRevDns(s output.TtyStyler, b output.Bios, ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if ok := b.CheckWarn(err); !ok {
		return "<NXDOMAIN>"
	}
	if len(names) > 1 {
		b.CheckInfo(errors.New("IP resolves to >1 host"))
	}
	fmt.Printf("%s reverses to %s\n", s.Addr(ip.String()), s.List(names, s.AddrStyle))

	return names[0]
}

func CheckDnsConsistent(s output.TtyStyler, b output.Bios, orig string, rev string) {
	if rev != orig {
		fmt.Printf("\t%s dns inconsistency: %s != %s\n", s.Warn("Warning"), s.Addr(orig), s.Addr(rev))
	}
}

func GetPlaintextClient(s output.TtyStyler, b output.Bios) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control: func(network, address string, rawConn syscall.RawConn) error {

					b.Banner("TCP")
					fmt.Println("Stream established with", s.Addr(address))

					return nil
				},
			}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			DisableCompression:    true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Printf("\tRedirected to %s\n", s.Addr(req.URL.String()))
			return nil
		},
	}

	return c
}
func GetTLSClient(s output.TtyStyler, b output.Bios, sni, caPath, certPath, keyPath string, krb, http11 bool) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control: func(network, address string, rawConn syscall.RawConn) error {

					b.Banner("TCP")
					fmt.Println("Stream established with", s.Addr(address))

					return nil
				},
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second, // assume this is just the TLS handshake ie tcp handshake is covered bby the dialer
			ResponseHeaderTimeout: 10 * time.Second,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // deliberate, qv
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         sni, // SNI for TLS vhosting
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					b.Trace("Asked for a TLS client certificate")

					/* Load from disk */
					if certPath == "" || keyPath == "" {
						panic(errors.New("Need to provide a path to key and cert"))
					}
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
