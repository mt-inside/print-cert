package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/MarshallWace/go-spnego"
	"github.com/mt-inside/http-log/pkg/output"
)

/* TODO:
* - single, configurable timeout for all network operations
 */

func getCheckRedirect(s output.TtyStyler, b output.Bios, c *http.Client) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		b.Banner("Redirect")

		fmt.Printf("Redirected to %s\n", s.Addr(req.URL.String()))

		b.Trace("Updating TLS ClientHello", "ServerName", req.URL.Host)
		getUnderlyingHttpTransport(c).TLSClientConfig.ServerName = req.URL.Host

		b.Trace("Updating HTTP request", "Host", req.URL.Host)
		req.Host = req.URL.Host

		DNSInfo(s, b, req.URL.Host)

		fmt.Println()

		printRequestPreamble(s, b, c, req)

		return nil
	}
}

// GetPlaintextClient returns an HTTP Client for calling non-TLS endpoints.
// It prints lots of info along the way.
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

				fmt.Printf("Connected %s -> %s\n", s.Addr(conn.LocalAddr().String()), s.Addr(conn.RemoteAddr().String()))

				return conn, err
			},
			ResponseHeaderTimeout: 5 * time.Second,
			DisableCompression:    true,
		},
	}

	c.CheckRedirect = getCheckRedirect(s, b, c)

	return c
}

// GetTLSClient returns an HTTP Client for calling TLS-enabled endpoints.
// It prints lots of info along the way.
func GetTLSClient(s output.TtyStyler, b output.Bios, sni, caPath, certPath, keyPath string, krb, http11 bool) *http.Client {

	// Always make a krb transport, becuase if we make a plain HTTP one and try to wrap it later, we have to copy the bytes (because spnego.Transport embeds http.Transport) and that copies a sync.Mutex.
	tr := &spnego.Transport{
		NoCanonicalize: true,
		Transport: http.Transport{
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

				fmt.Printf("Connected %s -> %s\n", s.Addr(conn.LocalAddr().String()), s.Addr(conn.RemoteAddr().String()))

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

	// Assuming we don't want krb, just point to the non-spnego parts of the struct
	c := &http.Client{
		Transport: &tr.Transport,
	}
	if krb {
		c = &http.Client{Transport: tr}
	}

	// Really ugly that this can't be set in the literal (so that it can reference and reach into the client and mutate it)
	c.CheckRedirect = getCheckRedirect(s, b, c)

	return c
}

// GetHTTPRequest returns an HTTP Request that can be used to call endpoints under test.
func GetHTTPRequest(s output.TtyStyler, b output.Bios, scheme, addr, port, host, path string) (*http.Request, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	addrPort := net.JoinHostPort(addr, port)
	hostPort := net.JoinHostPort(host, port)

	pathParts, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	l7Addr := url.URL{
		Scheme:   scheme,
		Host:     addrPort, // could leave off 80 or 443 but not an error to include them
		Path:     pathParts.EscapedPath(),
		RawQuery: pathParts.RawQuery,
		Fragment: pathParts.EscapedFragment(),
	}
	req, err := http.NewRequestWithContext(ctx, "GET", l7Addr.String(), nil)
	b.CheckErr(err)
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
	if port == "80" || port == "443" {
		req.Host = host // my reading of the spec is that it's not an error to include 80 or 443 but I can imagine some servers getting confused
	} else {
		req.Host = hostPort
	}

	return req, cancel
}

func printRequestPreamble(s output.TtyStyler, b output.Bios, client *http.Client, req *http.Request) {
	fmt.Printf("Beginning request...\n")
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
		switch req.URL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	systemRemoteIPs, err := net.LookupHost(host) // ie what the system resolver comes up with, as that's what the http client will use, and it includes files and other nsswitch stuff not just what we manually find in DNS
	b.CheckErr(err)
	fmt.Printf("\tTCP addresses: %s (from system/golang resolver)\n", s.List(output.ZipHostsPort(systemRemoteIPs, port), s.AddrStyle))
	if req.URL.Scheme == "https" {
		fmt.Printf("\tTLS handshake: SNI ServerName %s\n", s.Addr(getUnderlyingHttpTransport(client).TLSClientConfig.ServerName))
	}
	fmt.Printf("\tHTTP request: Host %s | %s %s\n", s.Addr(req.Host), s.Verb(req.Method), s.UrlPath(req.URL))
}

// CheckTLS sends the given request using the given client.
// It prints information about what's returned.
func CheckTLS(s output.TtyStyler, b output.Bios, client *http.Client, req *http.Request) []byte {

	b.Banner("Request")

	printRequestPreamble(s, b, client, req)

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

func getUnderlyingHttpTransport(client *http.Client) *http.Transport {
	switch c := client.Transport.(type) {
	case *http.Transport:
		return c
	case *spnego.Transport:
		return &c.Transport
	default:
		panic("Bottom")
	}
}
