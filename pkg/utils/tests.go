package utils

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
	"github.com/go-logr/logr"
	"github.com/logrusorgru/aurora/v3"
)

func CheckDns(name string) net.IP {
	ips, err := net.LookupIP(name)
	if ok := CheckWarn(err); !ok {
		return net.IPv4(0, 0, 0, 0)
	}
	if len(ips) > 1 {
		CheckInfo(errors.New("Host resolves to >1 IP, using first"))
	}
	ip := ips[0]
	fmt.Printf("Name %v is %s\n", aurora.Colorize(name, AddrStyle), aurora.Colorize(ip.String(), AddrStyle))

	return ip
}

func CheckRevDns(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if ok := CheckWarn(err); !ok {
		return "<NXDOMAIN>"
	}
	if len(names) > 1 {
		CheckInfo(errors.New("IP resolves to >1 host, using first"))
	}
	revName := names[0]
	fmt.Printf("%s reverses to %s\n", aurora.Colorize(ip.String(), AddrStyle), aurora.Colorize(revName, AddrStyle))

	return revName
}

func GetPlaintextClient(log logr.Logger) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					log.V(1).Info("%sTCP: connection established", "addr", address)

					return nil
				},
			}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			DisableCompression:    true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Printf("\t%s Redirected to %s\n", SInfo, aurora.Colorize(req.URL.String(), AddrStyle))
			return nil
		},
	}

	return c
}
func GetTLSClient(log logr.Logger, sni, caPath, certPath, keyPath string, krb, http11 bool) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					log.V(1).Info("TCP: connection established", "addr", address)

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
					log.Info("Asked for a client certificate")

					/* Load from disk */
					if certPath == "" || keyPath == "" {
						panic(errors.New("Need to provide a path to key and cert"))
					}
					pair, err := tls.LoadX509KeyPair(certPath, keyPath)
					CheckErr(err)

					/* Parse */
					var certs []*x509.Certificate
					for _, bytes := range pair.Certificate {
						cert, err := x509.ParseCertificate(bytes)
						CheckErr(err)
						certs = append(certs, cert)
					}

					/* Print */
					fmt.Println("Presenting client cert chain")
					RenderClientCertChain(certs...)

					/* Hand to http client */
					return &pair, err
				},
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					log.V(1).Info("TLS built-in cert verification finished (no-op in our config)")

					if len(verifiedChains) > 0 {
						panic("first time we've seen this, check it works. Shouldn't see it cause we set InsecureSkipVerify")
						if len(verifiedChains) > 1 {
							panic("multiple chains")
						}
						for _, cert := range verifiedChains[0] {
							fmt.Println(RenderCertBasics(cert))
						}
					}

					return nil
				},
				VerifyConnection: func(cs tls.ConnectionState) error {
					log.V(1).Info("TLS: all cert verification finished")
					Banner("TLS")

					fmt.Printf("%s handshake complete\n", aurora.Colorize(versionName(cs.Version), NounStyle))
					fmt.Printf("\tCypher suite %s\n", aurora.Colorize(tls.CipherSuiteName(cs.CipherSuite), NounStyle))

					// TODO this ^^ is the agreed-upon symmetic scheme? Print the key-exchange also used to get it - DH or ECDH. Already printing the signature scheme (RSA, ECDSA, etc) when we print certs
					fmt.Printf("\tALPN proto %s\n", RenderOptionalString(cs.NegotiatedProtocol, NounStyle))
					fmt.Printf("\tOCSP info stapled to response? %s\n", RenderYesNo(len(cs.OCSPResponse) > 0))
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
						CheckErr(err)

						roots := x509.NewCertPool()
						ok := roots.AppendCertsFromPEM(bytes)
						CheckOk(ok)
						opts.Roots = roots
					}
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}

					chains, err := cs.PeerCertificates[0].Verify(opts)
					if err != nil {
						RenderServingCertChain(&cs.ServerName, nil, cs.PeerCertificates, nil)
						fmt.Println()
					} else {
						for _, chain := range chains {
							RenderServingCertChain(&cs.ServerName, nil, cs.PeerCertificates, chain)
							fmt.Println()
						}
					}

					fmt.Println("\tCert accepted?", RenderYesError(err))
					fmt.Println()

					return nil
				},
			},
			ForceAttemptHTTP2: !http11, // Because we provide our own TLSClientConfig, golang defaults to no ALPN, we have to insist. Note that just setting TLSClientConfig.NextProtos isn't enough; this flag adds upgrade handler functions and other stuff
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Printf("\t%s Redirected to %s\n", SInfo, aurora.Colorize(req.URL.String(), AddrStyle))
			return nil
		},
	}

	if krb {
		c.Transport = &spnego.Transport{NoCanonicalize: true, Transport: *c.Transport.(*http.Transport)}
	}

	return c
}

func GetHttpRequest(log logr.Logger, scheme, addr, port, host, path string) (*http.Request, context.CancelFunc) {

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
	CheckErr(err)
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
	if port == "443" {
		req.Host = host
	} else {
		req.Host = hostPort
	}

	return req, cancel
}

func CheckTls(log logr.Logger, client *http.Client, req *http.Request) []byte {

	fmt.Printf("%s Beginning request...\n", STrying)
	if req.URL.Scheme == "https" {
		fmt.Printf("\tTLS handshake: SNI ServerName %s\n", aurora.Colorize(client.Transport.(*http.Transport).TLSClientConfig.ServerName, AddrStyle))
	}
	fmt.Printf("\tHTTP request: Host %s | %s %s %s\n", aurora.Colorize(req.Host, AddrStyle), aurora.Colorize(req.Method, VerbStyle), aurora.Colorize(req.URL.RequestURI(), AddrStyle), aurora.Colorize(req.URL.EscapedFragment(), AddrStyle)) // TODO render query

	resp, err := client.Do(req)
	CheckErr(err)
	defer resp.Body.Close()

	/* == HTTP == */

	Banner("HTTP")

	fmt.Printf("%s", aurora.Colorize(resp.Proto, NounStyle))
	if resp.StatusCode < 400 {
		fmt.Printf(" %s", aurora.Colorize(resp.Status, OkStyle))
	} else if resp.StatusCode < 500 {
		fmt.Printf(" %s", aurora.Colorize(resp.Status, WarnStyle))
	} else {
		fmt.Printf(" %s", aurora.Colorize(resp.Status, FailStyle))
	}
	fmt.Printf(" from %s", RenderOptionalString(resp.Header.Get("server"), NounStyle))
	fmt.Println()

	fmt.Printf("\tHSTS? %s\n", RenderYesNo(resp.Header.Get("Strict-Transport-Security") != ""))
	// CORS headers aren't really meaningful cause they'll only be sent if the request includes an Origin header

	fmt.Printf("\tclaimed %s bytes of %s\n", aurora.Colorize(strconv.FormatInt(int64(resp.ContentLength), 10), BrightStyle), aurora.Colorize(resp.Header.Get("content-type"), NounStyle))
	if resp.Uncompressed {
		fmt.Printf("\t%s Note: content was transparently decompressed; length information will not be accurate\n")
	}

	rawBody, err := ioutil.ReadAll(resp.Body)
	CheckErr(err)
	fmt.Printf("\tactual %s bytes of body read\n", aurora.Colorize(strconv.FormatInt(int64(len(rawBody)), 10), BrightStyle))

	return rawBody
}
