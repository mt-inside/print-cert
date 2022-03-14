package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	fmt.Printf("Name %v is %s\n", AddrStyle.Render(name), AddrStyle.Render(ip.String()))

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
	fmt.Printf("%s reverses to %s\n", AddrStyle.Render(ip.String()), AddrStyle.Render(revName))

	return revName
}

func GetPlaintextClient(log logr.Logger) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					log.V(1).Info("TCP: established connection with", "addr", address)

					return nil
				},
			}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			DisableCompression:    true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Printf("\t%s Redirected to %s\n", SInfo, AddrStyle.Render(req.URL.String()))
			return nil
		},
	}

	return c
}
func GetTLSClient(log logr.Logger, sni, certPath, keyPath string, krb, http11 bool) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second, // assume this is just the TLS handshake ie tcp handshake is covered bby the dialer
			ResponseHeaderTimeout: 10 * time.Second,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         sni, // SNI for TLS vhosting
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					log.Info("Asked for a client certificate")

					if certPath == "" || keyPath == "" {
						panic(errors.New("Need to provide a path to key and cert"))
					}
					pair, err := tls.LoadX509KeyPair(certPath, keyPath)

					fmt.Println("Presenting client cert chain")
					if err == nil {
						var certs []*x509.Certificate
						for _, bytes := range pair.Certificate {
							cert, _ := x509.ParseCertificate(bytes)
							certs = append(certs, cert)
						}

						fmt.Println(RenderCertBasics(certs[0]))
						fmt.Printf("Cert chain\n")
						for _, cert := range certs[1:] {
							fmt.Println(RenderCertBasics(cert))
						}
						fmt.Printf("\t\tissuer: %s\n", AddrStyle.Render(renderIssuer(certs[len(certs)-1])))
					}

					return &pair, err
				},
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					log.V(1).Info("TLS built-in cert verification finished")

					return nil // can do extra cert verification and reject
				},
				VerifyConnection: func(cs tls.ConnectionState) error {
					log.V(1).Info("TLS: all cert verification finished")

					return nil // can inspect all connection and TLS info and reject
				},
			},
			ForceAttemptHTTP2: !http11, // Because we provide our own TLSClientConfig, golang defaults to no ALPN, we have to insist. Note that just setting TLSClientConfig.NextProtos isn't enough; this flag adds upgrade handler functions and other stuff
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Printf("\t%s Redirected to %s\n", SInfo, AddrStyle.Render(req.URL.String()))
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

	host := req.Host

	resp, err := client.Do(req)
	CheckErr(err)
	defer resp.Body.Close()

	/* == TLS == */

	if req.URL.Scheme == "https" {
		fmt.Printf("%s TLS handshake with %s (SNI ServerName %s)...\n", STrying, AddrStyle.Render(req.URL.Host), AddrStyle.Render(client.Transport.(*http.Transport).TLSClientConfig.ServerName))

		fmt.Println()

		cs := resp.TLS
		fmt.Printf("Handshake complete. %s; ALPN proto %s\n", BrightStyle.Render(versionName(cs.Version)), BrightStyle.Render(RenderOptionalString(cs.NegotiatedProtocol)))
		fmt.Printf("\tTLS cypher suite %s\n", tls.CipherSuiteName(cs.CipherSuite))
		// TODO this ^^ is the agreed-upon symmetic scheme? Print the key-exchange also used to get it - DH or ECDH. Already printing the signature scheme (RSA, ECDSA, etc) when we print certs

		/* Cert chain */

		fmt.Println()
		servingCert := cs.PeerCertificates[0]
		fmt.Println("Serving Cert")
		fmt.Println(RenderCertBasics(servingCert))
		fmt.Printf("\tDNS SANs %s\n", RenderList(servingCert.DNSNames))
		fmt.Printf("\tIP SANs %s\n", RenderList(ips2str(servingCert.IPAddresses)))

		// TODO: take the subject too, parse it, check the CN value too
		// TODO if it's an IP, check against IP SANs instead
		fmt.Printf("\tGiven host %s in SANs? %s\n", host, YesNo(nameInCert(host, servingCert.Subject, servingCert.DNSNames)))

		fmt.Printf("\tHSTS? %s\n", YesNo(resp.Header.Get("Strict-Transport-Security") != ""))

		fmt.Printf("\tOCSP info stapled to response? %s\n", YesNo(len(cs.OCSPResponse) > 0))

		fmt.Println()

		fmt.Printf("Presented cert chain\n")
		// TODO render first and subsequent certs differently (don't care about SANs on signers)
		for _, cert := range cs.PeerCertificates[1:] {
			fmt.Println(RenderCertBasics(cert))
		}
		fmt.Printf("\t\tissuer: %s\n", AddrStyle.Render(renderIssuer(cs.PeerCertificates[len(cs.PeerCertificates)-1])))

		if len(cs.VerifiedChains) > 0 {
			// TODO: add cs.VerifidChains, which adds the certs from the local store that the presented certs (above) were verified against
			panic("first time we've seen this, check it works")
			if len(cs.VerifiedChains) > 1 {
				panic("multiple chains")
			}
			for _, cert := range cs.VerifiedChains[0] {
				fmt.Println(RenderCertBasics(cert))
			}
		}
	}

	/* == HTTP == */

	Banner("HTTP")

	fmt.Printf("%s HTTP request (Host %s) %s %s %s...\n", STrying, AddrStyle.Render(req.Host), AddrStyle.Render(req.Method), AddrStyle.Render(req.URL.RequestURI()), AddrStyle.Render(req.URL.EscapedFragment()))

	fmt.Printf("%s", BrightStyle.Render(resp.Proto))
	if resp.StatusCode < 400 {
		fmt.Printf(" %s", OkStyle.Render(resp.Status))
	} else if resp.StatusCode < 500 {
		fmt.Printf(" %s", WarnStyle.Render(resp.Status))
	} else {
		fmt.Printf(" %s", FailStyle.Render(resp.Status))
	}
	fmt.Printf(" from server %s", RenderOptionalString(resp.Header.Get("server")))
	fmt.Println()

	// CORS headers aren't really meaningful cause they'll only be sent if the request includes an Origin header

	fmt.Printf("\tclaimed %s bytes of %s\n", BrightStyle.Render(strconv.FormatInt(int64(resp.ContentLength), 10)), BrightStyle.Render(resp.Header.Get("content-type")))
	if resp.Uncompressed {
		fmt.Printf("\t%s Note: content was transparently decompressed; length information will not be accurate\n")
	}

	rawBody, err := ioutil.ReadAll(resp.Body)
	CheckErr(err)
	fmt.Printf("\tactual %s bytes of body read\n", BrightStyle.Render(strconv.FormatInt(int64(len(rawBody)), 10)))

	return rawBody
}

func renderIssuer(cert *x509.Certificate) string {
	if cert.Issuer.String() == cert.Subject.String() {
		return "<self-signed>"
	}
	return cert.Issuer.String()
}

func ips2str(ips []net.IP) []string {
	ipStrs := []string{}
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	return ipStrs
}

//TODO: need to understand wildcards etc. Defer to the library to do this check
func nameInCert(name string, subj pkix.Name, sans []string) bool {
	if name == subj.CommonName {
		return true
	}
	for _, san := range sans {
		if san == name {
			return true
		}
	}
	return false
}

// TODO will be in stdlib anytime now... https://go-review.googlesource.com/c/go/+/321733/, https://github.com/golang/go/issues/46308
func versionName(tlsVersion uint16) string {
	switch tlsVersion {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		panic(errors.New("Unknown TLS version"))
	}
}
