package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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

// TODO does single-ip need this, or can it just use CheckTls2?
func CheckTls(l4Addr string, host string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host, // SNI for TLS vhosting
		},
		TLSHandshakeTimeout:   1 * time.Second, // assume this includes TCP handshake
		ResponseHeaderTimeout: 5 * time.Second,
	}
	client := &http.Client{Transport: tr}

	fmt.Printf("%s TLS handshake with %s (SNI ServerName %s)...\n", STrying, AddrStyle.Render(l4Addr), AddrStyle.Render(host))
	// TODO use context
	resp, err := client.Get("https://" + l4Addr) // TODO construct a URL object
	CheckErr(err)
	defer resp.Body.Close()

	cs := resp.TLS
	fmt.Printf("%s TLS handshake with %s. TLS version %s; ALPN proto %s\n", SOk, AddrStyle.Render(l4Addr), versionName(cs.Version), cs.NegotiatedProtocol)
	fmt.Printf("\t%s TLS cypher suite %s\n", SInfo, tls.CipherSuiteName(cs.CipherSuite))

	/* Cert chain */

	servingCert := cs.PeerCertificates[0]
	fmt.Printf("Serving Cert [%s -> %s] %s subj %s (iss %s %s) ca %t\n",
		TimeStyle.Render(servingCert.NotBefore.Format(TimeFmt)), TimeStyle.Render(servingCert.NotAfter.Format(TimeFmt)),
		servingCert.PublicKeyAlgorithm, AddrStyle.Render(servingCert.Subject.String()),
		AddrStyle.Render(renderIssuer(servingCert)), servingCert.SignatureAlgorithm,
		servingCert.IsCA,
	)
	fmt.Printf("\tSANs: DNS %s, IPs %s\n",
		AddrStyle.Render(strings.Join(servingCert.DNSNames, ",")), AddrStyle.Render(strings.Join(ips2str(servingCert.IPAddresses), ",")),
	)
	if !nameInSans(host, servingCert.DNSNames) { // TODO if it's an IP, check against IP SANs instead
		fmt.Printf("\t%s given name %s not in SANs\n", SWarning, host)
	}

	fmt.Printf("Cert chain\n")
	// TODO render first and subsequent certs differently (don't care about SANs on signers)
	for _, cert := range cs.PeerCertificates[1:] {
		fmt.Printf("\tCert [%s -> %s] %s subj %s (iss %s %s) ca %t\n",
			TimeStyle.Render(cert.NotBefore.Format(TimeFmt)), TimeStyle.Render(cert.NotAfter.Format(TimeFmt)),
			cert.PublicKeyAlgorithm, AddrStyle.Render(cert.Subject.String()),
			AddrStyle.Render(renderIssuer(cert)), cert.SignatureAlgorithm,
			cert.IsCA,
		)
	}
}

func CheckTls2(l4Addr string, host string) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host, // SNI for TLS vhosting
			},
			ForceAttemptHTTP2:     true,            // Because we provide our own TLSClientConfig, golang defaults to no ALPN, we have to insist. Note that just setting TLSClientConfig.NextProtos isn't enough; this flag adds upgrade handler functions and other stuff
			TLSHandshakeTimeout:   1 * time.Second, // assume this includes TCP handshake
			ResponseHeaderTimeout: 5 * time.Second,
			DisableCompression:    true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Printf("\t%s Redirected to %s\n", SInfo, AddrStyle.Render(req.URL.String()))
			return nil
		},
	}

	fmt.Printf("%s TLS handshake with %s (SNI ServerName %s, HTTP Host %s)...\n", STrying, AddrStyle.Render(l4Addr), AddrStyle.Render(host), AddrStyle.Render(l4Addr))
	// TODO: not negoiating h2, looks like its sending no ALPN (and if we manually do it barfs on a binary response with i think is h2 when it's only expecting h1.1). Use go/x/net/http2 to do http2
	l7Addr := url.URL{
		Scheme: "https",
		Host:   l4Addr,
		Path:   "/",
	}
	req, err := http.NewRequest("GET", l7Addr.String(), nil)
	CheckErr(err)
	req.Host = l4Addr
	resp, err := client.Do(req)
	CheckErr(err)
	defer resp.Body.Close()

	fmt.Println()

	cs := resp.TLS
	fmt.Printf("Handshake complete. %s; ALPN proto %s\n", BrightStyle.Render(versionName(cs.Version)), BrightStyle.Render(RenderOptionalString(cs.NegotiatedProtocol)))
	fmt.Printf("\tTLS cypher suite %s\n", tls.CipherSuiteName(cs.CipherSuite))

	/* Cert chain */

	fmt.Println()
	servingCert := cs.PeerCertificates[0]
	fmt.Println("Serving Cert")
	fmt.Println(RenderCertBasics(servingCert))
	fmt.Printf("\tDNS SANs %s\n", RenderList(servingCert.DNSNames))
	fmt.Printf("\tIP SANs %s\n", RenderList(ips2str(servingCert.IPAddresses)))

	fmt.Printf("\tGiven host %s in SANs? %s\n", host, YesNo(nameInSans(host, servingCert.DNSNames))) // TODO if it's an IP, check against IP SANs instead

	fmt.Printf("\tHSTS? %s\n", YesNo(resp.Header.Get("Strict-Transport-Security") != ""))

	fmt.Printf("\tOCSP info stapled to response? %s\n", YesNo(len(cs.OCSPResponse) > 0))

	fmt.Println()

	fmt.Printf("Cert chain\n")
	// TODO render first and subsequent certs differently (don't care about SANs on signers)
	for _, cert := range cs.PeerCertificates[1:] {
		fmt.Println(RenderCertBasics(cert))
	}
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

	fmt.Println()

	fmt.Printf("%s", BrightStyle.Render(resp.Proto))
	if resp.StatusCode < 400 {
		fmt.Printf(" %s\n", OkStyle.Render(resp.Status))
	} else if resp.StatusCode < 500 {
		fmt.Printf(" %s\n", WarnStyle.Render(resp.Status))
	} else {
		fmt.Printf(" %s\n", FailStyle.Render(resp.Status))
	}

	// CORS headers aren't really meaningful cause they'll only be sent if the request includes an Origin header

	fmt.Printf("\t%d bytes of %s from %s\n", resp.ContentLength, BrightStyle.Render(resp.Header.Get("content-type")), BrightStyle.Render(resp.Header.Get("server")))
	if resp.Uncompressed {
		fmt.Printf("\t%s Note: content was transparently decompressed; length information will not be accurate\n")
	}

	rawBody, err := ioutil.ReadAll(resp.Body)
	CheckErr(err)
	fmt.Printf("\t%s bytes actual body read\n", BrightStyle.Render(strconv.FormatInt(int64(len(rawBody)), 10)))
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

func nameInSans(name string, sans []string) bool {
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
