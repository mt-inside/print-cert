package state

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mt-inside/go-usvc"

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

type PrintOpts struct {
	// TODO drop Print
	// TODO: make an enum
	// TODO: Meta => Http
	PrintDns, PrintDnsFull   bool
	PrintTcp, PrintTcpFull   bool
	PrintTls, PrintTlsFull   bool
	PrintMeta, PrintMetaFull bool
	PrintBody, PrintBodyFull bool
	Trace, Requests          bool
}

func (pO *PrintOpts) Zero() bool {
	return !(pO.PrintDns || pO.PrintDnsFull ||
		pO.PrintTcp || pO.PrintTcpFull ||
		pO.PrintTls || pO.PrintTlsFull ||
		pO.PrintMeta || pO.PrintMetaFull ||
		pO.PrintBody || pO.PrintBodyFull)
}
func (pO *PrintOpts) SetDefaults() {
	pO.PrintDns = true
	pO.PrintTcp = true
	pO.PrintTls = true
	pO.PrintMeta = true
	pO.PrintBody = true
}

// TODO: some/all of these fields to be type Event{timestamp, value: T}
// - actually, just for initiate and complete times (maybe a timing type, with a method for duration?)
// - print init time with request info
// - print complete time with summary
// - print duration for section somewhere
type ResponseData struct {
	DnsSystemResolves []string

	TransportConnNo     uint
	TransportDialTime   time.Time
	TransportConnTime   time.Time
	TransportRemoteAddr net.Addr
	TransportLocalAddr  net.Addr

	TlsClientCertRequest bool

	TlsServerCerts []*x509.Certificate

	TlsAgreedTime        *time.Time
	TlsAgreedVersion     uint16
	TlsAgreedCipherSuite uint16
	TlsServerName        string
	TlsAgreedALPN        string
	TlsOCSPStapled       bool

	HttpProto         string
	HttpStatusCode    int
	HttpStatusMessage string
	HttpHeaders       http.Header
	HttpContentLength int64
	HttpCompressed    bool

	BodyBytes []byte

	RedirectTarget *url.URL
}

func NewResponseData() *ResponseData {
	return &ResponseData{}
}

func (pD *ResponseData) Print(
	s output.TtyStyler, b output.Bios,
	requestData *RequestData,
	rtData *RoundTripData,
	pO *PrintOpts,
) {
	// TODO: make work for aborted responses. Mostly about how we call it
	// - work out how to test an abort in each section (and document, and script if possible)
	//   - no internet at all (ie no routes, no local IP to initiate connections)
	//   - internet up but no packets flow (eg all sections are conn timeout)
	//   - DNS: dns server that is port closed / returns garbage
	//   - TCP: port closed
	//   - TLS: abort due to can't handshake - something (httplog) offering ancient ciphers
	//   - HTTP Head: garbage / close pipe mid-header
	//   - HTTP body: close pipe mid-body
	// - probably: a "completed" bool for each section (either print its values, or "not available due to abort")

	if pO.PrintDns || pO.PrintDnsFull {
		b.Banner(fmt.Sprintf("DNS - system resolver (%s)", requestData.DnsSystemResolver))
		fmt.Printf("TCP addresses: %s\n", s.List(pD.DnsSystemResolves, s.AddrStyle))
	}

	if pO.PrintTcp || pO.PrintTcpFull {
		b.Banner("TCP")
		fmt.Printf("Connected %s -> %s\n", s.Addr(pD.TransportLocalAddr.String()), s.Addr(pD.TransportRemoteAddr.String()))
	}

	if rtData.TlsEnabled && (pO.PrintTls || pO.PrintTlsFull) {
		b.Banner("TLS")

		if pO.Requests {
			fmt.Printf("Request: ")
			if rtData.TlsServerName != "" {
				fmt.Printf("SNI ServerName %s\n", s.Addr(rtData.TlsServerName))
			} else {
				// If an explicit --sni is given which is invalid, we'll already have error'd out
				b.PrintWarn("Not sending SNI ServerName. Either provide one explicity with --sni, or give a --host or target that's a valid SNI.")
			}
			fmt.Println()
		}

		if pD.TlsClientCertRequest {
			if requestData.TlsClientPair == nil {
				b.PrintWarn("Server asked for a client cert but none configured (-c/-k). Not presenting a cert, this might cause the server to abort the handshake.")
			} else {
				//need a deamonData with these thigns in (reused)
				fmt.Println("Presenting client cert chain")
				if pO.PrintTlsFull {
					s.ClientCertChain(codec.ChainFromCertificate(requestData.TlsClientPair))
				}
			}
			fmt.Println()
		}

		/* Print cert chain */

		fmt.Println("Received serving cert chain")

		// This verification would normally happen automatically, and we'd be given these chains as args to VerifyPeerCertificate()
		// However a failed validation would cause client.Do() to return early with that error, and we want to carry on
		// This we set InsecureSkipVerify to stop the early bail out, and basically recreate the default checks ourselves
		// If caCert is nil ServingCertChainVerified() will use system roots to verify
		// The name given is verified against the cert.
		s.VerifiedServingCertChain(pD.TlsServerCerts, requestData.TlsServingCA, rtData.TlsValidateName, pO.PrintTlsFull)

		/* TLS agreement summary */

		// TODO: useful TLS info checklist
		// - [x] HSTS
		// - [x] OCSP pinning
		// - [ ] HPKP: obsolete, but may as well print it if it's present (not print anything when it's not)
		// - [ ] Certificate Transparency: understand it, do stuff. Is a header? Is also stuff in the OCSP bundle?
		// - [ ] DNS CAA records: should investigate and print in the TLS section
		// CORS headers aren't really meaningful cause they'll only be sent if the request includes an Origin header
		fmt.Printf("%s handshake complete with %s\n", s.Noun(output.TLSVersionName(pD.TlsAgreedVersion)), s.Addr(pD.TlsServerName))
		fmt.Printf("\tSymmetric cypher suite %s\n", s.Noun(tls.CipherSuiteName(pD.TlsAgreedCipherSuite)))
		fmt.Printf("\tALPN proto %s\n", s.OptionalString(pD.TlsAgreedALPN, s.NounStyle))
		fmt.Printf("\tOCSP info stapled to response? %s\n", s.YesNo(pD.TlsOCSPStapled))
		fmt.Printf("\tHSTS? %s\n", s.YesNo(pD.HttpHeaders.Get("Strict-Transport-Security") != ""))
		fmt.Println()

	}

	if pO.PrintMeta || pO.PrintMetaFull {
		b.Banner("HTTP")

		if pO.Requests {
			fmt.Printf("Request: Host %s %s %s\n", s.Addr(rtData.HttpHost), s.Verb(requestData.HttpMethod), s.UrlPath(rtData.HttpPath))
			if requestData.AuthBearerToken != "" {
				if token, err := codec.ParseJWTNoSignature(requestData.AuthBearerToken); err == nil {
					fmt.Printf("\tPresented bearer token: ")
					s.JWTSummary(token)
					fmt.Println()
				} else {
					panic(err)
				}
			}
			fmt.Println()
		}

		fmt.Printf("%s", s.Noun(pD.HttpProto))
		if pD.HttpStatusCode < 400 {
			fmt.Printf(" %s", s.Ok(pD.HttpStatusMessage))
		} else if pD.HttpStatusCode < 500 {
			fmt.Printf(" %s", s.Warn(pD.HttpStatusMessage))
		} else {
			fmt.Printf(" %s", s.Fail(pD.HttpStatusMessage))
		}
		fmt.Printf(" from %s", s.OptionalString(pD.HttpHeaders.Get("server"), s.NounStyle))
		fmt.Println()

		if !pO.PrintMetaFull {
			fmt.Printf("\tclaimed %s bytes of %s\n", s.Bright(strconv.FormatInt(int64(pD.HttpContentLength), 10)), s.Noun(pD.HttpHeaders.Get("content-type")))
			if pD.HttpCompressed {
				fmt.Printf("\tcontent was transparently decompressed; length information will not be accurate\n")
			}
		} else {
			// TODO: use new and improved outputting for this from http-log
			for k, vs := range pD.HttpHeaders {
				fmt.Printf("\t%s = %v\n", s.Addr(k), s.Noun(strings.Join(vs, ",")))
			}
		}
	}

	if pO.PrintBody || pO.PrintBodyFull {
		b.Banner("Body")
		bodyLen := len(pD.BodyBytes)

		fmt.Printf("%s bytes of body actually read\n", s.Bright(strconv.FormatInt(int64(bodyLen), 10)))
		fmt.Printf("Valid utf-8? %s\n", s.YesNo(utf8.Valid(pD.BodyBytes)))
		fmt.Println()

		printLen := usvc.MinInt(bodyLen, 72)
		if pO.PrintBodyFull {
			printLen = bodyLen
		}

		// TODO should share a print-body with all the other places that do this, which should check it's UTF, print that status, deal with elision, etc
		fmt.Printf("%v", string(pD.BodyBytes[0:printLen])) // assumes utf8
		if bodyLen > printLen {
			fmt.Printf("<%d bytes elided>", bodyLen-printLen)
		}
		if bodyLen > 0 {
			fmt.Println()
		}
	}

	if pD.RedirectTarget != nil {
		b.Banner("Redirect")

		fmt.Printf("Redirected to %s\n", s.Addr(pD.RedirectTarget.String()))
	}
}
