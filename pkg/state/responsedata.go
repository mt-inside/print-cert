package state

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mt-inside/go-usvc"

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

// TODO: some/all of these fields to be type Event{timestamp, value: T}
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
	TlsAgreedALPN        string
	TlsOCSPStapled       bool

	HttpProto         string
	HttpStatusCode    int
	HttpStatusMessage string
	HttpHeaders       http.Header
	HttpContentLength int64
	HttpCompressed    bool

	BodyBytes []byte
}

func NewResponseData() *ResponseData {
	return &ResponseData{}
}

func (pD *ResponseData) Print(
	s output.TtyStyler, b output.Bios,
	requestData *RequestData,
	printDns, printDnsFull,
	printTls, printTlsFull,
	printMeta, printMetaFull,
	printBody, printBodyFull bool,
) {
	if printDns || printDnsFull {
		b.Banner(fmt.Sprintf("DNS - system resolver (%s)", requestData.DnsSystemResolver))
		fmt.Printf("TCP addresses: %s\n", s.List(pD.DnsSystemResolves, s.AddrStyle))
	}

	// TODO: make transport printing optional. What are http-log's Transport and Tls short flags?
	b.Banner("TCP")
	fmt.Printf("Connected %s -> %s\n", s.Addr(pD.TransportLocalAddr.String()), s.Addr(pD.TransportRemoteAddr.String()))

	if requestData.TlsEnabled && (printTls || printTlsFull) {
		b.Banner("TLS")

		fmt.Printf("Request: ")
		if requestData.TlsServerName != "" {
			fmt.Printf("SNI ServerName %s\n", s.Addr(requestData.TlsServerName))
		} else {
			fmt.Printf("Not sending SNI ServerName. Set one with --sni, or will fall back to an explicit --host.\n")
		}
		fmt.Println()

		if pD.TlsClientCertRequest {
			if requestData.TlsClientPair == nil {
				b.PrintWarn("Server asked for a client cert but none configured (-c/-k). Not presenting a cert, this might cause the server to abort the handshake.")
			} else {
				//need a deamonData with these thigns in (reused)
				fmt.Println("Presenting client cert chain")
				if printTlsFull {
					s.ClientCertChain(codec.ChainFromCertificate(requestData.TlsClientPair), nil)
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
		s.ServingCertChainVerifyNameSignature(pD.TlsServerCerts, requestData.TlsValidateName, requestData.TlsServingCA, printTlsFull)

		/* TLS agreement summary */

		// TODO: useful TLS info checklist
		// - [x] HSTS
		// - [x] OCSP pinning
		// - [ ] HPKP: obsolete, but may as well print it if it's present (not print anything when it's not)
		// - [ ] Certificate Transparency: understand it, do stuff. Is a header? Is also stuff in the OCSP bundle?
		// - [ ] DNS CAA records: should investigate and print in the TLS section
		// CORS headers aren't really meaningful cause they'll only be sent if the request includes an Origin header
		fmt.Printf("%s handshake complete\n", s.Noun(output.TLSVersionName(pD.TlsAgreedVersion)))
		fmt.Printf("\tSymmetric cypher suite %s\n", s.Noun(tls.CipherSuiteName(pD.TlsAgreedCipherSuite)))
		fmt.Printf("\tALPN proto %s\n", s.OptionalString(pD.TlsAgreedALPN, s.NounStyle))
		fmt.Printf("\tOCSP info stapled to response? %s\n", s.YesNo(pD.TlsOCSPStapled))
		fmt.Printf("\tHSTS? %s\n", s.YesNo(pD.HttpHeaders.Get("Strict-Transport-Security") != ""))
		fmt.Println()

	}

	if printMeta || printMetaFull {
		b.Banner("HTTP")

		fmt.Printf("Request: Host %s %s %s\n", s.Addr(requestData.HttpHost), s.Verb(requestData.HttpMethod), s.UrlPath(requestData.HttpPath))
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

		if !printMetaFull {

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

	if printBody || printBodyFull {
		b.Banner("HTTP Body")
		bodyLen := len(pD.BodyBytes)

		fmt.Printf("%s bytes of body actually read\n", s.Bright(strconv.FormatInt(int64(bodyLen), 10)))
		fmt.Printf("Valid utf-8? %s\n", s.YesNo(utf8.Valid(pD.BodyBytes)))
		fmt.Println()

		printLen := usvc.MinInt(bodyLen, 72)
		if printBodyFull {
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

}