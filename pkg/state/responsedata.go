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

	"github.com/spf13/viper"

	"github.com/mt-inside/go-usvc"

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

type PrintOpts struct {
	Dns, DnsFull    bool
	Tcp, TcpFull    bool
	Tls, TlsFull    bool
	Http, HttpFull  bool
	Body, BodyFull  bool
	Trace, Requests bool
	Timestamps      output.TimestampType
}

func PrintOptsFromViper() PrintOpts {
	var ts output.TimestampType
	switch viper.GetString("timestamps") {
	case "none":
		ts = output.TimestampNone
	case "abs":
		ts = output.TimestampAbsolute
	case "rel":
		ts = output.TimestampRelative
	default:
		panic("Unknown timestamp option (input to this function should be sanitised)")
	}

	pO := &PrintOpts{
		Dns: viper.GetBool("dns"), DnsFull: viper.GetBool("dns-full"),
		Tcp: viper.GetBool("transport"), TcpFull: viper.GetBool("transport-full"),
		Tls: viper.GetBool("tls"), TlsFull: viper.GetBool("tls-full"),
		Http: viper.GetBool("http"), HttpFull: viper.GetBool("http-full"),
		Body: viper.GetBool("body"), BodyFull: viper.GetBool("body-full"),

		Trace: viper.GetBool("trace"), Requests: viper.GetBool("requests"),
		Timestamps: ts,
	}

	return *pO
}

/* On timestamps:
* - We can't time every field, the protocols don't work like that
* - What we want to time is each step of the protocols thus related groups of data
* - What we _can_ time is when Go calls our callbacks, which is a close-ish approximation to that, modulo some quirks in the ways it handles various protocols
* - Haven't bothered with a Timing{T, time.Time} type for the timed things, because there's only a few of them that are
 */
type ResponseData struct {
	StartTime time.Time

	DnsSystemResolves []string

	TransportError      error
	TransportConnTime   time.Time
	TransportRemoteAddr net.Addr
	TransportLocalAddr  net.Addr

	TlsClientCertRequest     bool
	TlsClientCertRequestTime time.Time

	TlsServerCerts     []*x509.Certificate
	TlsServerCertsTime time.Time

	TlsComplete bool
	// There is no way to know handshake complete time. VerifyConnection isn't it, cause it's actually called before we send the client cert in (qv)
	TlsAgreedVersion     uint16
	TlsAgreedCipherSuite uint16
	TlsServerName        string
	TlsAgreedALPN        string
	TlsOCSPStapled       bool

	HttpError         error
	HttpHeadersTime   time.Time
	HttpProto         string
	HttpStatusCode    int // stdlib has no special type for this
	HttpStatusMessage string
	HttpHeaders       http.Header
	HttpContentLength int64
	HttpCompressed    bool

	BodyError        error
	BodyCompleteTime time.Time
	BodyBytes        []byte

	RedirectTarget *url.URL
}

func NewResponseData() *ResponseData {
	return &ResponseData{}
}

func (pD *ResponseData) Print(
	s output.TtyStyler, b output.Bios,
	requestData *RequestData,
	rtData *RoundTripData,
	pO PrintOpts,
) {
	// TODO: make work for aborted responses. Mostly about how we call it
	// - work out how to test an abort in each section (and document, and script if possible)
	//   - [ ] no internet at all (ie no routes, no local IP to initiate connections)
	//   - [ ] internet up but no packets flow (eg all sections are conn timeout)
	//   - [ ] DNS: dns server that is port closed / returns garbage
	//   - [x] TCP: port closed
	//   - [x] TLS: abort due to can't handshake - something (httplog) offering ancient ciphers
	//   - [x] HTTP Head: garbage / close pipe mid-header
	//   - [x] HTTP body: close pipe mid-body - don't think this is ever an error?
	// - probably: a "completed" bool for each section (either print its values, or "not available due to abort")

	if pO.Dns || pO.DnsFull {
		b.Banner("DNS")
		fmt.Print(s.Info("Using the Go stdlib lookup functions (rather than manual queries). Which, in this build, are calling...\n").String())
		fmt.Printf("Resovler: %s.\n", s.Noun(requestData.DnsSystemResolver))
		fmt.Printf("TCP addresses: %s\n", s.List(pD.DnsSystemResolves, s.AddrStyle))
	}

	if pO.Tcp || pO.TcpFull {
		b.Banner("TCP")
		b.CheckErr(pD.TransportError)

		fmt.Printf(
			"%sConnected %s -> %s\n",
			s.Timestamp(pD.TransportConnTime, pO.Timestamps, &pD.StartTime),
			s.Addr(pD.TransportLocalAddr.String()),
			s.Addr(pD.TransportRemoteAddr.String()),
		)
	}

	if rtData.TlsEnabled && (pO.Tls || pO.TlsFull) {
		b.Banner("TLS")

		if !pD.TlsComplete {
			b.PrintWarn("TLS handshake did not complete. It can fail at any point, so all, some, or none of the following might be incomplete")
		}

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

		/* Serving cert chain */

		fmt.Printf("%sServing cert chain\n", s.Timestamp(pD.TlsServerCertsTime, pO.Timestamps, &pD.StartTime))

		// This verification would normally happen automatically, and we'd be given these chains as args to VerifyPeerCertificate()
		// However a failed validation would cause client.Do() to return early with that error, and we want to carry on
		// This we set InsecureSkipVerify to stop the early bail out, and basically recreate the default checks ourselves
		// If caCert is nil ServingCertChainVerified() will use system roots to verify
		// The name given is verified against the cert.
		s.VerifiedServingCertChain(pD.TlsServerCerts, requestData.TlsServingCA, rtData.TlsValidateName, pO.TlsFull)

		/* Client cert auth */

		if pD.TlsClientCertRequest {
			fmt.Print(s.Timestamp(pD.TlsClientCertRequestTime, pO.Timestamps, &pD.StartTime))
			if requestData.TlsClientPair == nil {
				b.PrintWarn("Server asked for a client cert but none configured (-c/-k). Not presenting a cert, this might cause the server to abort the handshake.")
			} else {
				//need a deamonData with these thigns in (reused)
				fmt.Println("Presenting client cert chain")
				if pO.TlsFull {
					s.ClientCertChain(codec.ChainFromCertificate(requestData.TlsClientPair))
				}
			}
			fmt.Println()
		}

		/* TLS agreement summary */

		// TODO: useful TLS info checklist
		// - [x] HSTS
		// - [x] OCSP pinning
		// - [x] HPKP: obsolete, but may as well print it if it's present (not print anything when it's not)
		// - [ ] Certificate Transparency: understand it, do stuff. Is a header? Is also stuff in the OCSP bundle?
		// - [ ] DNS CAA records: should investigate and print in the TLS section
		// - [ ] DANE
		// CORS headers aren't really meaningful cause they'll only be sent if the request includes an Origin header
		fmt.Printf("%s handshake complete with %s\n",
			s.Noun(output.TLSVersionName(pD.TlsAgreedVersion)),
			s.Addr(pD.TlsServerName),
		)
		fmt.Printf("\tSymmetric cypher suite %s\n", s.Noun(tls.CipherSuiteName(pD.TlsAgreedCipherSuite)))
		fmt.Printf("\tALPN proto %s\n", s.OptionalString(pD.TlsAgreedALPN, s.NounStyle))
		fmt.Printf("\tOCSP info stapled to response? %s\n", s.YesNo(pD.TlsOCSPStapled))
		fmt.Printf("\tHSTS? %s\n", s.YesNo(pD.HttpHeaders.Get("Strict-Transport-Security") != ""))
		if pD.HttpHeaders.Get("Public-Key-Pins") != "" || pD.HttpHeaders.Get("Public-Key-Pins-Report-Only") != "" {
			// Don't print an angry red "no" if not present, because it's obsolete
			fmt.Printf("\tHPKP? %s\n", s.Ok("yes (Not currently parsed or validated)"))
		}
		fmt.Println()

	}

	if pO.Http || pO.HttpFull {
		b.Banner("HTTP")
		b.CheckErr(pD.HttpError)

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

		fmt.Printf("%s%s", s.Timestamp(pD.HttpHeadersTime, pO.Timestamps, &pD.StartTime), s.Noun(pD.HttpProto))
		if pD.HttpStatusCode < 400 {
			fmt.Printf(" %s", s.Ok(pD.HttpStatusMessage))
		} else if pD.HttpStatusCode < 500 {
			fmt.Printf(" %s", s.Warn(pD.HttpStatusMessage))
		} else {
			fmt.Printf(" %s", s.Fail(pD.HttpStatusMessage))
		}
		fmt.Printf(" from %s", s.OptionalString(pD.HttpHeaders.Get("server"), s.NounStyle))
		fmt.Println()

		if !pO.HttpFull {
			fmt.Printf("\tclaimed %s bytes of %s\n", s.Bright(strconv.FormatInt(int64(pD.HttpContentLength), 10)), s.Noun(pD.HttpHeaders.Get("content-type")))
			if pD.HttpCompressed {
				fmt.Printf("\tcontent was transparently decompressed; length information will not be accurate\n")
			}
		} else {
			for k, vs := range pD.HttpHeaders {
				fmt.Printf("\t%s = %v\n", s.Addr(k), s.Noun(strings.Join(vs, ",")))
			}
		}
	}

	if pO.Body || pO.BodyFull {
		b.Banner("Body")
		b.CheckErr(pD.BodyError)

		bodyLen := len(pD.BodyBytes)
		fmt.Printf("%s%s bytes of body actually read\n",
			s.Timestamp(pD.BodyCompleteTime, pO.Timestamps, &pD.StartTime),
			s.Bright(strconv.FormatInt(int64(bodyLen), 10)),
		)
		fmt.Printf("Valid utf-8? %s\n", s.YesNo(utf8.Valid(pD.BodyBytes)))
		fmt.Println()

		printLen := usvc.MinInt(bodyLen, 72)
		if pO.BodyFull {
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
		if requestData.FollowRedirects {
			fmt.Println("\tfollowing...")
		} else {
			fmt.Println("\tNot following redirects, enable with --location")
		}
	}
}
