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

	"github.com/quic-go/quic-go/logging"
	"github.com/spf13/viper"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/parser"
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
	TransportVersion    logging.VersionNumber // Protocol version, iff QUIC

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
	HttpRatelimit     *HttpRatelimit

	BodyError        error
	BodyCompleteTime time.Time
	BodyBytes        []byte

	RedirectTarget *url.URL
}

type HttpRatelimit struct {
	Bucket   uint64
	Remain   uint64
	Reset    time.Duration
	Policies []HttpRatelimitPolicy
}
type HttpRatelimitPolicy struct {
	Bucket uint64
	Window time.Duration
}

func NewResponseData() *ResponseData {
	return &ResponseData{}
}

func (pD *ResponseData) Print(
	s output.TtyStyler,
	b bios.Bios,
	requestData *RequestData,
	rtData *RoundTripData,
	pO PrintOpts,
) {
	// TODO: check all summaries and fulls with the new indentingBuilder. All features on, and internet DNS so -D prints something meaningful
	var op output.IndentingBuilder
	var skipping bool

	// TODO: make work for aborted responses. Mostly about how we call it
	// - work out how to test an abort in each section (and document, and script if possible)
	//   - [x] no internet at all (ie no routes, no local IP to initiate connections)
	//   - [ ] internet up but no packets flow (eg all sections are conn timeout)
	//   - [ ] DNS: dns server that is port closed / returns garbage
	//   - [x] TCP: port closed
	//   - [x] TLS: abort due to can't handshake - something (httplog) offering ancient ciphers
	//   - [x] HTTP Head: garbage / close pipe mid-header
	//   - [x] HTTP body: close pipe mid-body - don't think this is ever an error?
	// - probably: a "completed" bool for each section (either print its values, or "not available due to abort")

	if pO.Dns || pO.DnsFull {
		op.Block(s.Banner("DNS"))
		op.Line(s.Info("Using the Go stdlib lookup functions (rather than manual queries). Which, in this build, are calling..."))
		op.Linef("Resovler: %s.", s.Noun(requestData.DnsSystemResolver))
		op.Linef("TCP addresses: %s", s.List(pD.DnsSystemResolves, output.AddrStyle))
	}

	if !skipping && (pO.Tcp || pO.TcpFull) {
		op.Block(s.Banner("TRANSPORT"))
		if pD.TransportError != nil {
			skipping = true
			op.Line(s.RenderErr(pD.TransportError.Error()))
		}

		op.Printf("%s", s.Timestamp(pD.TransportConnTime, pO.Timestamps, &pD.StartTime))
		if pD.TransportVersion != 0 { // NB: h2 can run over quic too, so don't check HTTP version here
			op.Print(s.Noun(fmt.Sprintf("QUIC %s", pD.TransportVersion)))
		} else {
			op.Print(s.Noun("TCP"))
		}
		op.Linef(
			" connected %s -> %s",
			s.Addr(pD.TransportLocalAddr),
			s.Addr(pD.TransportRemoteAddr),
		)
	}

	if !skipping && (rtData.TlsEnabled && (pO.Tls || pO.TlsFull)) {
		op.Block(s.Banner("TLS"))
		skipping = !pD.TlsComplete // can't really get tls Errors (they're private and wrapped), but can infer from this

		if !pD.TlsComplete {
			op.Line(s.RenderWarn("TLS handshake did not complete. It can fail at any point, so all, some, or none of the following might be incomplete"))
			op.NewLine()
		}

		if pO.Requests {
			op.Line("Request: ")
			if rtData.TlsServerName != "" {
				op.Linef("SNI ServerName %s", s.Addr(rtData.TlsServerName))
			} else {
				// If an explicit --sni is given which is invalid, we'll already have error'd out
				op.Line(s.RenderWarn("Not sending SNI ServerName. Either provide one explicity with --sni, or give a --host or target that's a valid SNI."))
			}
			op.NewLine()
		}

		/* Serving cert chain */

		op.Linef("%sServing cert chain", s.Timestamp(pD.TlsServerCertsTime, pO.Timestamps, &pD.StartTime))
		op.Indent()

		// This verification would normally happen automatically, and we'd be given these chains as args to VerifyPeerCertificate()
		// However a failed validation would cause client.Do() to return early with that error, and we want to carry on
		// This we set InsecureSkipVerify to stop the early bail out, and basically recreate the default checks ourselves
		// If caCert is nil ServingCertChainVerified() will use system roots to verify
		// The name given is verified against the cert.
		op.Block(s.VerifiedServingCertChain(pD.TlsServerCerts, requestData.TlsServingCA, rtData.TlsValidateName, pO.TlsFull))

		op.Dedent()

		/* Client cert auth */

		if pD.TlsClientCertRequest {
			op.Tabs()
			// TODO: with the timestamp versions, move this into the two branches
			op.Print(s.Timestamp(pD.TlsClientCertRequestTime, pO.Timestamps, &pD.StartTime))
			if requestData.TlsClientPair == nil {
				op.Println(s.RenderWarn("Server asked for a client cert but none configured (-c/-k). Not presenting a cert, this might cause the server to abort the handshake."))
			} else {
				//need a deamonData with these thigns in (reused)
				op.Println("Presenting client cert chain")
				if pO.TlsFull {
					op.Indent()
					op.Block(s.ClientCertChain(codec.ChainFromCertificate(requestData.TlsClientPair)))
					op.Dedent()
				}
			}
			op.NewLine()
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
		op.Linef("%s handshake complete with %s",
			s.Noun(tls.VersionName(pD.TlsAgreedVersion)),
			s.Addr(pD.TlsServerName),
		)
		op.Indent()
		op.Linef("Symmetric cypher suite %s", s.Noun(tls.CipherSuiteName(pD.TlsAgreedCipherSuite)))
		op.Linef("ALPN proto %s", s.Noun(pD.TlsAgreedALPN))
		op.Linef("OCSP info stapled to response? %s", s.YesNo(pD.TlsOCSPStapled))
		op.Linef("HSTS? %s", s.YesNo(pD.HttpHeaders.Get("Strict-Transport-Security") != ""))
		if pD.HttpHeaders.Get("Public-Key-Pins") != "" || pD.HttpHeaders.Get("Public-Key-Pins-Report-Only") != "" {
			// Don't print an angry red "no" if not present, because it's obsolete
			op.Linef("HPKP? %s", s.Ok("yes (Not currently parsed or validated)"))
		}
		op.Dedent()
	}

	if !skipping && (pO.Http || pO.HttpFull) {
		op.Block(s.Banner("HTTP"))
		if pD.HttpError != nil {
			skipping = true
			op.Line(s.RenderErr(pD.HttpError.Error()))
		}

		if pO.Requests {
			op.Linef("Request: Host %s %s %s", s.Addr(rtData.HttpHost), s.Verb(requestData.HttpMethod), s.UrlPath(rtData.HttpPath))
			op.Indent()
			if requestData.AuthBearerToken != "" {
				if token, err := parser.JWTNoSignature(requestData.AuthBearerToken); err == nil {
					op.Linef("Presented bearer token: %s", s.JWTFull(token))
				} else {
					panic(err)
				}
			}
			op.NewLine()
			op.Dedent()
		}

		op.Tabs()
		op.Printf("%s%s", s.Timestamp(pD.HttpHeadersTime, pO.Timestamps, &pD.StartTime), s.Noun(pD.HttpProto))
		if pD.HttpStatusCode < 400 {
			op.Printf(" %s", s.Ok(pD.HttpStatusMessage))
		} else if pD.HttpStatusCode < 500 {
			op.Printf(" %s", s.Warn(pD.HttpStatusMessage))
		} else {
			op.Printf(" %s", s.Fail(pD.HttpStatusMessage))
		}
		op.Printf(" from %s", s.Noun(pD.HttpHeaders.Get("server")))
		op.NewLine()

		op.Indent()

		/* HEADERS */

		if !pO.HttpFull {
			op.Linef("claimed %s bytes of %s", s.Bright(strconv.FormatInt(int64(pD.HttpContentLength), 10)), s.Noun(pD.HttpHeaders.Get("content-type")))
			if pD.HttpCompressed {
				op.Linef("content was transparently decompressed; length information will not be accurate")
			}
		} else {
			for k, vs := range pD.HttpHeaders {
				op.Linef("%s: %v", s.Addr(k), s.Noun(strings.Join(vs, ",")))
			}
		}

		/* RATELIMIT */

		if pD.HttpRatelimit != nil {
			op.NewLine()
			op.Tabs()
			op.Printf("Ratelimit: policies")
			for _, policy := range pD.HttpRatelimit.Policies {
				op.Printf(" %s/%s", s.Number(policy.Bucket), s.Duration(policy.Window))
			}
			op.Printf("; soonest expiring bucket %s/%s, resets in %s", s.Number(pD.HttpRatelimit.Remain), s.Number(pD.HttpRatelimit.Bucket), s.Duration(pD.HttpRatelimit.Reset))
			op.NewLine()
		}

		op.Dedent()
	}

	if !skipping && (pO.Body || pO.BodyFull) {
		op.Block(s.Banner("Body"))
		if pD.BodyError != nil {
			skipping = true
			op.Line(s.RenderErr(pD.BodyError.Error()))
		}

		bodyLen := len(pD.BodyBytes)
		op.Linef("%s%s bytes of body actually read",
			s.Timestamp(pD.BodyCompleteTime, pO.Timestamps, &pD.StartTime),
			s.Bright(strconv.FormatInt(int64(bodyLen), 10)),
		)
		op.Indent()
		op.Linef("Valid utf-8? %s", s.YesNo(utf8.Valid(pD.BodyBytes)))
		op.Dedent()
		op.NewLine()

		printLen := min(bodyLen, 72)
		if pO.BodyFull {
			printLen = bodyLen
		}

		// TODO should share a print-body with all the other places that do this, which should check it's UTF, print that status, deal with elision, etc
		op.Printf("%v", string(pD.BodyBytes[0:printLen])) // assumes utf8
		if bodyLen > printLen {
			op.Printf("<%d bytes elided>", bodyLen-printLen)
		}
		if bodyLen > 0 {
			op.NewLine()
		}
	}

	if !skipping && (pD.RedirectTarget != nil) {
		op.Block(s.Banner("Redirect"))

		op.Linef("Redirected to %s", s.Addr(pD.RedirectTarget.String()))
		op.Indent()
		if requestData.FollowRedirects {
			op.Line("following...")
		} else {
			op.Line("Not following redirects, enable with --location")
		}
		op.Dedent()
	}

	op.Output()
}
