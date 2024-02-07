package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/mt-inside/print-cert/internal/build"
	"github.com/mt-inside/print-cert/pkg/parser"
	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/output"
	hlu "github.com/mt-inside/http-log/pkg/utils"
)

// Throws away the tls.Config, and returns a plaintext stream
func getFakeTLSDialContext(s output.TtyStyler, b bios.Bios, requestData *state.RequestData, responseData *state.ResponseData) func(context.Context, string, string, *tls.Config) (net.Conn, error) {
	return func(ctx context.Context, network, address string, tlsCfg *tls.Config) (net.Conn, error) {
		return getDialContext(s, b, requestData, responseData)(ctx, network, address)
	}
}

func getDialContext(s output.TtyStyler, b bios.Bios, requestData *state.RequestData, responseData *state.ResponseData) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   requestData.Timeout,
			KeepAlive: 60 * time.Second,
			// Happens "after creating the network connection but before actually dialing."
			Control: func(network, address string, rawConn syscall.RawConn) error {
				responseData.StartTime = time.Now() // we use this time, which is _some time_ before the syn is sent, as start time. We do so because even on a fast machine it's 0.5ms after we call client.Do(), which is a longer delay than the actual TCP handshake over loopback. So while not totally acurate, it's more acurate.
				log.Info("Dialing", "net", network, "addr", address)

				return nil
			},
		}
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			responseData.TransportError = err
			return nil, err
		}

		log.Info("Connected", "to", conn.RemoteAddr(), "from", conn.LocalAddr())
		responseData.TransportConnTime = time.Now()
		responseData.TransportLocalAddr = conn.LocalAddr()
		responseData.TransportRemoteAddr = conn.RemoteAddr()

		return conn, err
	}
}

func getCheckRedirect(s output.TtyStyler, b bios.Bios, requestData *state.RequestData, responseData *state.ResponseData) func(*http.Request, []*http.Request) error {
	// NB: when testing this
	// - Go will only follow redirects when status is 30[1,2,3,7,8] and Location is set (https://cs.opensource.google/go/go/+/refs/tags/go1.19.4:src/net/http/client.go;l=502)
	// - Even apparently duplicating the request that curl sends, it's really hard to make httpbin give us a 302
	// - Good URLs
	//   - http-log --status 302
	//   - https://office.com/setup
	return func(req *http.Request, via []*http.Request) error {
		responseData.RedirectTarget = req.URL

		return http.ErrUseLastResponse
	}
}

func Probe(
	s output.TtyStyler,
	b bios.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	printOpts state.PrintOpts,
	manualDns bool,
	readBody bool,
) (body []byte) {
	responseData := state.NewResponseData()

	for {
		var client *http.Client
		if rtData.TlsEnabled {
			client = buildTlsClient(s, b, requestData, rtData, responseData)
		} else {
			client = buildPlaintextClient(s, b, requestData, rtData, responseData)
		}
		request, cancel := buildHttpRequest(s, b, requestData, rtData, responseData)
		defer cancel()

		// Do manual DNS first, so that it can give an idea of /why/ the resolution failed, as dnsSystem() quits the programme
		if manualDns { // Performance optimisation
			dnsManual(s, b, requestData, rtData, responseData)
		}
		dnsSystem(s, b, requestData, rtData, responseData)

		httpRoundTrip(s, b, responseData, client, request, readBody)
		body = responseData.BodyBytes

		/* Print */

		// TODO: the functions on the state object should be focussed on feeding info *into* it, like "ingestTLSConnState()", "ingestHTTPResponse()" (should do some parsing like looking for hsts header and promoting to struct field)
		// - there's then one "printAll()" function which looks at all the tls-full etc flags and prints everything
		// - it can be clever and eg use hsts info from http header in the TLS output section
		// - make sure the controlflow is such that this is always called to do what it can no matter if we bail out on an abort or an error
		// - can do other clever stuff like (in http-log) not printing SNI in tls-agreed if we have the tls-negotiation flag set because that will have done it

		responseData.Print(
			s, b,
			requestData,
			rtData,
			printOpts,
		)

		/* Redirect */

		if requestData.FollowRedirects && responseData.HttpStatusCode >= 300 && responseData.HttpStatusCode < 400 {
			// We're basically re-implementing this, which is horrible to have to do: https://cs.opensource.google/go/go/+/refs/tags/go1.19.4:src/net/http/client.go;l=585
			// We don't have a choice though, because there's no other way to get hold of the HTTP response and body.
			// - CheckRedirect returning nil means the client follows redirects and eventually returns only the last metadata and body
			// - CheckRedirect returning ar err causes the client to bail early (like returning ErrUseLastResponse does), but the http.Response object is empty, and the body is closed
			loc := responseData.RedirectTarget
			// The std lib does a lot of messing around working out if the redirect is relative etc, but I think we can just take this new target (which is Location resolved onto the original request target) and use its host?
			rtData = state.DeriveRoundTripData(s, b, loc.Host, loc.Host, loc.Host, loc.Path, loc.Scheme == "https")

			responseData = state.NewResponseData()
		} else {
			break
		}
	}

	return
}

func buildHttpRequest(
	s output.TtyStyler,
	b bios.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) (*http.Request, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), requestData.Timeout)

	/* This is the URL we give to the HTTP client library. The "Host" part of the URL is just used as the connection address, and not seen on the other end */
	l7Addr := url.URL{
		Scheme:   hlu.Ternary(rtData.TlsEnabled, "https", "http"),
		Host:     rtData.TransportTarget, // could leave off 80 or 443 but not an error to include them
		Path:     rtData.HttpPath.EscapedPath(),
		RawQuery: rtData.HttpPath.RawQuery,
		Fragment: rtData.HttpPath.EscapedFragment(),
	}

	req, err := http.NewRequestWithContext(ctx, requestData.HttpMethod, l7Addr.String(), requestData.BodyReader)
	b.Unwrap(err)

	req.Host = rtData.HttpHost
	if requestData.AuthBearerToken != "" {
		req.Header.Add("authorization", fmt.Sprintf("Bearer %s", requestData.AuthBearerToken))
	}

	// We don't fake user-agent or anything to try to influence responses, but some servers obviously are sensitive to that.
	req.Header.Add("accept", "*/*")
	req.Header.Add("user-agent", build.NameAndVersion())

	// Add these after we've set the built-in ones above, so the user can override them
	for k, v := range requestData.ExtraHeaders {
		req.Header.Set(k, v)
	}

	return req, cancel
}

func httpRoundTrip(
	s output.TtyStyler,
	b bios.Bios,
	responseData *state.ResponseData,
	client *http.Client,
	req *http.Request,
	readBody bool, // performance optimisation
) {
	resp, err := client.Do(req)
	if err != nil {
		// NB: can't really differentiate actual HTTP errors from TLS ones here, as tls error types are returned, but they're private, wrapped in url.Error. But we have our ResponseData::TlsComplete flag that we use
		responseData.HttpError = err
		return
	}

	defer resp.Body.Close()

	// The TLS handshake can fail "late", eg because we send a client cert that the server won't authenticate. This happens after all the TLS callbacks have been called, so there's nothing on our side to receive an error. The definitive "ok" signal seems to be this field of ConnectionState (which is low during all the TLS callbacks, cause by definition the handshake isn't done in any of them). Note that the handshake can fail but all our ResponseData can be gathered and valid (if it fails late in the process), so we just print incomplete-handshake as a warning and carefully look at ResponseData fields to see if they're worth printing.
	if resp.TLS != nil { // might be in plaintext mode
		responseData.TlsComplete = resp.TLS.HandshakeComplete
	}

	log.Info("Metadata round trip done", "headers", len(resp.Header))
	responseData.HttpHeadersTime = time.Now()
	responseData.HttpProto = resp.Proto
	responseData.HttpStatusCode = resp.StatusCode
	responseData.HttpStatusMessage = resp.Status
	responseData.HttpHeaders = resp.Header
	responseData.HttpContentLength = resp.ContentLength
	responseData.HttpCompressed = resp.Uncompressed

	/* Parsers / Enrichers */

	responseData.HttpRatelimit = parser.Ratelimit(resp.Header)
	// TODO: should parse more things here. Like hops...

	/* Body */

	if readBody {
		rawBody, err := io.ReadAll(resp.Body)
		if err != nil {
			responseData.BodyError = err
			return
		}
		responseData.BodyCompleteTime = time.Now()
		log.Info("Body read complete", "bytes", len(rawBody))
		responseData.BodyBytes = rawBody
	}
}
