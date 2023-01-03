package probes

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/spf13/viper"

	"github.com/mt-inside/print-cert/pkg/build"
	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
	hlu "github.com/mt-inside/http-log/pkg/utils"
)

func getCheckRedirect(s output.TtyStyler, b output.Bios, requestData *state.RequestData, responseData *state.ResponseData) func(*http.Request, []*http.Request) error {
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

// TODO: don't pass responseData in
func Probe(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
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

		dnsSystem(s, b, requestData, rtData, responseData)
		if manualDns { // Performance optimisation
			dnsManual(s, b, requestData, rtData, responseData)
		}

		probe(s, b, responseData, client, request, readBody)
		body = responseData.BodyBytes

		/* Print */

		// TODO: passing [tls,head][-full] into these functions is hideous.
		// This needs an outputter like http-log's (shouldn't share/duplicate any code but will use a lot of high-level stuff from the styler like styleHeaderArray())
		// The outputter should be constructed over all the tls-full etc, then it can be unconditiionally called and choose what to print
		// Pro: the functions on the outputter should be focussed on feeding info *into* it, like "ingestTLSConnState()", "ingestHTTPResponse()" (should do some parsing like looking for hsts header and promoting to struct field)
		// - there's then one "printAll()" function which looks at all the tls-full etc flags and prints everything
		// - it can be clever and eg use hsts info from http header in the TLS output section
		// - make sure the controlflow is such that this is always called to do what it can no matter if we bail out on an abort or an error
		// - can do other clever stuff like (in http-log) not printing SNI in tls-agreed if we have the tls-negotiation flag set because that will have done it

		responseData.Print(
			s, b,
			requestData,
			rtData,
			// TODO: if none of these are set, default to dns,tls,head,body. Can't set their default flag values cause then they can't be turned off. See how http-log does it
			viper.GetBool("dns"), viper.GetBool("dns-full"),
			viper.GetBool("tls"), viper.GetBool("tls-full"),
			viper.GetBool("head"), viper.GetBool("head-full"),
			viper.GetBool("body"), viper.GetBool("body-full"),
			// TODO: make printing of request info optional (can be inferred from the args but can be useful to have it spelled out)
			// TODO: make it possible to turn b.Trace output on/off
		)

		/* Redirect */

		if responseData.HttpStatusCode >= 300 && responseData.HttpStatusCode < 400 {
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
	b output.Bios,
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

	req, err := http.NewRequestWithContext(ctx, requestData.HttpMethod, l7Addr.String(), nil)
	b.CheckErr(err)

	req.Host = rtData.HttpHost
	if requestData.AuthBearerToken != "" {
		req.Header.Add("authorization", fmt.Sprintf("Bearer %s", requestData.AuthBearerToken))
	}

	// We don't fake user-agent or anything to try to influence responses, but some servers obviously are sensitive to that.
	req.Header.Add("accept", "*/*")
	req.Header.Add("user-agent", build.NameAndVersion())

	return req, cancel
}

func probe(
	s output.TtyStyler,
	b output.Bios,
	responseData *state.ResponseData,
	client *http.Client,
	req *http.Request,
	readBody bool, // performance optimisation
) {
	resp, err := client.Do(req)
	b.CheckErr(err)
	defer resp.Body.Close()

	responseData.HttpProto = resp.Proto
	responseData.HttpStatusCode = resp.StatusCode
	responseData.HttpStatusMessage = resp.Status
	responseData.HttpHeaders = resp.Header
	responseData.HttpContentLength = resp.ContentLength
	responseData.HttpCompressed = resp.Uncompressed

	if readBody {
		rawBody, err := io.ReadAll(resp.Body)
		b.CheckErr(err)
		responseData.BodyBytes = rawBody
	}
}
