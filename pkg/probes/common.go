package probes

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/spf13/viper"

	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/utils"
	"github.com/mt-inside/print-cert/pkg/state"
)

// two objects
// - permanent settings (daemondata)
// - ephemeral data (HAVE a probedata. Build* to be non-members)
//   - this tree to have all the Build* methods (as they close over the pD)
//   - Do() to return new target, port, scheme
// - NewEphemeral to take "target" (user-supplied name or IP), port, scheme
//   - do extended DNS over target
//   - do simple DNS over target (needs to check if it's an IP), return one of the IPs (so can say which one, force v4/6, etc)
// - doc names: how TlsVerifyName is derived, how target is used
// - compare's ref and diff should both be treated like this, and can be names or IPs

func getCheckRedirect(s output.TtyStyler, b output.Bios, requestData *state.RequestData, responseData *state.ResponseData) func(*http.Request, []*http.Request) error {
	// NB: when testing this
	// - Go will only follow redirects when status is 30[1,2,3,7,8] and Location is set (https://cs.opensource.google/go/go/+/refs/tags/go1.19.4:src/net/http/client.go;l=502)
	// - Even apparently duplicating the request that curl sends, it's really hard to make httpbin give us a 302
	return func(req *http.Request, via []*http.Request) error {
		responseData.RedirectTarget = req.URL

		return http.ErrUseLastResponse
	}
}

func Probe(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	responseData *state.ResponseData,
	target string,
	port uint64,
	path string,
	manualDns bool,
	readBody bool,
) {
	for {
		var client *http.Client
		if requestData.TlsEnabled {
			client = buildTlsClient(s, b, requestData, responseData)
		} else {
			client = buildPlaintextClient(s, b, requestData, responseData)
		}
		request, cancel := buildHttpRequest(s, b, requestData, responseData, target, port, path)
		defer cancel()

		dnsSystem(s, b, requestData, responseData, target)
		if manualDns {
			dnsManual(s, b, requestData, responseData, target) // Performance optimisation
		}

		probe(s, b, requestData, responseData, client, request, readBody)

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
			// We're basically re-implementing this, which is horrible to have to do: https://cs.opensource.google/go/go/+/refs/tags/go1.19.4:src/net/http/client.go;drc=9123221ccf3c80c741ead5b6f2e960573b1676b9;l=585
			// We don't have a choice though, because there's no other way to get hold of the HTTP response and body.
			// - CheckRedirect returning nil means the client follows redirects and eventually returns only the last metadata and body
			// - CheckRedirect returning ar err causes the client to bail early (like returning ErrUseLastResponse does), but the http.Response object is empty, and the body is closed
			loc := responseData.RedirectTarget
			// TODO: if redirect is NOT relative, set Host and SNI to the new domain (see code linked above)
			target, port = utils.SplitHostMaybePortDefault(loc.Host, utils.Ternary(loc.Scheme == "https", uint64(443), 80))
			path = loc.Path
			// TODO: deal with scheme. Change TLSEnabled on requestData? Modifying that struct doesn't feel like the end of the world
			responseData = state.NewResponseData()
		} else {
			break
		}
	}
}

func buildHttpRequest(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	responseData *state.ResponseData,
	target string,
	port uint64,
	path string,
) (*http.Request, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), requestData.Timeout)

	/* This is the URL we give to the HTTP client library. The "Host" part of the URL is just used as the connection address, and not seen on the other end */
	addrPort := net.JoinHostPort(target, strconv.FormatUint(port, 10))
	pathParts, err := url.Parse(path)
	b.CheckErr(err)
	l7Addr := url.URL{
		Scheme:   utils.Ternary(requestData.TlsEnabled, "https", "http"),
		Host:     addrPort, // could leave off 80 or 443 but not an error to include them
		Path:     pathParts.EscapedPath(),
		RawQuery: pathParts.RawQuery,
		Fragment: pathParts.EscapedFragment(),
	}
	requestData.HttpPath = &l7Addr

	req, err := http.NewRequestWithContext(ctx, requestData.HttpMethod, requestData.HttpPath.String(), nil)
	b.CheckErr(err)

	req.Host = requestData.HttpHost
	if requestData.AuthBearerToken != "" {
		req.Header.Add("authorization", fmt.Sprintf("Bearer %s", requestData.AuthBearerToken))
	}

	// TODO: do better
	req.Header.Add("accept", "application/json")
	req.Header.Add("accept", "*/*")
	//req.Header.Add("user-agent", "print-cert TODO from build info")
	req.Header.Add("user-agent", "curl/7.85.0")

	return req, cancel
}

func probe(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
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
