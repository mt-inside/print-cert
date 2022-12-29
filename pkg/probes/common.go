package probes

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/http-log/pkg/utils"
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

func getCheckRedirect(s output.TtyStyler, b output.Bios, requestData *state.RequestData, c *http.Client) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		b.Banner("Redirect")

		// 		fmt.Printf("Redirected to %s\n", s.Addr(req.URL.String()))

		// 		b.Trace("Updating TLS ClientHello", "ServerName", req.URL.Host)
		// 		getUnderlyingHttpTransport(c).TLSClientConfig.ServerName = req.URL.Host

		// 		b.Trace("Updating HTTP request", "Host", req.URL.Host)
		// 		req.Host = req.URL.Host

		// 		DnsSystem(s, b, requestData.Timeout, req.URL.Host)

		// 		fmt.Println()

		return nil
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
	targetIP := dnsSystem(s, b, requestData, responseData, target)
	var client *http.Client
	if requestData.TlsEnabled {
		client = buildTlsClient(s, b, requestData, responseData)
	} else {
		client = buildPlaintextClient(s, b, requestData, responseData)
	}
	request, cancel := buildHttpRequest(s, b, requestData, responseData, targetIP, port, path)
	defer cancel()
	if manualDns {
		dnsManual(s, b, requestData, responseData, target) // TODO make optional - eventually as perf optim, but now to stop it printing (plaintext too)
	}
	probe(s, b, requestData, responseData, client, request, readBody)
}

func buildHttpRequest(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	responseData *state.ResponseData,
	addr net.IP,
	port uint64,
	path string,
) (*http.Request, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), requestData.Timeout)

	/* This is the URL we give to the HTTP client library. The "Host" part of the URL is just used as the connection address, and not seen on the other end */
	addrPort := net.JoinHostPort(addr.String(), strconv.FormatUint(port, 10))
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
	req.Header.Add("user-agent", "print-cert TODO from build info")
	if requestData.AuthBearerToken != "" {
		req.Header.Add("authorization", fmt.Sprintf("Bearer %s", requestData.AuthBearerToken))
	}

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
