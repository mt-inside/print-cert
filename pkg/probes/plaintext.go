package probes

import (
	"net/http"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/output"
)

func buildPlaintextClient(
	s output.TtyStyler,
	b bios.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext:           getDialContext(s, b, requestData, responseData),
			ResponseHeaderTimeout: requestData.Timeout,
			DisableCompression:    true,
			// Note that this is pointless because Go's http2 won't work without TLS. This flag doesn't attempt anything. You can change this to an http2.Transport, and it'll tell you "http" is an invalid scheme.
			ForceAttemptHTTP2: !requestData.HttpForce11, // Because there's no TLS, there's no ALPN, so we have to insist.
		},
	}

	c.CheckRedirect = getCheckRedirect(s, b, requestData, responseData)

	return c
}
