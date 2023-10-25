package probes

import (
	"net/http"

	"golang.org/x/net/http2"

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
	var t http.RoundTripper

	if !requestData.HttpForce11 {
		t = &http2.Transport{
			AllowHTTP:          true,                                                   // Allow use of the "http" scheme. Just sends it; doesn't do `Update: h2c`
			DialTLSContext:     getFakeTLSDialContext(s, b, requestData, responseData), // To do plaintext h2, you have to give a function that, despite the name, will return a non-TLS connection.
			PingTimeout:        requestData.Timeout,
			WriteByteTimeout:   requestData.Timeout,
			DisableCompression: true,
		}
	} else {
		t = &http.Transport{
			DialContext:           getDialContext(s, b, requestData, responseData),
			ResponseHeaderTimeout: requestData.Timeout,
			DisableCompression:    true,
			// Note that ForceAttemptHTTP2 doesn't do anything without TLS
		}
	}

	c := &http.Client{
		Transport: t,
	}

	c.CheckRedirect = getCheckRedirect(s, b, requestData, responseData)

	return c
}
