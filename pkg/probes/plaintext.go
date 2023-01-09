package probes

import (
	"net/http"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
)

func buildPlaintextClient(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext:           getDialContext(s, b, requestData, responseData),
			ResponseHeaderTimeout: requestData.Timeout,
			DisableCompression:    true,
		},
	}

	c.CheckRedirect = getCheckRedirect(s, b, requestData, responseData)

	return c
}
