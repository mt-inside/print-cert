package probes

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
)

func buildPlaintextClient(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	responseData *state.ResponseData,
) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   requestData.Timeout,
					KeepAlive: 60 * time.Second,
					// Note: happens "after creating the network connection but before actually dialing."
					Control: func(network, address string, rawConn syscall.RawConn) error {
						responseData.TransportDialTime = time.Now()
						b.Trace("Dialing", "addr", address)

						return nil
					},
				}
				conn, err := dialer.DialContext(ctx, network, address)
				b.CheckErr(err)
				b.Trace("Connected", "to", conn.RemoteAddr(), "from", conn.LocalAddr())

				responseData.TransportConnTime = time.Now()
				responseData.TransportLocalAddr = conn.LocalAddr()
				responseData.TransportRemoteAddr = conn.RemoteAddr()

				return conn, err
			},
			ResponseHeaderTimeout: requestData.Timeout,
			DisableCompression:    true,
		},
	}

	c.CheckRedirect = getCheckRedirect(s, b, requestData, c)

	return c
}
