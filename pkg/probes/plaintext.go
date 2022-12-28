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
	daemonData *state.DaemonData,
	probeData *state.ProbeData,
) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   daemonData.Timeout,
					KeepAlive: 60 * time.Second,
					// Note: happens "after creating the network connection but before actually dialing."
					Control: func(network, address string, rawConn syscall.RawConn) error {
						probeData.TransportDialTime = time.Now()
						b.Trace("Dialing", "addr", address)

						return nil
					},
				}
				conn, err := dialer.DialContext(ctx, network, address)
				b.CheckErr(err)
				b.Trace("Connected", "to", conn.RemoteAddr(), "from", conn.LocalAddr())

				probeData.TransportConnTime = time.Now()
				probeData.TransportLocalAddr = conn.LocalAddr()
				probeData.TransportRemoteAddr = conn.RemoteAddr()

				return conn, err
			},
			ResponseHeaderTimeout: daemonData.Timeout,
			DisableCompression:    true,
		},
	}

	c.CheckRedirect = getCheckRedirect(s, b, daemonData, c)

	return c
}
