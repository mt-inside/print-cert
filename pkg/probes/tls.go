package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/MarshallWace/go-spnego"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
)

func buildTlsClient(
	s output.TtyStyler,
	b output.Bios,
	daemonData *state.DaemonData,
	probeData *state.ProbeData,
) *http.Client {

	// Always make a krb transport, becuase if we make a plain HTTP one and try to wrap it later, we have to copy the bytes (because spnego.Transport embeds http.Transport) and that copies a sync.Mutex.
	tr := &spnego.Transport{
		NoCanonicalize: true,
		Transport: http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   daemonData.Timeout,
					KeepAlive: 60 * time.Second,
					// Note: happens "after creating the network connection but before actually dialing."
					Control: func(network, address string, rawConn syscall.RawConn) error {
						probeData.TransportDialTime = time.Now()
						b.Trace("Dialing", "addr", address) // TODO ever any different to the below? Should just capture the time here, and print it if in transport-full

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
			TLSHandshakeTimeout:   daemonData.Timeout, // assume this is just the TLS handshake ie tcp handshake is covered by the dialer
			ResponseHeaderTimeout: daemonData.Timeout,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // deliberate, qv
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         daemonData.TlsServerName, // SNI for TLS vhosting
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					probeData.TlsClientCertRequest = true
					b.Trace("TLS: Asked for a client certificate")

					if daemonData.TlsClientPair == nil {
						return &tls.Certificate{}, nil
					}

					return daemonData.TlsClientPair, nil
				},
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					b.Trace("TLS: built-in cert verification finished (no-op in our config)")

					// TODO: should extract serving keys here, for purity
					// Also tbf we might not reach the next function if say alpn negotiation fails

					if len(verifiedChains) > 0 {
						panic("Shouldn't see this cause we set InsecureSkipVerify")
					}

					return nil
				},
				VerifyConnection: func(cs tls.ConnectionState) error {
					b.Trace("TLS: all cert verification finished")

					probeData.TlsAgreedVersion = cs.Version
					probeData.TlsAgreedCipherSuite = cs.CipherSuite
					// Would be nice to print the key exchange algo used but it's not available to us, and indeed all the code relating to it is non-exported from golang's crypto package
					probeData.TlsAgreedALPN = cs.NegotiatedProtocol
					probeData.TlsOCSPStapled = len(cs.OCSPResponse) > 0

					// Note that the Print() function verifies the certs we're presented against the CAs provided (or built-in)
					// This verification would normally happen automatically, and we'd be given these chains as args to VerifyPeerCertificate()
					// However a failed validation would cause client.Do() to return early with that error, and we want to carry on
					// This we set InsecureSkipVerify to stop the early bail out, and basically recreate the default checks ourselves
					// If caCert is nil ServingCertChainVerified() will use system roots to verify
					// TODO: verify servername == our requested sni.
					probeData.TlsServerCerts = cs.PeerCertificates

					return nil
				},
			},
			ForceAttemptHTTP2: !daemonData.HttpForce11, // Because we provide our own TLSClientConfig, golang defaults to no ALPN, we have to insist. Note that just setting TLSClientConfig.NextProtos isn't enough; this flag adds upgrade handler functions and other stuff
		},
	}

	// Assuming we don't want krb, just point to the non-spnego parts of the struct (hack)
	c := &http.Client{Transport: &tr.Transport}
	if daemonData.AuthKrb {
		c = &http.Client{Transport: tr}
	}

	// Really ugly that this can't be set in the literal (so that it can reference and reach into the client and mutate it)
	c.CheckRedirect = getCheckRedirect(s, b, daemonData, c)

	return c
}
