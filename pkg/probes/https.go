package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/MarshallWace/go-spnego"

	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/print-cert/pkg/state"
)

func getCheckRedirect(s output.TtyStyler, b output.Bios, daemonData *state.DaemonData, c *http.Client) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		b.Banner("Redirect")

		fmt.Printf("Redirected to %s\n", s.Addr(req.URL.String()))

		b.Trace("Updating TLS ClientHello", "ServerName", req.URL.Host)
		getUnderlyingHttpTransport(c).TLSClientConfig.ServerName = req.URL.Host

		b.Trace("Updating HTTP request", "Host", req.URL.Host)
		req.Host = req.URL.Host

		DNSInfo(s, b, daemonData.Timeout, req.URL.Host)

		fmt.Println()

		return nil
	}
}

// GetPlaintextClient returns an HTTP Client for calling non-TLS endpoints.
// It prints lots of info along the way.
func GetPlaintextClient(s output.TtyStyler, b output.Bios, daemonData *state.DaemonData, probeData *state.ProbeData) *http.Client {
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

// GetTLSClient returns an HTTP Client for calling TLS-enabled endpoints.
// It prints lots of info along the way.
func GetTLSClient(
	s output.TtyStyler, b output.Bios,
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

// GetHTTPRequest returns an HTTP Request that can be used to call endpoints under test.
func GetHTTPRequest(
	s output.TtyStyler, b output.Bios,
	scheme string, addr net.IP, port uint64, path string,
	daemonData *state.DaemonData,
) (*http.Request, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), daemonData.Timeout)

	/* This is the URL we give to the HTTP client library. The "Host" part of the URL is just used as the connection address, and not seen on the other end */
	addrPort := net.JoinHostPort(addr.String(), strconv.FormatUint(port, 10))
	pathParts, err := url.Parse(path)
	b.CheckErr(err)
	l7Addr := url.URL{
		Scheme:   scheme,
		Host:     addrPort, // could leave off 80 or 443 but not an error to include them
		Path:     pathParts.EscapedPath(),
		RawQuery: pathParts.RawQuery,
		Fragment: pathParts.EscapedFragment(),
	}
	daemonData.HttpPath = &l7Addr

	req, err := http.NewRequestWithContext(ctx, daemonData.HttpMethod, daemonData.HttpPath.String(), nil)
	b.CheckErr(err)

	req.Host = daemonData.HttpHost
	req.Header.Add("user-agent", "print-cert TODO from build info")
	if daemonData.AuthBearerToken != "" {
		req.Header.Add("authorization", fmt.Sprintf("Bearer %s", daemonData.AuthBearerToken))
	}

	return req, cancel
}

// CheckTLS sends the given request using the given client.
// It prints information about what's returned.
func CheckTLS(
	s output.TtyStyler, b output.Bios,
	client *http.Client, req *http.Request,
	readBody bool, // performance optimisation
	probeData *state.ProbeData,
) {
	resp, err := client.Do(req)
	b.CheckErr(err)
	defer resp.Body.Close()

	probeData.HttpProto = resp.Proto
	probeData.HttpStatusCode = resp.StatusCode
	probeData.HttpStatusMessage = resp.Status
	probeData.HttpHeaders = resp.Header
	probeData.HttpContentLength = resp.ContentLength
	probeData.HttpCompressed = resp.Uncompressed

	if readBody {
		rawBody, err := io.ReadAll(resp.Body)
		b.CheckErr(err)
		probeData.BodyBytes = rawBody
	}
}

func getUnderlyingHttpTransport(client *http.Client) *http.Transport {
	switch c := client.Transport.(type) {
	case *http.Transport:
		return c
	case *spnego.Transport:
		return &c.Transport
	default:
		panic("Bottom")
	}
}
