package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/MarshallWace/go-spnego"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/output"
)

func buildTlsClient(
	s output.TtyStyler,
	b bios.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) *http.Client {

	/* On the order of these callbacks:
	* TLS1.3 handshake is (https://www.ibm.com/docs/en/sdk-java-technology/8?topic=handshake-tls-13-protocol)
	 * -> ClientHello (supported versions etc)
	 * <- ServerHello (supported versions etc)
	 * <- CertificateRequest
	 * <- Serving Certificate
	 * -> Client Certificate
	 *
	 * Note that although the server sends the cert request before the serving cert, the client waits for both before sending in the client cert.
	 * Golang seems to reliably call the callbacks in the following valid, but counter-intuative way:
	 * - Serving Certificate - do you wanna object?
	 * - Verify Connection - do you wanna object to things like symmetric cypher suite and ALPN protocol? I guess these values come from looking at Client+ServerHello, and don't depend on the client cert. It'll be cheaper to work out these set intersections than the send the client cert over the network, so Go seems to ask for confirmation of them first.
	 * - Client Certificate Request - this happens last, see above. At this point we've agreed connection params that /would/ be used, but that's nothing sensitive. Now we give the server a chance to reject our auth and abort the handshake.
	 * - Finished - no hook for this, not sure there's even an ack
	*/

	tlsConfig := tls.Config{
		// Note that the Print() function verifies the certs we're presented against the CAs provided (or built-in)
		// This verification would normally happen automatically, and we'd be given these chains as args to VerifyPeerCertificate()
		// However a failed validation would cause client.Do() to return early with that error, and we want to carry on
		// Thus we set InsecureSkipVerify to stop the early bail out, and basically recreate the default checks ourselves
		InsecureSkipVerify: true, // deliberate
		Renegotiation:      tls.RenegotiateOnceAsClient,
		ServerName:         rtData.TlsServerName, // SNI for TLS vhosting
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			responseData.TlsClientCertRequestTime = time.Now()
			responseData.TlsClientCertRequest = true
			log.Info("Asked for a client certificate")

			if requestData.TlsClientPair == nil {
				// No error but an empty Certificate.Certificate means we won't send a client cert. If this is unacceptable to the server, it'll abort the handshake.
				return &tls.Certificate{}, nil
			}

			return requestData.TlsClientPair, nil
		},
		// I think this func is
		// - Called when we receive the serving certs
		// - Library has already done basic validation like expiration checks
		// - Library has also checked them against the CA(s), and provided verified chains back to those roots of trust
		// - But, because we set InsecureSkipVerify, we'll always get here.
		// - By the same token, verifiedChains is always empty (we manually call that validation function later, when it wouldn't cause a connection abort)
		// - We're asked to give any other opinions on them
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			responseData.TlsServerCertsTime = time.Now()
			log.Info("Built-in cert verification finished (no-op)")

			// For maximum purity we'd save the presented certs in this callback, but
			// - a) we'd have to parse them ourselves, and idk how much nuance there is in that, and
			// - b) I don't think it's ever the case that we'd reach here but not the next callback (maybe if they fail to negotiate ALPN or summat)

			if len(verifiedChains) > 0 {
				panic("Shouldn't see this cause we set InsecureSkipVerify")
			}

			return nil
		},
		// I think this func is
		// - One last chance to reject the connection
		// - I think all cert checking can be done above, so this is about objecting to the negotiated ALPN protocol or cypher suite or whatever
		VerifyConnection: func(cs tls.ConnectionState) error {
			log.Info("Connection parameter validation")

			// In the case of a handshake error, depending on where the server bails, none, some, or all of these callbacks get called
			// No "tls code" is handed an error; http::Client.Do is given one, so we have to infer things from what's called
			// Eg it's possible for this to be called and have every field be valid, but still not complete handshake
			// Or it's possible for even the first callback to never even be called

			responseData.TlsAgreedVersion = cs.Version
			responseData.TlsAgreedCipherSuite = cs.CipherSuite
			// Would be nice to print the key exchange algo used but it's not available to us, and indeed all the code relating to it is non-exported from golang's crypto package
			responseData.TlsAgreedALPN = cs.NegotiatedProtocol
			responseData.TlsOCSPStapled = len(cs.OCSPResponse) > 0

			responseData.TlsServerCerts = cs.PeerCertificates
			if rtData.TlsServerName != "" && cs.ServerName != rtData.TlsServerName {
				// TODO: to responseData - acutally, check & print this in responseData::Print
				b.PrintErr("TLS handshake's ServerName " + cs.ServerName + " does not equal requested " + rtData.TlsServerName)
			}
			responseData.TlsServerName = cs.ServerName

			return nil
		},
	}

	// Always make a krb transport, becuase if we make a plain HTTP one and try to wrap it later, we have to copy the bytes (because spnego.Transport embeds http.Transport) and that copies a sync.Mutex.
	h2 := &spnego.Transport{
		NoCanonicalize: true,
		// http.Client types this as iface http.RoundTripper, but this wants an http.Transport (because it embeds it)
		Transport: http.Transport{
			DialContext:           getDialContext(s, b, requestData, responseData),
			TLSHandshakeTimeout:   requestData.Timeout, // assume this is just the TLS handshake ie tcp handshake is covered by the dialer
			ResponseHeaderTimeout: requestData.Timeout,
			DisableCompression:    true,
			TLSClientConfig:       &tlsConfig,
			ForceAttemptHTTP2:     !requestData.HttpForce11, // Because we provide our own TLSClientConfig, golang defaults to sending empty ALPN (which will result in h1.1). Setting this to true sends ALPN ["h2, "http/1.1"]. Note that just setting TLSClientConfig.NextProtos isn't enough; this flag adds upgrade handler functions and other stuff
		},
	}
	// Assuming we don't want krb, just point to the non-spnego parts of the struct (hack)
	var tr http.RoundTripper = &h2.Transport
	if requestData.AuthKrb {
		tr = h2
	}

	if requestData.HttpForce3 {
		tr = &http3.RoundTripper{
			DisableCompression: true,
			TLSClientConfig:    &tlsConfig,
			QUICConfig: &quic.Config{
				Tracer: func(ctx context.Context, perspective logging.Perspective, connId quic.ConnectionID) *logging.ConnectionTracer {
					return newTracer(s, b, responseData)
				},
			},
			// No need to override the Dialer, becuase we have the Tracer (but it looks like it can be done by giving a Dial(), which calls quic.DialAddrEarly and inspects the resulting quic.EarlyConnection)
		}
	}

	c := &http.Client{Transport: tr}

	// Really ugly that this can't be set in the literal (so that it can reference and reach into the client and mutate it)
	c.CheckRedirect = getCheckRedirect(s, b, requestData, responseData)

	return c
}
