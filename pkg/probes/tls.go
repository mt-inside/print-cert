package probes

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/MarshallWace/go-spnego"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/output"
)

func buildTlsClient(
	s output.TtyStyler,
	b output.Bios,
	requestData *state.RequestData,
	rtData *state.RoundTripData,
	responseData *state.ResponseData,
) *http.Client {

	// Always make a krb transport, becuase if we make a plain HTTP one and try to wrap it later, we have to copy the bytes (because spnego.Transport embeds http.Transport) and that copies a sync.Mutex.
	tr := &spnego.Transport{
		NoCanonicalize: true,
		Transport: http.Transport{
			DialContext:           getDialContext(s, b, requestData, responseData),
			TLSHandshakeTimeout:   requestData.Timeout, // assume this is just the TLS handshake ie tcp handshake is covered by the dialer
			ResponseHeaderTimeout: requestData.Timeout,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				// Note that the Print() function verifies the certs we're presented against the CAs provided (or built-in)
				// This verification would normally happen automatically, and we'd be given these chains as args to VerifyPeerCertificate()
				// However a failed validation would cause client.Do() to return early with that error, and we want to carry on
				// Thus we set InsecureSkipVerify to stop the early bail out, and basically recreate the default checks ourselves
				InsecureSkipVerify: true, // deliberate
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         rtData.TlsServerName, // SNI for TLS vhosting
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					responseData.TlsClientCertRequest = true
					b.TraceWithName("tls", "Asked for a client certificate")

					if requestData.TlsClientPair == nil {
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
					b.TraceWithName("tls", "Built-in cert verification finished (no-op)")

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
					b.TraceWithName("tls", "Handshake complete")

					responseData.TlsAgreedVersion = cs.Version
					responseData.TlsAgreedCipherSuite = cs.CipherSuite
					// Would be nice to print the key exchange algo used but it's not available to us, and indeed all the code relating to it is non-exported from golang's crypto package
					responseData.TlsAgreedALPN = cs.NegotiatedProtocol
					responseData.TlsOCSPStapled = len(cs.OCSPResponse) > 0

					// TODO: verify servername == our requested sni.
					responseData.TlsServerCerts = cs.PeerCertificates
					if rtData.TlsServerName != "" && cs.ServerName != rtData.TlsServerName {
						b.PrintErr("TLS handshake's ServerName " + cs.ServerName + " does not equal requested " + rtData.TlsServerName)
					}
					responseData.TlsServerName = cs.ServerName

					return nil
				},
			},
			ForceAttemptHTTP2: !requestData.HttpForce11, // Because we provide our own TLSClientConfig, golang defaults to no ALPN, we have to insist. Note that just setting TLSClientConfig.NextProtos isn't enough; this flag adds upgrade handler functions and other stuff
		},
	}

	// Assuming we don't want krb, just point to the non-spnego parts of the struct (hack)
	c := &http.Client{Transport: &tr.Transport}
	if requestData.AuthKrb {
		c = &http.Client{Transport: tr}
	}

	// Really ugly that this can't be set in the literal (so that it can reference and reach into the client and mutate it)
	c.CheckRedirect = getCheckRedirect(s, b, requestData, responseData)

	return c
}
