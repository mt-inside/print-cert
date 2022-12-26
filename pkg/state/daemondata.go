package state

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"time"
)

type DaemonData struct {
	Timeout time.Duration

	DnsSystemResolver string

	TlsEnabled bool
	// Name to send for SNI, might be empty
	TlsServerName string
	// Name to validate presented certs against, shouldn't be empty
	TlsValidateName string
	TlsClientPair   *tls.Certificate
	TlsServingCA    *x509.Certificate

	HttpHost    string
	HttpMethod  string
	HttpPath    *url.URL
	HttpForce11 bool

	AuthKrb         bool
	AuthBearerToken string
}

func NewDaemonData() *DaemonData {
	return &DaemonData{}
}
