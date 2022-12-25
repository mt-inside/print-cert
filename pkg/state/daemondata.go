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

	TlsEnabled    bool
	TlsServerName string
	TlsClientPair *tls.Certificate
	TlsServingCA  *x509.Certificate

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
