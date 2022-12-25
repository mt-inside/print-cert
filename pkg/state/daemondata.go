package state

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

type DaemonData struct {
	Timeout time.Duration

	TlsServerName string
	TlsClientPair *tls.Certificate
	TlsServingCA  *x509.Certificate

	HttpHost    string
	HttpPath    string
	HttpForce11 bool

	AuthKrb         bool
	AuthBearerToken string
}

func NewDaemonData() *DaemonData {
	return &DaemonData{}
}
