package state

import (
	"crypto/x509"
	"net"
	"time"
)

// TODO: some/all of these fields to be type Event{timestamp, value: T}
type ProbeData struct {
	TransportConnNo        uint
	TransportDialTime      *time.Time
	TransportConnTime      *time.Time
	TransportRemoteAddress net.Addr
	TransportLocalAddress  net.Addr

	TlsClientCertRequest bool

	TlsServerCerts []*x509.Certificate

	TlsAgreedTime        *time.Time
	TlsAgreedVersion     uint16
	TlsAgreedCipherSuite uint16
	TlsAgreedALPN        string
	TlsOCSPStapled       bool
}

func NewProbeData() *ProbeData {
	return &ProbeData{}
}
