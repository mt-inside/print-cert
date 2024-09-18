package state

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"

	hlutils "github.com/mt-inside/http-log/pkg/utils"

	"github.com/mt-inside/print-cert/internal/build"
	"github.com/mt-inside/print-cert/pkg/utils"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
)

type RequestData struct {
	Timeout         time.Duration
	FollowRedirects bool

	// TODO: this should be on the other structure? Or just read straight from  the const tbh
	DnsSystemResolver string

	TlsClientPair *tls.Certificate
	TlsServingCAs []*x509.Certificate

	HttpMethod  string
	HttpForce11 bool
	HttpForce3  bool // Necessarily forces QUIC too. h2 can also run over QUIC, but that's not supported by the library we use, so the two are coupled

	AuthKrb         bool
	AuthBasic       string
	AuthBearerToken string

	BodyReader   io.Reader
	ExtraHeaders map[string]string
}

func RequestDataFromViper(s output.TtyStyler, b bios.Bios, dnsResolverName string) *RequestData {
	requestData := &RequestData{
		Timeout:           viper.GetDuration("timeout"),
		FollowRedirects:   viper.GetBool("location"),
		DnsSystemResolver: dnsResolverName,
		HttpMethod:        viper.GetString("method"),
		HttpForce11:       viper.GetBool("http-11"),
		HttpForce3:        viper.GetBool("http-3"),
		AuthKrb:           viper.GetBool("auth-kerberos"),
		ExtraHeaders:      map[string]string{},
	}

	/* Load TLS material */

	if viper.GetString("cert") != "" || viper.GetString("key") != "" {
		pair, err := tls.LoadX509KeyPair(viper.GetString("cert"), viper.GetString("key"))
		b.Unwrap(err)
		requestData.TlsClientPair = &pair
	}
	if requestData.TlsClientPair == nil && viper.GetString("tls-algo") != "" {
		var err error
		ca, err := hlutils.GenSelfSignedCa(context.Background(), viper.GetString("tls-algo"), build.Name)
		b.Unwrap(err)
		requestData.TlsClientPair, err = hlutils.GenClientCert(context.Background(), build.Name, ca, viper.GetString("tls-algo"), build.Name)
		b.Unwrap(err)
	}

	for _, caPath := range viper.GetStringSlice("ca") {
		bytes, err := os.ReadFile(caPath)
		b.Unwrap(err)
		ca, err := codec.ParseCertificate(bytes)
		b.Unwrap(err)
		requestData.TlsServingCAs = append(requestData.TlsServingCAs, ca)
	}

	/* Load other request files */

	if viper.GetString("auth-basic") != "" {
		// User is expected to provide bob:password
		requestData.AuthBasic = strings.TrimSpace(viper.GetString("auth-basic"))
	}

	if viper.GetString("auth-bearer") != "" {
		bytes, err := os.ReadFile(viper.GetString("auth-bearer"))
		b.Unwrap(err)
		requestData.AuthBearerToken = strings.TrimSpace(string(bytes))
	}

	/* Request body */
	if viper.GetString("req-body") != "" {
		requestData.BodyReader = strings.NewReader(viper.GetString("req-body"))
	}

	/* Request headers */
	for _, kv := range viper.GetStringSlice("req-header") {
		pair := strings.Split(kv, "=")
		if len(pair) != 2 {
			b.PrintWarn("Invalid format for --req-header")
		} else {
			requestData.ExtraHeaders[pair[0]] = pair[1]
		}
	}

	return requestData
}

type RoundTripData struct {
	TransportTarget string // addr[:port], where addr is name or IP

	TlsEnabled bool
	// Name to send for SNI, might be empty
	TlsServerName string
	// Name to validate presented certs against, shouldn't be empty
	TlsValidateName string

	HttpHost string
	HttpPath *url.URL
}

func DeriveRoundTripData(s output.TtyStyler, b bios.Bios, target, host, sni, path string, tls bool) *RoundTripData {
	rtd := &RoundTripData{}

	rtd.TransportTarget = target

	// HTTP/1.1 Host. Either:
	// - explicitly given value, or
	// - connection target, be that name or IP, with non-standard ports appended
	rtd.HttpHost = host
	if rtd.HttpHost == "" {
		rtd.HttpHost = target
		// TODO: drop 80/443 suffix
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
	}

	pathParts, err := url.Parse(path)
	b.Unwrap(err)
	rtd.HttpPath = pathParts

	rtd.TlsEnabled = tls

	// TLS SNI ServerName field.
	rtd.TlsServerName = "" // Field is optional
	if utils.ServerNameConformant(sni) {
		rtd.TlsServerName = sni
	}
	if rtd.TlsServerName == "" && utils.ServerNameConformant(rtd.HttpHost) {
		rtd.TlsServerName = rtd.HttpHost
	}

	// Name to validate received certs against - fall back some non-empty string, even if it is an IP
	rtd.TlsValidateName = rtd.TlsServerName
	if rtd.TlsValidateName == "" {
		rtd.TlsValidateName = rtd.HttpHost
	}

	return rtd
}
