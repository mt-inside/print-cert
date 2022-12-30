package state

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/mt-inside/http-log/pkg/codec"
	"github.com/mt-inside/http-log/pkg/output"
	"github.com/mt-inside/print-cert/pkg/utils"
)

type RequestData struct {
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

func RequestDataFromViper(s output.TtyStyler, b output.Bios, target string, port uint64, dnsResolverName string) *RequestData {
	requestData := &RequestData{}

	requestData.Timeout = viper.GetDuration("timeout")
	requestData.DnsSystemResolver = dnsResolverName

	// HTTP/1.1 Host. Either:
	// - explicitly given value, or
	// - connection target, be that name or IP, with non-standard ports appended
	requestData.HttpHost = viper.GetString("host")
	if requestData.HttpHost == "" {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
		if port == 80 || port == 443 {
			requestData.HttpHost = target // my reading of the spec is that it's not an error to include 80 or 443 but I can imagine some servers getting confused
		} else {
			requestData.HttpHost = net.JoinHostPort(target, strconv.FormatUint(port, 10))
		}
	}

	// TLS SNI ServerName field. Optional.
	requestData.TlsServerName = viper.GetString("sni")
	if requestData.TlsServerName != "" {
		if !utils.ServerNameConformant(requestData.TlsServerName) {
			b.PrintErr("SNI ServerName cannot be an IP or contain a port number. Ignoring supplied value.")
			requestData.TlsServerName = ""
		}
	}
	if requestData.TlsServerName == "" {
		requestData.TlsServerName = viper.GetString("host")
		if requestData.TlsServerName != "" {
			if !utils.ServerNameConformant(requestData.TlsServerName) {
				requestData.TlsServerName = ""
			}
		}
	}
	if requestData.TlsServerName == "" {
		requestData.TlsServerName = target
		if requestData.TlsServerName != "" {
			if !utils.ServerNameConformant(requestData.TlsServerName) {
				requestData.TlsServerName = ""
			}
		}
	}

	// Name to validate received certs against - fall back some non-empty string, even if it is an IP
	requestData.TlsValidateName = requestData.TlsServerName
	if requestData.TlsValidateName == "" {
		requestData.TlsValidateName = target
	}

	requestData.TlsEnabled = !viper.GetBool("no-tls")
	requestData.HttpMethod = "GET"

	requestData.AuthKrb = viper.GetBool("kerberos")
	requestData.HttpForce11 = viper.GetBool("http-11")

	/* Load TLS material */

	if viper.Get("cert") != "" || viper.Get("key") != "" {
		pair, err := tls.LoadX509KeyPair(viper.Get("cert").(string), viper.Get("key").(string))
		b.CheckErr(err)
		requestData.TlsClientPair = &pair
	}

	if viper.Get("ca") != "" {
		bytes, err := os.ReadFile(viper.Get("ca").(string))
		b.CheckErr(err)
		requestData.TlsServingCA, err = codec.ParseCertificate(bytes)
		b.CheckErr(err)
	}

	/* Load other request files */

	if viper.Get("bearer") != "" {
		bytes, err := os.ReadFile(viper.Get("bearer").(string))
		b.CheckErr(err)
		requestData.AuthBearerToken = strings.TrimSpace(string(bytes))
	}

	return requestData
}
