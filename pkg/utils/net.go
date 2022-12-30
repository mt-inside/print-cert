package utils

import "net"

// RFC 6066 §3 (https://www.rfc-editor.org/rfc/rfc6066)
// - DNS names only
// - No ports
// - No literal IPs
// Thus either:
// - explicitly given value, if conformant
// - HTTP Host value (ie explicit or target), if conformant
func ServerNameConformant(sn string) bool {
	// No IPs
	if ip := net.ParseIP(sn); ip != nil {
		return false
	}
	// No ports
	if _, _, err := net.SplitHostPort(sn); err == nil {
		return false
	}
	return true
}
