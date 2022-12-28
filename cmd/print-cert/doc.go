/* Draft docs:
*
* CONNECTION
* Logic flow
* * The TCP connection is made to `target`
*   * If that's an IP, it's used as-is
*   * If it's a name, it's resolved with the Go std library (qv). The first resulting IP is used (and printed, so you're sure which one)
* * If `--host` is specified, that value is used for the HTTP `Host` / h2 `:authority` header
*   * `Host` is mandatory in HTTP/1.1 onwards
*   * If it's not given, `target` is used as the Host (both names and IPs are valid Host header values). Per the spec, the port is appended if it's not 80 or 443
*   * Setting `--host` never has any effect on the connection target
* * If `--sni` is specified, that value is used for the TLS SNI `ServerName` field
*   * If it's not given, `--host` (or if that's empty too, _target_) is used if it's a valid _ServerName_; they must be names, not IPs, and not have a port
*   * `ServerName` is optional, so if no suitable value can be found for it, it's not sent.
* This logic gives ergonomic default behaviour: a hostname target (eg `google.com`) is called after being resolved in the normal way, and is used as the `Host` header and `ServerName`, as you probably want.
* However you have full control should you need it.
* A common use-case is giving an IP as _target_ (a new server / load balancer / reverse proxy) and setting `--host` and `--sni` to test its behaviour before pointing prod DNS as it.
*
* DNS
* Ultimately, an IP is needed to which to connect.
* _target_ determins this; `--host` and `--sni` have no effect.
* If an IP is given for _target_, it's used as-is.
* If a name is given, it's resolved using the Go standard library, and the first result is used.
* * This is what the Go HTTP library would do anyway, but we do it manually so that we can print all the other results too.
* * The Go std library might not resolve DNS the way you expect, or the same way as curl/wget/a C programme/a Java programme/etc. If in doubt, supply an IP directly
* * Of particular note is whether Go is using its own native-Go resolution code, or libc's `getaddrinfo()` via _CGO_. The details are complicated, but some pertinant info
*   * Go-native only looks in DNS, and `/etc/hosts`, but not NIS/LDAP/etc. It can't parse all `/etc/resolv.conf` options. It doesn't check _dnssec_ so won't filter out results with invalid signatures
*   * CGO is at the whim of `nsswitch.conf` etc etc
* * `print-cert` prints which resolver the std library is using
* Additionally, if `dns-full` is requested, another set of "manual" resolutions is done, tracing recursive resolution, showing _dnssec_ info, and so on
* * This is purely informative. It's code I wrote in `print-cert` that may not be correct, and certainly won't handle all cases. It may give no answer, or a different one to the Go std library's resolver.
* * The Go std lib's answer is always used for the actual connection
 */
package main
