//go:build cgo && !netgo

package probes

/* Seems to be no way to directly detect which resolution functions we'll end up using.
* Have to do our best to reproduce the linker's logic.
* My understanding: we'll use libc iff cgo is in use and the netgo flag hasn't been explicity set.
* Note: just checking the netgo flag is insufficient; it's not set by CGO_ENABLED=0
*
*         netgo  !netgo
* cgo     g      c
* !cgo    g      g
*
* (g == Go, c - libC)
 */

const DnsResolverName = "CGO (system's libc's getaddrinfo(), which will honour nsswitch config)"
