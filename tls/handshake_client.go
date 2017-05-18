package tls

import (
	"net"
	"strings"
)

// hostnameInSNI converts name into an approriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See https://tools.ietf.org/html/rfc6066#section-3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
