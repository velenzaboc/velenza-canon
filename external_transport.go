package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"time"
)

type externalNetIPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type publicOnlyExternalDialer struct {
	resolver externalNetIPResolver
	dial     func(context.Context, string, string) (net.Conn, error)
}

func (d publicOnlyExternalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("external fetch dial address: %w", err)
	}
	if port != "443" {
		return nil, fmt.Errorf("external fetch port %q refused; canonical HTTPS requires 443", port)
	}
	if literal, literalErr := netip.ParseAddr(host); literalErr == nil {
		literal = literal.Unmap()
		if !externalFetchPublicIP(literal) {
			return nil, fmt.Errorf("external fetch literal host %q is a forbidden address", host)
		}
		return d.dial(ctx, network, net.JoinHostPort(literal.String(), port))
	}
	ips, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve external fetch host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve external fetch host %q: no addresses", host)
	}
	// Fail the whole answer set when any address is unsafe. Selecting only a
	// public member of a mixed result lets a rebinding/multi-answer hostname
	// retain an internal target for a later connection.
	for _, ip := range ips {
		if !externalFetchPublicIP(ip) {
			return nil, fmt.Errorf("external fetch host %q resolved to forbidden address %s", host, ip.String())
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
	// Dial the already-validated address, not the hostname. HTTP Transport
	// still uses the original URL hostname for Host and TLS SNI, while DNS
	// cannot be consulted again between policy check and connection.
	return d.dial(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

var externalFetchReservedPrefixes = []netip.Prefix{
	// IANA IPv4 Special-Purpose Address Space entries that are not globally
	// reachable, plus the retired 6to4 relay block. IsGlobalUnicast is
	// intentionally broader than public routability and therefore cannot be
	// the sole SSRF boundary.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// IANA IPv6 special-purpose entries inside the otherwise public 2000::/3
	// space. Translation/tunnelling prefixes are refused even where IANA
	// marks the outer prefix globally reachable: they can encode a forbidden
	// IPv4 destination and would bypass the IPv4 gate.
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var externalFetchIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

func externalFetchPublicIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	// RFC 4291/IANA allocate public IPv6 global unicast from 2000::/3. Go's
	// IsGlobalUnicast also returns true for reserved future-use space, so keep
	// the HTTP dial surface inside the allocated public envelope.
	if addr.Is6() && !externalFetchIPv6GlobalUnicast.Contains(addr) {
		return false
	}
	for _, prefix := range externalFetchReservedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func newBootstrapExternalHTTPClient() *http.Client {
	netDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	safeDialer := publicOnlyExternalDialer{
		resolver: net.DefaultResolver,
		dial:     netDialer.DialContext,
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:             nil,
		DialContext:       safeDialer.DialContext,
		ForceAttemptHTTP2: true,
		// ⛔ TLS 1.3 FLOOR, NOT 1.2. Below 1.3 there is no ML-KEM key-exchange group
		// at all — the hybrid groups exist only in 1.3 — so a 1.2 minimum is not a
		// weaker preference, it is a GUARANTEED classical-only key exchange whenever
		// the peer prefers one.
		//
		// The peer here is arbitrary, which puts this in the external-peer class
		// rather than the Velenza-operated one. That class permits a narrowed,
		// declared, attributable boundary; it does not permit a blanket floor drop
		// applied to every fetch, which is undeclared and unattributed by
		// construction. CurvePreferences is deliberately left unset: Go offers
		// X25519MLKEM768 by default, and pinning a list here would silently DISABLE
		// post-quantum key exchange if the constant ever moved.
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}, Timeout: 30 * time.Second}
}
