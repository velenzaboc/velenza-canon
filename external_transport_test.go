package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

type fixedExternalResolver struct {
	ips []netip.Addr
	err error
}

func (r fixedExternalResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.ips...), r.err
}

func TestExternalFetchPublicIPRejectsNonPublicRanges(t *testing.T) {
	for _, literal := range []string{
		"0.0.0.0", "0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.0.0.9", "192.88.99.2", "192.168.0.1", "198.18.0.1", "224.0.0.1",
		"240.0.0.1", "255.255.255.255", "::", "::1", "64:ff9b::a00:1", "100::1", "2001::1",
		"2001:db8::1", "2002:a00:1::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff02::1",
	} {
		t.Run(literal, func(t *testing.T) {
			if externalFetchPublicIP(netip.MustParseAddr(literal)) {
				t.Fatalf("non-public address %s accepted", literal)
			}
		})
	}
	if !externalFetchPublicIP(netip.MustParseAddr("8.8.8.8")) || !externalFetchPublicIP(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("known public unicast address rejected")
	}
}

func TestPublicOnlyExternalDialerPinsValidatedAddressAndRejectsMixedAnswers(t *testing.T) {
	var dialed string
	dialSentinel := errors.New("dial sentinel")
	dialer := publicOnlyExternalDialer{
		resolver: fixedExternalResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, dialSentinel
		},
	}
	_, err := dialer.DialContext(context.Background(), "tcp", "docs.example:443")
	if !errors.Is(err, dialSentinel) || dialed != "8.8.8.8:443" {
		t.Fatalf("pinned dial err=%v address=%q", err, dialed)
	}

	dialed = ""
	dialer.resolver = fixedExternalResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("169.254.169.254")}}
	_, err = dialer.DialContext(context.Background(), "tcp", "metadata-rebind.example:443")
	if err == nil || !strings.Contains(err.Error(), "forbidden address") || dialed != "" {
		t.Fatalf("mixed public/private DNS answer err=%v dialed=%q", err, dialed)
	}

	_, err = dialer.DialContext(context.Background(), "tcp", "docs.example:8443")
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("non-443 port accepted: %v", err)
	}

	dialed = ""
	dialer.resolver = fixedExternalResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	_, err = dialer.DialContext(context.Background(), "tcp", "0.0.0.1:443")
	if err == nil || !strings.Contains(err.Error(), "literal host") || dialed != "" {
		t.Fatalf("forbidden literal reached resolver/dial path: err=%v dialed=%q", err, dialed)
	}
	_, err = dialer.DialContext(context.Background(), "tcp", "[2002:a00:1::1]:443")
	if err == nil || !strings.Contains(err.Error(), "literal host") || dialed != "" {
		t.Fatalf("forbidden IPv6 tunnel literal reached dial path: err=%v dialed=%q", err, dialed)
	}
}

// ⛔ THE EXTERNAL-REFERENCE FETCHER MAY NOT PERMIT A SUB-TLS-1.3 HANDSHAKE.
// BELOW TLS 1.3 THERE IS NO ML-KEM GROUP AT ALL — the hybrid groups exist only in
// 1.3 — so a MinVersion of TLS 1.2 is not a weaker preference, it is a GUARANTEED
// classical-only key exchange whenever the peer prefers one.
//
// The peer here is arbitrary, so this is the external-peer class rather than a
// Velenza-operated endpoint. That class permits a narrowed, declared, attributable
// boundary — it does NOT permit a blanket floor drop applied to every fetch. A
// process-wide TLS 1.2 minimum is exactly the undeclared, unattributed downgrade
// the boundary rule exists to prevent, and it is indistinguishable on the wire from
// an intentional one.
//
// Note this is not merely "the Go default": Go's client default minimum is already
// TLS 1.2, so writing it explicitly documents an intent to accept 1.2 rather than
// inheriting it. Raising it to 1.3 removes the guaranteed-classical path.
func TestBootstrapExternalHTTPClientRefusesSubTLS13(t *testing.T) {
	client := newBootstrapExternalHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport is %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil; the external fetcher must pin its own floor rather than inherit one")
	}
	if got := transport.TLSClientConfig.MinVersion; got != tls.VersionTLS13 {
		t.Fatalf("external fetcher MinVersion = %#x, want TLS 1.3 (%#x) — below 1.3 no ML-KEM group exists, so this is a guaranteed classical-only key exchange", got, tls.VersionTLS13)
	}
}
