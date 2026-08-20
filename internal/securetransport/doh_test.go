// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
)

const relayName = "relay.example.com"

func TestResolveReturnsAddressesAndECHConfig(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	resolver, stub := newStubResolver(t, zone{
		ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 1, "", svcParam(svcParamECH, list)))},
		ask(relayName, typeA):     {answer(relayName, typeA, addressData(t, "203.0.113.10"))},
		ask(relayName, typeAAAA):  {answer(relayName, typeAAAA, addressData(t, "2606:4700::1111"))},
	})

	resolution, err := resolver.Resolve(context.Background(), relayName)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !resolution.HTTPSRecord {
		t.Error("the HTTPS record was not reported")
	}
	if !bytes.Equal(resolution.ECHConfig, list) {
		t.Error("the ECHConfigList was not returned")
	}
	if len(resolution.Addresses) != 2 {
		t.Fatalf("addresses = %v", resolution.Addresses)
	}
	if resolution.TTL == 0 {
		t.Error("no TTL was reported")
	}
	if asked := stub.questions(); len(asked) != 3 || asked[0].qtype != typeHTTPS {
		t.Errorf("questions = %+v, want HTTPS then A then AAAA", asked)
	}
}

// A name with no HTTPS record resolves, but reports that there is none: the
// dialer, not the resolver, decides that this ends a required-ECH tunnel.
func TestResolveWithoutAnHTTPSRecord(t *testing.T) {
	resolver, _ := newStubResolver(t, zone{
		ask(relayName, typeA): {answer(relayName, typeA, addressData(t, "203.0.113.10"))},
	})
	resolution, err := resolver.Resolve(context.Background(), relayName)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolution.HTTPSRecord || len(resolution.ECHConfig) != 0 {
		t.Errorf("resolution = %+v, want no HTTPS record", resolution)
	}
}

func TestResolveFollowsAnHTTPSAliasChain(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	resolver, _ := newStubResolver(t, zone{
		ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 0, "edge.example.net"))},
		ask("edge.example.net", typeHTTPS): {
			answer("edge.example.net", typeHTTPS, httpsData(t, 1, "", svcParam(svcParamECH, list))),
		},
		ask("edge.example.net", typeA): {answer("edge.example.net", typeA, addressData(t, "203.0.113.11"))},
	})
	resolution, err := resolver.Resolve(context.Background(), relayName)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(resolution.ECHConfig, list) {
		t.Error("the alias target's ECHConfigList was not used")
	}
	if len(resolution.Addresses) != 1 || resolution.Addresses[0].String() != "203.0.113.11" {
		t.Errorf("addresses = %v, want the alias target's", resolution.Addresses)
	}
}

func TestResolveRejectsHostileHTTPSAnswers(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	other := testECHConfigList(t, "elsewhere.example")

	cases := map[string]zone{
		"answer for a name that was not asked about": {
			ask(relayName, typeHTTPS): {answer("evil.example", typeHTTPS, httpsData(t, 1, ""))},
		},
		"ambiguous service records": {
			ask(relayName, typeHTTPS): {
				answer(relayName, typeHTTPS, httpsData(t, 1, "", svcParam(svcParamECH, list))),
				answer(relayName, typeHTTPS, httpsData(t, 1, "", svcParam(svcParamECH, other))),
			},
		},
		"ambiguous aliases": {
			ask(relayName, typeHTTPS): {
				answer(relayName, typeHTTPS, httpsData(t, 0, "one.example.net")),
				answer(relayName, typeHTTPS, httpsData(t, 0, "two.example.net")),
			},
		},
		"alias loop": {
			ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 0, "edge.example.net"))},
			ask("edge.example.net", typeHTTPS): {
				answer("edge.example.net", typeHTTPS, httpsData(t, 0, relayName)),
			},
		},
		"unexpected record type": {
			ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 1, "")), answer(relayName, typeA, addressData(t, "203.0.113.1"))},
		},
		"empty alias target": {
			ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 0, ""))},
		},
	}
	for description, records := range cases {
		t.Run(description, func(t *testing.T) {
			resolver, _ := newStubResolver(t, records)
			if _, err := resolver.Resolve(context.Background(), relayName); err == nil {
				t.Fatal("a hostile HTTPS answer was accepted")
			} else if reason := ReasonOf(err); reason != FailureHTTPSRecord {
				t.Errorf("reason = %s, want https-record", reason)
			}
		})
	}
}

func TestResolveAddressesFollowsCNAMEs(t *testing.T) {
	resolver, _ := newStubResolver(t, zone{
		ask(relayName, typeA): {
			answer(relayName, typeCNAME, mustName(t, "edge.example.net")),
			answer("edge.example.net", typeA, addressData(t, "203.0.113.12")),
		},
	})
	addresses, err := resolver.LookupAddresses(context.Background(), relayName)
	if err != nil {
		t.Fatalf("LookupAddresses: %v", err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("203.0.113.12") {
		t.Errorf("addresses = %v", addresses)
	}
}

// An answer that resolves a name the query did not reach is refused, not
// filtered: a response that answers questions of its own is not one to salvage.
func TestResolveRejectsHostileAddressAnswers(t *testing.T) {
	cases := map[string]zone{
		"address for an unrelated name": {
			ask(relayName, typeA): {answer("evil.example", typeA, addressData(t, "203.0.113.1"))},
		},
		"address record smuggled past a broken chain": {
			ask(relayName, typeA): {
				answer(relayName, typeCNAME, mustName(t, "edge.example.net")),
				answer("other.example.net", typeA, addressData(t, "203.0.113.1")),
			},
		},
		"ambiguous CNAME targets": {
			ask(relayName, typeA): {
				answer(relayName, typeCNAME, mustName(t, "one.example.net")),
				answer(relayName, typeCNAME, mustName(t, "two.example.net")),
			},
		},
		"CNAME loop": {
			ask(relayName, typeA): {
				answer(relayName, typeCNAME, mustName(t, "edge.example.net")),
				answer("edge.example.net", typeCNAME, mustName(t, relayName)),
			},
		},
		"AAAA answer to an A query": {
			ask(relayName, typeA): {answer(relayName, typeAAAA, addressData(t, "2606:4700::1"))},
		},
		"A record of the wrong length": {
			ask(relayName, typeA): {answer(relayName, typeA, []byte{203, 0, 113})},
		},
		"no address at all": {
			ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 1, ""))},
		},
	}
	for description, records := range cases {
		t.Run(description, func(t *testing.T) {
			resolver, _ := newStubResolver(t, records)
			if _, err := resolver.LookupAddresses(context.Background(), relayName); err == nil {
				t.Fatal("a hostile address answer was accepted")
			} else if reason := ReasonOf(err); reason != FailureDoH {
				t.Errorf("reason = %s, want doh", reason)
			}
		})
	}
}

func TestLookupAddressesSortsAndDeduplicates(t *testing.T) {
	resolver, _ := newStubResolver(t, zone{
		ask(relayName, typeA): {
			answer(relayName, typeA, addressData(t, "203.0.113.20")),
			answer(relayName, typeA, addressData(t, "203.0.113.10")),
			answer(relayName, typeA, addressData(t, "203.0.113.20")),
		},
	})
	addresses, err := resolver.LookupAddresses(context.Background(), relayName)
	if err != nil {
		t.Fatalf("LookupAddresses: %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.20")}
	if len(addresses) != len(want) || addresses[0] != want[0] || addresses[1] != want[1] {
		t.Errorf("addresses = %v, want %v", addresses, want)
	}
}

// The name is folded before it is asked, so a mixed-case destination resolves
// and its answers still compare equal.
func TestResolveFoldsTheQueriedName(t *testing.T) {
	resolver, stub := newStubResolver(t, zone{
		ask(relayName, typeA): {answer(relayName, typeA, addressData(t, "203.0.113.10"))},
	})
	if _, err := resolver.LookupAddresses(context.Background(), "Relay.Example.COM."); err != nil {
		t.Fatalf("LookupAddresses: %v", err)
	}
	if asked := stub.questions(); asked[0].name != relayName {
		t.Errorf("asked %q, want the folded name", asked[0].name)
	}
}

func TestQueryRejectsAnswersThatDoNotMatchTheQuestion(t *testing.T) {
	question := ask(relayName, typeA)
	records := []testAnswer{answer(relayName, typeA, addressData(t, "203.0.113.10"))}

	cases := map[string]func(id uint16, question dnsQuestion) *http.Response{
		"transaction ID does not match": func(id uint16, q dnsQuestion) *http.Response {
			return dnsResponse(buildResponse(t, responseOptions{id: id + 1, question: q, answers: records}))
		},
		"not marked as a response": func(id uint16, q dnsQuestion) *http.Response {
			return dnsResponse(buildResponse(t, responseOptions{id: id, question: q, answers: records, notAResponse: true}))
		},
		"truncated": func(id uint16, q dnsQuestion) *http.Response {
			return dnsResponse(buildResponse(t, responseOptions{id: id, question: q, answers: records, truncated: true}))
		},
		"server failure": func(id uint16, q dnsQuestion) *http.Response {
			return dnsResponse(buildResponse(t, responseOptions{id: id, question: q, rcode: 2}))
		},
		"different question echoed": func(id uint16, _ dnsQuestion) *http.Response {
			return dnsResponse(buildResponse(t, responseOptions{id: id, question: ask("evil.example", typeA), answers: records}))
		},
		"no question echoed": func(id uint16, q dnsQuestion) *http.Response {
			return dnsResponse(buildResponse(t, responseOptions{id: id, question: q, answers: records, omitQuestion: true}))
		},
		"wrong content type": func(id uint16, q dnsQuestion) *http.Response {
			response := dnsResponse(buildResponse(t, responseOptions{id: id, question: q, answers: records}))
			response.Header.Set("Content-Type", "text/html")
			return response
		},
		"HTTP error status": func(uint16, dnsQuestion) *http.Response {
			return &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
		},
		"body over the size limit": func(id uint16, q dnsQuestion) *http.Response {
			response := dnsResponse(buildResponse(t, responseOptions{id: id, question: q, answers: records}))
			response.Body = io.NopCloser(bytes.NewReader(make([]byte, dnsResponseLimit+1)))
			return response
		},
	}
	for description, reply := range cases {
		t.Run(description, func(t *testing.T) {
			resolver := newResolverWithStub(t, &dohStub{t: t, reply: reply})
			if _, err := resolver.LookupAddresses(context.Background(), question.name); err == nil {
				t.Fatal("a mismatched DoH answer was accepted")
			} else if reason := ReasonOf(err); reason != FailureDoH {
				t.Errorf("reason = %s, want doh", reason)
			}
		})
	}
}

// A resolver that answers with a redirect is a resolver that moved. Following
// it would hand resolution to whatever the redirect names.
func TestQueryRejectsARedirect(t *testing.T) {
	resolver := newResolverWithStub(t, &dohStub{t: t, reply: func(uint16, dnsQuestion) *http.Response {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://elsewhere.example/dns-query"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}
	}})
	_, err := resolver.LookupAddresses(context.Background(), relayName)
	if reason := ReasonOf(err); reason != FailureRedirect {
		t.Fatalf("reason = %s, want redirect", reason)
	}
}

func TestNewResolverRequiresBootstrapAddresses(t *testing.T) {
	endpoint, err := url.Parse("https://dns.example/dns-query")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = NewResolver(ResolverOptions{URL: endpoint, Timeouts: config.DefaultTimeouts()})
	if err == nil {
		t.Fatal("a resolver with no bootstrap address was built")
	}
	if !strings.Contains(err.Error(), "operating system resolver") {
		t.Errorf("err = %v, want it to name what it refuses to do", err)
	}
}

func TestNewResolverAcceptsAnIPLiteralEndpoint(t *testing.T) {
	endpoint, err := url.Parse("https://1.1.1.1/dns-query")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := NewResolver(ResolverOptions{URL: endpoint, Timeouts: config.DefaultTimeouts()}); err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
}

func TestNewResolverRejectsUndialableBootstrapAddresses(t *testing.T) {
	endpoint, err := url.Parse("https://dns.example/dns-query")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, address := range []string{"0.0.0.0", "224.0.0.1", "::"} {
		_, err := NewResolver(ResolverOptions{
			URL:       endpoint,
			Bootstrap: []netip.Addr{netip.MustParseAddr(address)},
			Timeouts:  config.DefaultTimeouts(),
		})
		if err == nil {
			t.Errorf("bootstrap address %s was accepted", address)
		}
	}
}

// The production transport dials the bootstrap addresses and ignores the
// address the HTTP transport computed from the URL. That is what makes an
// operating-system lookup unreachable: there is no code path where a name
// becomes an address outside the DoH exchange itself.
func TestDoHTransportIgnoresTheAddressItIsGiven(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	endpoint := netip.MustParseAddrPort(listener.Addr().String())

	url, err := url.Parse("https://dns.example:" + strconv.Itoa(int(endpoint.Port())) + "/dns-query")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	transport, err := newDoHTransport(ResolverOptions{
		URL:       url,
		Bootstrap: []netip.Addr{endpoint.Addr()},
		Timeouts:  config.DefaultTimeouts(),
	})
	if err != nil {
		t.Fatalf("newDoHTransport: %v", err)
	}
	if transport.Proxy != nil {
		t.Fatal("DoH transport inherited an HTTP proxy")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.TLSClientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("DoH TLS versions = %#x..%#x, want TLS 1.3 only",
			transport.TLSClientConfig.MinVersion, transport.TLSClientConfig.MaxVersion)
	}

	// A name that cannot resolve anywhere: if the dialer used it, this fails.
	conn, err := transport.DialContext(t.Context(), "tcp", "no-such-host.invalid:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got := conn.RemoteAddr().String(); got != endpoint.String() {
		t.Errorf("dialed %s, want the bootstrap address %s", got, endpoint)
	}
}

// Every bootstrap address is tried, so one unreachable edge does not end the
// tunnel before it starts.
func TestDoHTransportTriesEveryBootstrapAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	endpoint := netip.MustParseAddrPort(listener.Addr().String())

	url, err := url.Parse("https://dns.example:" + strconv.Itoa(int(endpoint.Port())) + "/dns-query")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	transport, err := newDoHTransport(ResolverOptions{
		URL: url,
		// Nothing listens on the first address, so the dial to it is
		// refused and the second one has to be tried.
		Bootstrap: []netip.Addr{netip.MustParseAddr("127.0.0.2"), endpoint.Addr()},
		Timeouts:  config.Timeouts{Dial: 200 * time.Millisecond, TLSHandshake: time.Second, Control: time.Second},
	})
	if err != nil {
		t.Fatalf("newDoHTransport: %v", err)
	}
	conn, err := transport.DialContext(t.Context(), "tcp", "no-such-host.invalid:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got := conn.RemoteAddr().String(); got != endpoint.String() {
		t.Errorf("dialed %s, want %s", got, endpoint)
	}
}
