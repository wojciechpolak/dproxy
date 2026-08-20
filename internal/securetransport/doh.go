// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
)

// The remote's destination policy resolves through this type, so the one rule
// about how a name becomes an address has one implementation.
var _ policy.Resolver = (*Resolver)(nil)

// Resolver is the in-process DoH resolver. It is the only way either dproxy
// role turns a name into an address: there is no OS-DNS fallback, and no code
// path here reaches net.Resolver, so a failure ends the tunnel instead of
// leaking a plaintext query.
//
// The client resolves the relay hostname with it; the remote resolves the
// destination, which is why it also satisfies policy.Resolver.
type Resolver struct {
	endpoint  string
	client    *http.Client
	timeout   time.Duration
	aliasHops int
}

// aliasHopLimit bounds an alias or CNAME chain. A chain is also refused when
// it revisits a name, so this bounds the honest-but-long case.
const aliasHopLimit = 8

// dnsResponseLimit bounds a DoH response body before it is parsed.
const dnsResponseLimit = dnsMessageLimit

// ResolverOptions configures a resolver.
type ResolverOptions struct {
	// URL is the DoH endpoint. It must be https with a canonical path.
	URL *url.URL
	// Bootstrap are the addresses the endpoint is dialed at. They exist
	// because resolving the resolver's own name is the one lookup DoH
	// cannot perform: without them the process would have to ask the
	// operating system, which is exactly what dproxy must never do.
	//
	// It may be empty only when the endpoint is an IP literal.
	Bootstrap []netip.Addr
	// Timeouts bounds the dial, the handshake, and one query.
	Timeouts config.Timeouts
	// roundTripper replaces the production HTTPS transport in tests, so the
	// resolution logic can be exercised over canned wire messages without a
	// network. Production leaves it nil.
	roundTripper http.RoundTripper
}

// NewResolver builds a resolver. It fails rather than defaulting: a resolver
// that cannot be reached without the OS resolver is a configuration error, not
// something to discover at the first query.
func NewResolver(options ResolverOptions) (*Resolver, error) {
	if options.URL == nil {
		return nil, errors.New("DoH URL is required")
	}
	endpoint := options.URL.String()
	timeout := options.Timeouts.Control
	if timeout <= 0 {
		timeout = config.DefaultTimeouts().Control
	}
	resolver := &Resolver{endpoint: endpoint, timeout: timeout, aliasHops: aliasHopLimit}
	if options.roundTripper != nil {
		resolver.client = &http.Client{
			Transport:     options.roundTripper,
			CheckRedirect: refuseRedirect,
		}
		return resolver, nil
	}
	transport, err := newDoHTransport(options)
	if err != nil {
		return nil, err
	}
	resolver.client = &http.Client{Transport: transport, CheckRedirect: refuseRedirect}
	return resolver, nil
}

// refuseRedirect stops the client from following a redirect. A resolver that
// moved is a resolver that must be reconfigured, not one to follow.
func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// newDoHTransport builds the HTTPS transport for the resolver endpoint.
//
// The endpoint's own SNI is visible: it has no HTTPS record dproxy could have
// fetched without a resolver. That is acceptable and unrelated to the guarantee
// dproxy makes — a shared public resolver's name says nothing about which relay
// or which provider this process talks to.
func newDoHTransport(options ResolverOptions) (*http.Transport, error) {
	host := options.URL.Hostname()
	port := options.URL.Port()
	if port == "" {
		port = "443"
	}
	addresses := append([]netip.Addr(nil), options.Bootstrap...)
	if literal, err := netip.ParseAddr(host); err == nil && len(addresses) == 0 {
		addresses = []netip.Addr{literal}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf(
			"DoH endpoint %s has no bootstrap addresses; dproxy will not ask the operating system resolver for one (--doh-bootstrap)",
			host)
	}
	for _, address := range addresses {
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("bootstrap address %s is not dialable", address)
		}
	}
	timeouts := options.Timeouts
	if timeouts.Dial <= 0 || timeouts.TLSHandshake <= 0 {
		timeouts = config.DefaultTimeouts()
	}
	dialer := &net.Dialer{Timeout: timeouts.Dial}
	var next atomic.Uint32
	return &http.Transport{
		// Proxy is nil deliberately: dproxy is what HTTPS_PROXY points at,
		// and routing its own resolver through itself would be a loop.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The address the transport computed from the URL is ignored:
			// no code path may turn the endpoint name back into a lookup.
			start := int(next.Add(1) - 1)
			var failures []error
			for i := range addresses {
				address := addresses[(start+i)%len(addresses)]
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
				if err == nil {
					return conn, nil
				}
				failures = append(failures, err)
			}
			return nil, errors.Join(failures...)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			ServerName: host,
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeouts.TLSHandshake,
		ResponseHeaderTimeout: timeouts.Control,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   2,
	}, nil
}

// Resolution is what the relay hostname resolved to: the addresses to dial and
// the ECHConfigList to encrypt the ClientHello under.
type Resolution struct {
	// Addresses are the resolved addresses, sorted and deduplicated. They
	// have not been classified; the caller applies the address policy.
	Addresses []netip.Addr
	// ECHConfig is the ECHConfigList from the HTTPS record, or nil when the
	// name published none.
	ECHConfig []byte
	// HTTPSRecord reports whether an HTTPS service record was found at all,
	// so "no record" and "a record without ECH" can be told apart.
	HTTPSRecord bool
	// TTL is the smallest TTL behind the answer.
	TTL time.Duration
}

// LookupAddresses resolves a hostname to addresses. It implements
// policy.Resolver, which is what the remote uses to resolve a destination.
//
// The addresses are returned unclassified: policy.Checker applies the
// non-public-address rule, so one implementation of that rule serves both
// roles.
func (r *Resolver) LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	addresses, _, err := r.resolveAddresses(ctx, canonicalDNSName(host), 0, map[string]bool{})
	return addresses, err
}

// Resolve performs the complete client-side resolution of the relay hostname:
// the HTTPS record for its ECHConfigList, then the addresses of whatever that
// record pointed at.
func (r *Resolver) Resolve(ctx context.Context, host string) (*Resolution, error) {
	host = canonicalDNSName(host)
	record, err := r.resolveHTTPS(ctx, host, 0, map[string]bool{})
	if err != nil {
		return nil, err
	}
	resolution := &Resolution{}
	addressHost := host
	if record != nil {
		resolution.HTTPSRecord = true
		resolution.ECHConfig = record.ech
		resolution.TTL = time.Duration(record.ttl) * time.Second
		if record.target != "" {
			addressHost = record.target
		}
	}
	addresses, ttl, err := r.resolveAddresses(ctx, addressHost, 0, map[string]bool{})
	if err != nil {
		return nil, err
	}
	resolution.Addresses = addresses
	if resolution.TTL == 0 || (ttl != 0 && ttl < resolution.TTL) {
		resolution.TTL = ttl
	}
	return resolution, nil
}

// resolveHTTPS returns the selected HTTPS service record for host, or nil when
// the name publishes none.
//
// An answer for a name that was not asked about, an ambiguous alias set, and
// two equal-priority service records that disagree are all refused: each is a
// way for an answer to decide something the query did not.
func (r *Resolver) resolveHTTPS(ctx context.Context, host string, depth int, seen map[string]bool) (*httpsRecord, error) {
	if depth >= r.aliasHops || seen[host] {
		return nil, Fail(FailureHTTPSRecord, fmt.Errorf("HTTPS alias chain is cyclic or longer than %d records", r.aliasHops))
	}
	seen[host] = true
	message, err := r.query(ctx, host, typeHTTPS)
	if err != nil {
		return nil, err
	}
	var services []httpsRecord
	var aliases []string
	for _, answer := range message.answers {
		if answer.class != classINET || answer.name != host {
			return nil, Fail(FailureHTTPSRecord, errors.New("HTTPS answer is for a name that was not asked about"))
		}
		switch answer.rtype {
		case typeCNAME:
			target, _, err := decodeName(message.wire, answer.dataOffset)
			if err != nil {
				return nil, Fail(FailureHTTPSRecord, err)
			}
			aliases = append(aliases, target)
		case typeHTTPS:
			record, err := parseHTTPSRecord(message.wire, answer)
			if err != nil {
				return nil, Fail(FailureHTTPSRecord, err)
			}
			if record.alias() {
				aliases = append(aliases, record.target)
				continue
			}
			if record.target == "" {
				record.target = host
			}
			services = append(services, record)
		default:
			return nil, Fail(FailureHTTPSRecord, fmt.Errorf("HTTPS answer contains an unexpected %s record", answer.rtype))
		}
	}
	if len(services) == 0 {
		if len(aliases) == 0 {
			return nil, nil
		}
		sort.Strings(aliases)
		if aliases[0] == "" {
			return nil, Fail(FailureHTTPSRecord, errors.New("HTTPS alias target is empty"))
		}
		for _, alias := range aliases[1:] {
			if alias != aliases[0] {
				return nil, Fail(FailureHTTPSRecord, errors.New("HTTPS answer contains ambiguous aliases"))
			}
		}
		return r.resolveHTTPS(ctx, aliases[0], depth+1, seen)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].priority < services[j].priority })
	selected := services[0]
	for _, service := range services[1:] {
		if service.priority != selected.priority {
			break
		}
		if service.target != selected.target || !bytes.Equal(service.ech, selected.ech) {
			return nil, Fail(FailureHTTPSRecord, errors.New("HTTPS answer contains ambiguous service records"))
		}
		if service.ttl < selected.ttl {
			selected.ttl = service.ttl
		}
	}
	return &selected, nil
}

// resolveAddresses returns the A and AAAA addresses of host.
//
// Both queries are made; an answer is accepted only for the queried name or a
// name reached from it through a CNAME chain built out of the same answer. An
// address record for anything else is refused rather than ignored, because a
// response that answers a question it was not asked is not a response to
// filter.
func (r *Resolver) resolveAddresses(ctx context.Context, host string, depth int, seen map[string]bool) ([]netip.Addr, time.Duration, error) {
	if depth >= r.aliasHops || seen[host] {
		return nil, 0, Fail(FailureDoH, fmt.Errorf("CNAME chain is cyclic or longer than %d records", r.aliasHops))
	}
	seen[host] = true
	var addresses []netip.Addr
	var aliases []string
	var ttl time.Duration
	for _, qtype := range []dnsType{typeA, typeAAAA} {
		message, err := r.query(ctx, host, qtype)
		if err != nil {
			return nil, 0, err
		}
		chain, err := followCNAMEs(message, host)
		if err != nil {
			return nil, 0, err
		}
		aliases = append(aliases, chain.aliases...)
		for _, answer := range message.answers {
			if answer.class != classINET {
				return nil, 0, Fail(FailureDoH, errors.New("address answer is not class IN"))
			}
			if !chain.names[answer.name] {
				return nil, 0, Fail(FailureDoH, errors.New("address answer is for a name that was not asked about"))
			}
			switch answer.rtype {
			case typeA:
				if qtype != typeA || len(answer.data) != 4 {
					return nil, 0, Fail(FailureDoH, errors.New("address answer contains an unexpected A record"))
				}
				addresses = append(addresses, netip.AddrFrom4([4]byte(answer.data)))
			case typeAAAA:
				if qtype != typeAAAA || len(answer.data) != 16 {
					return nil, 0, Fail(FailureDoH, errors.New("address answer contains an unexpected AAAA record"))
				}
				addresses = append(addresses, netip.AddrFrom16([16]byte(answer.data)))
			case typeCNAME:
				// Already validated while building the chain.
			default:
				return nil, 0, Fail(FailureDoH, fmt.Errorf("address answer contains an unexpected %s record", answer.rtype))
			}
			candidate := time.Duration(answer.ttl) * time.Second
			if ttl == 0 || candidate < ttl {
				ttl = candidate
			}
		}
	}
	if len(addresses) == 0 && len(aliases) != 0 {
		sort.Strings(aliases)
		for _, alias := range aliases[1:] {
			if alias != aliases[0] {
				return nil, 0, Fail(FailureDoH, errors.New("address answer contains ambiguous CNAME targets"))
			}
		}
		return r.resolveAddresses(ctx, aliases[0], depth+1, seen)
	}
	if len(addresses) == 0 {
		return nil, 0, Fail(FailureDoH, errors.New("the resolver returned no A or AAAA address"))
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	return compactAddresses(addresses), ttl, nil
}

// cnameChain is the set of names an answer may legitimately be for.
type cnameChain struct {
	names   map[string]bool
	aliases []string
}

// followCNAMEs walks the CNAME records of one response from the queried name,
// returning every name the answer may then speak for.
func followCNAMEs(message *dnsMessage, host string) (cnameChain, error) {
	targets := map[string]string{}
	for _, answer := range message.answers {
		if answer.rtype != typeCNAME {
			continue
		}
		target, _, err := decodeName(message.wire, answer.dataOffset)
		if err != nil {
			return cnameChain{}, Fail(FailureDoH, err)
		}
		if previous, exists := targets[answer.name]; exists && previous != target {
			return cnameChain{}, Fail(FailureDoH, errors.New("address answer contains ambiguous CNAME targets"))
		}
		targets[answer.name] = target
	}
	chain := cnameChain{names: map[string]bool{host: true}}
	current := host
	for hop := 0; hop < aliasHopLimit; hop++ {
		target, exists := targets[current]
		if !exists {
			break
		}
		if target == "" || chain.names[target] {
			return cnameChain{}, Fail(FailureDoH, errors.New("address answer contains an invalid CNAME chain"))
		}
		chain.names[target] = true
		chain.aliases = append(chain.aliases, target)
		current = target
	}
	return chain, nil
}

// query performs one DoH exchange and validates that the answer belongs to the
// question that was asked.
//
// The checks are what makes a substituted answer fail rather than parse: the
// transaction ID must match, the response bit must be set, truncation is not
// accepted, the RCODE must be success, and the echoed question must be exactly
// the one sent.
func (r *Resolver) query(ctx context.Context, host string, qtype dnsType) (*dnsMessage, error) {
	question := dnsQuestion{name: host, qtype: qtype, class: classINET}
	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, Fail(FailureDoH, err)
	}
	id := binary.BigEndian.Uint16(seed[:])
	wire, err := buildDNSQuery(id, question)
	if err != nil {
		return nil, Fail(FailureDoH, err)
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, Fail(FailureDoH, err)
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, Fail(FailureDoH, fmt.Errorf("DoH query failed: %w", err))
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return nil, Fail(FailureRedirect, fmt.Errorf("the resolver answered with HTTP status %d", response.StatusCode))
		}
		return nil, Fail(FailureDoH, fmt.Errorf("the resolver answered with HTTP status %d", response.StatusCode))
	}
	if mediaType := response.Header.Get("Content-Type"); !isDNSMessageType(mediaType) {
		return nil, Fail(FailureDoH, fmt.Errorf("the resolver answered with content type %q", mediaType))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, dnsResponseLimit+1))
	if err != nil {
		return nil, Fail(FailureDoH, fmt.Errorf("read DoH response: %w", err))
	}
	if len(body) > dnsResponseLimit {
		return nil, Fail(FailureDoH, errors.New("DoH response exceeds the size limit"))
	}

	message, err := parseDNSMessage(body)
	if err != nil {
		return nil, Fail(FailureDoH, err)
	}
	switch {
	case message.header.id != id:
		return nil, Fail(FailureDoH, errors.New("DoH response does not carry the transaction ID that was sent"))
	case !message.header.response:
		return nil, Fail(FailureDoH, errors.New("DoH response is not marked as a response"))
	case message.header.truncated:
		return nil, Fail(FailureDoH, errors.New("DoH response is truncated"))
	case message.header.rcode != rcodeSuccess:
		return nil, Fail(FailureDoH, fmt.Errorf("the resolver answered %s", message.header.rcode))
	case len(message.questions) != 1 || message.questions[0] != question:
		return nil, Fail(FailureDoH, errors.New("DoH response echoes a different question"))
	}
	return message, nil
}

// isDNSMessageType reports whether a Content-Type names a DNS wire message.
func isDNSMessageType(value string) bool {
	mediaType, _, _ := strings.Cut(value, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/dns-message")
}

// compactAddresses removes adjacent duplicates from a sorted slice.
func compactAddresses(addresses []netip.Addr) []netip.Addr {
	if len(addresses) < 2 {
		return addresses
	}
	result := addresses[:1]
	for _, address := range addresses[1:] {
		if address != result[len(result)-1] {
			result = append(result, address)
		}
	}
	return result
}
