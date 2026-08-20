// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/wojciechpolak/dproxy/internal/config"
)

// An injected DoH transport, the technique DUD's transport matrix uses: the
// resolution logic is exercised over canned wire messages, so every failure
// path is reachable without a network and without a DNS server that would have
// to be persuaded to misbehave.

// stubEndpoint is the DoH URL the stubs answer for. Nothing dials it.
const stubEndpoint = "https://dns.example/dns-query"

// dohStub answers DoH requests and records what was asked.
type dohStub struct {
	t *testing.T
	// reply builds the HTTP response for one query. Set by the constructors
	// below.
	reply func(id uint16, question dnsQuestion) *http.Response
	mu    sync.Mutex
	asked []dnsQuestion
}

// RoundTrip decodes the query and hands it to reply.
func (s *dohStub) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost {
		s.t.Errorf("DoH request method = %s, want POST", request.Method)
	}
	if got := request.Header.Get("Content-Type"); got != "application/dns-message" {
		s.t.Errorf("DoH request content type = %q", got)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	query, err := parseDNSMessage(body)
	if err != nil {
		s.t.Fatalf("the resolver sent a query that does not parse: %v", err)
	}
	if len(query.questions) != 1 {
		s.t.Fatalf("the resolver sent %d questions", len(query.questions))
	}
	question := query.questions[0]
	s.mu.Lock()
	s.asked = append(s.asked, question)
	s.mu.Unlock()
	return s.reply(query.header.id, question), nil
}

// questions returns the questions the resolver asked, in order.
func (s *dohStub) questions() []dnsQuestion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dnsQuestion(nil), s.asked...)
}

// dnsResponse wraps wire bytes as a well-formed DoH response.
func dnsResponse(wire []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/dns-message"}},
		Body:       io.NopCloser(bytes.NewReader(wire)),
	}
}

// zone maps a question onto the answer section returned for it. A question
// with no entry is answered NOERROR with no records, which is what a name that
// publishes nothing looks like.
type zone map[dnsQuestion][]testAnswer

// answersFor looks a question up by name and type, ignoring class.
func (z zone) answersFor(question dnsQuestion) []testAnswer {
	return z[dnsQuestion{name: question.name, qtype: question.qtype, class: classINET}]
}

// ask is shorthand for a zone key.
func ask(name string, qtype dnsType) dnsQuestion {
	return dnsQuestion{name: name, qtype: qtype, class: classINET}
}

// newStubResolver builds a resolver answering from a zone.
func newStubResolver(t *testing.T, records zone) (*Resolver, *dohStub) {
	t.Helper()
	stub := &dohStub{t: t}
	stub.reply = func(id uint16, question dnsQuestion) *http.Response {
		return dnsResponse(buildResponse(t, responseOptions{
			id:       id,
			question: question,
			answers:  records.answersFor(question),
		}))
	}
	return newResolverWithStub(t, stub), stub
}

// newResolverWithStub builds a resolver over an arbitrary stub.
func newResolverWithStub(t *testing.T, stub *dohStub) *Resolver {
	t.Helper()
	endpoint, err := url.Parse(stubEndpoint)
	if err != nil {
		t.Fatalf("parse stub endpoint: %v", err)
	}
	resolver, err := NewResolver(ResolverOptions{
		URL:          endpoint,
		Timeouts:     config.DefaultTimeouts(),
		roundTripper: stub,
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return resolver
}
