// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/logging"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/securetransport"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

// The "dproxy test" report. It establishes the transport a tunnel would use
// and prints what each stage negotiated.
//
// Nothing here prints a token, a request, application bytes, or — unless the
// operator asked for destinations in the log — the relay hostname. The outer
// SNI is printed because it is the ECHConfig's public name rather than the
// private relay hostname.

// checkStatus is how one diagnostic ended.
type checkStatus uint8

const (
	// statusOK reports a check that passed.
	statusOK checkStatus = iota
	// statusFailed reports a check that did not hold. It is fatal: the
	// checks after it never ran.
	statusFailed
	// statusSkipped reports a check that could not run because an earlier
	// one failed.
	statusSkipped
	// statusInsecure reports a guarantee the operator turned off. It is not
	// a failure, and it must not read like an ordinary result either.
	statusInsecure
)

// check is one line of the report.
type check struct {
	label  string
	status checkStatus
	// detail is the value or the reason, already safe to print.
	detail string
}

// report is the whole diagnostic run.
type report struct {
	checks     []check
	failed     bool
	redactions []string
}

// add records a check.
func (r *report) add(label string, status checkStatus, detail string) {
	if status == statusFailed {
		r.failed = true
	}
	r.checks = append(r.checks, check{label: label, status: status, detail: detail})
}

// ok records a check that passed.
func (r *report) ok(label, detail string) { r.add(label, statusOK, detail) }

// fail records a check that did not hold. The underlying reason helps an
// operator distinguish policy, handshake, and reachability failures. Any relay
// hostname in that reason follows the same opt-in rule as the report heading.
func (r *report) fail(label string, err error) {
	detail := err.Error()
	var failure *securetransport.Error
	if errors.As(err, &failure) && failure.Err != nil {
		detail = failure.Reason.String() + ": " + failure.Err.Error()
	}
	for _, protected := range r.redactions {
		if protected != "" {
			detail = strings.ReplaceAll(detail, protected, logging.Redacted)
		}
	}
	r.add(label, statusFailed, detail)
}

// skip marks the remaining checks as never having run.
func (r *report) skip(labels ...string) {
	for _, label := range labels {
		r.add(label, statusSkipped, "")
	}
}

// attribute records a failure on whichever of the given labels it is about,
// marking every other one as never having run. Each label appears once, so the
// report stays readable regardless of which invariant broke.
//
// fallback owns a failure whose reason names a line that is not in this set,
// which happens because a stage can fail for a reason an earlier stage already
// reported on.
func (r *report) attribute(err error, fallback string, labels ...string) {
	target := checkForFailure(err)
	if !slices.Contains(labels, target) {
		target = fallback
	}
	for _, label := range labels {
		if label == target {
			r.fail(label, err)
			continue
		}
		r.skip(label)
	}
}

// write prints the report.
func (r *report) write(w io.Writer) {
	for _, entry := range r.checks {
		fmt.Fprintf(w, "%-16s %s\n", entry.label, entry.render())
	}
}

// render formats one line's value.
func (c check) render() string {
	switch c.status {
	case statusOK:
		if c.detail == "" {
			return "OK"
		}
		return c.detail
	case statusFailed:
		return "FAILED — " + c.detail
	case statusInsecure:
		return "INSECURE — " + c.detail
	default:
		return "not checked"
	}
}

// Labels of the report, in the order they are printed. The transport stages
// are named separately from the ones later checkpoints add, so a failure can
// mark exactly one of them and leave the rest as never having run.
const (
	checkDoH         = "DoH"
	checkHTTPSRecord = "HTTPS RR"
	checkTLS         = "TLS"
	checkCipher      = "cipher"
	checkECH         = "ECH"
	checkOuterSNI    = "outer SNI"
	checkCertificate = "certificate"
	checkWebSocket   = "websocket"
)

// dialChecks are the lines the outer dial produces, in print order.
var dialChecks = []string{checkTLS, checkCipher, checkECH, checkOuterSNI, checkCertificate, checkWebSocket}

const (
	checkInnerTLS       = "inner TLS"
	checkServerPin      = "server pin"
	checkAuthentication = "authentication"
)

var innerChecks = []string{checkInnerTLS, checkServerPin, checkAuthentication}

const checkRemoteRelay = "remote relay"

var laterChecks = append(append([]string{}, innerChecks...), checkRemoteRelay)

// diagnose runs the transport checks against the configured relay.
func diagnose(ctx context.Context, settings *config.ClientConfig) *report {
	result := &report{}

	relay := logging.Redacted
	if settings.Log.IncludeTargets {
		relay = settings.RelayURL.Hostname()
	} else {
		result.redactions = append(result.redactions, settings.RelayURL.Hostname())
	}
	result.ok("relay", relay)
	result.ok("ech", settings.ECH.String())

	resolver, err := securetransport.NewResolver(securetransport.ResolverOptions{
		URL:       settings.DoHURL,
		Bootstrap: settings.DoHBootstrap,
		Timeouts:  settings.Timeouts,
	})
	if err != nil {
		result.fail(checkDoH, err)
		result.skip(checkHTTPSRecord)
		result.skip(dialChecks...)
		result.skip(laterChecks...)
		return result
	}

	hostname := settings.RelayURL.Hostname()
	resolution, err := resolver.Resolve(ctx, hostname)
	if err != nil {
		// Both stages come out of one resolution, so a failure in it is
		// attributed to whichever of them it was about.
		result.attribute(err, checkDoH, checkDoH, checkHTTPSRecord)
		result.skip(dialChecks...)
		result.skip(laterChecks...)
		return result
	}
	result.ok(checkDoH, fmt.Sprintf("OK (%s)", plural(len(resolution.Addresses), "address", "addresses")))
	switch {
	case resolution.HTTPSRecord && len(resolution.ECHConfig) != 0:
		result.ok(checkHTTPSRecord, "OK (ECH configuration published)")
	case resolution.HTTPSRecord:
		result.ok(checkHTTPSRecord, "OK (no ECH configuration)")
	default:
		result.ok(checkHTTPSRecord, "absent")
	}

	dialer := &securetransport.SecureDialer{
		Resolver: resolver,
		ECH:      settings.ECH,
		Timeouts: settings.Timeouts,
	}
	conn, info, err := dialer.DialPort(ctx, hostname, relayPort(settings.RelayURL))
	if err != nil {
		// An HTTPS-record failure here means "no ECH configuration to use":
		// the record itself was already reported above.
		result.attribute(err, checkECH, dialChecks...)
		result.skip(laterChecks...)
		return result
	}
	defer func() { _ = conn.Close() }()

	result.ok(checkTLS, info.VersionName())
	result.ok(checkCipher, info.CipherSuiteName())
	if info.ECHAccepted {
		result.ok(checkECH, "accepted")
		result.ok(checkOuterSNI, echPublicNameOrUnknown(info))
	} else {
		result.add(checkECH, statusInsecure, "not used; the outer SNI is exposed (--insecure-disable-ech)")
		result.ok(checkOuterSNI, "the relay hostname, in the clear")
	}
	result.ok(checkCertificate, certificateSummary(info))

	upgrader := &tunnel.Upgrader{URL: settings.RelayURL, Timeout: settings.Timeouts.Control}
	reader, err := upgrader.Upgrade(ctx, conn)
	if err != nil {
		result.fail(checkWebSocket, err)
		result.skip(laterChecks...)
		return result
	}
	result.ok(checkWebSocket, "accepted")

	websocket := tunnel.NewClientWebSocketConn(conn, reader)
	diagnoseInner(ctx, websocket, settings, result)
	return result
}

// diagnoseInner verifies every remote-controlled stage without sending OPEN.
// Keeping it separate also lets tests exercise the real pinned TLS and HELLO
// exchange without needing a public ECH endpoint.
func diagnoseInner(ctx context.Context, stream net.Conn, settings *config.ClientConfig, result *report) {
	inner, innerInfo, err := tunnel.DialInnerTLS(ctx, stream, settings.ServerPin, settings.Timeouts.TLSHandshake)
	if err != nil {
		if errors.Is(err, tunnel.ErrPinMismatch) {
			result.skip(checkInnerTLS)
			result.fail(checkServerPin, err)
			result.skip(checkAuthentication, checkRemoteRelay)
		} else {
			result.fail(checkInnerTLS, err)
			result.skip(checkServerPin, checkAuthentication, checkRemoteRelay)
		}
		return
	}
	defer func() { _ = inner.Close() }()
	result.ok(checkInnerTLS, tls.VersionName(innerInfo.Version)+" / "+innerInfo.NegotiatedProtocol)
	result.ok(checkServerPin, "verified")

	token, err := settings.TokenFile.Read()
	if err != nil {
		result.fail(checkAuthentication, safeTokenFileError(err))
		result.skip(checkRemoteRelay)
		return
	}
	if err := authenticateDiagnostic(ctx, inner, token, settings.Timeouts.Control); err != nil {
		result.fail(checkAuthentication, err)
		result.skip(checkRemoteRelay)
		return
	}
	result.ok(checkAuthentication, "accepted")
	result.ok(checkRemoteRelay, "ready (no destination opened)")
}

// authenticateDiagnostic performs only HELLO. It proves that the configured
// token reaches the expected remote through the pinned channel without sending
// OPEN, resolving a provider hostname, or relaying application traffic.
func authenticateDiagnostic(ctx context.Context, conn *tls.Conn, token config.Token, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return errors.New("could not set the authentication deadline")
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stopCancellation()

	encoder := protocol.NewEncoder(conn, config.DefaultLimits().MaxControlMessageBytes)
	decoder := protocol.NewDecoder(conn, config.DefaultLimits().MaxControlMessageBytes)
	if err := encoder.Encode(protocol.Hello{Version: protocol.Version1, Token: token}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errors.New("the remote did not receive HELLO")
	}
	message, err := decoder.Decode()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return tunnel.ErrAuthenticationFailed
	}
	helloOK, ok := message.(protocol.HelloOK)
	if !ok || helloOK.Version != protocol.Version1 {
		return errors.New("the remote returned an unexpected HELLO response")
	}
	return nil
}

// safeTokenFileError keeps paths and file contents out of a normal diagnostic
// while still telling the operator which property to fix.
func safeTokenFileError(err error) error {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return errors.New("token file could not be read")
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "permissions"):
		return errors.New("token file permissions are too open; use 0600")
	case strings.Contains(text, "at least"):
		return fmt.Errorf("token is shorter than %d bytes", config.MinTokenBytes)
	case strings.Contains(text, " is a directory"):
		return errors.New("token file path names a directory")
	case strings.Contains(text, "larger"):
		return errors.New("token file is too large")
	default:
		return errors.New("token file could not be read")
	}
}

// checkForFailure names the line a transport failure belongs on, so "ECH was
// unavailable" is not reported as a TLS problem.
func checkForFailure(err error) string {
	switch securetransport.ReasonOf(err) {
	case securetransport.FailureDoH:
		return checkDoH
	case securetransport.FailureHTTPSRecord:
		return checkHTTPSRecord
	case securetransport.FailureECHUnavailable, securetransport.FailureECHRejected:
		return checkECH
	case securetransport.FailureCertificate:
		return checkCertificate
	default:
		return checkTLS
	}
}

// relayPort returns the port the relay URL names, defaulting to 443.
func relayPort(relay *url.URL) uint16 {
	if port := relay.Port(); port != "" {
		if value, err := strconv.ParseUint(port, 10, 16); err == nil {
			return uint16(value)
		}
	}
	return policy.AllowedPort
}

// echPublicNameOrUnknown renders the outer SNI.
func echPublicNameOrUnknown(info *securetransport.TransportInfo) string {
	if info.ECHPublicName == "" {
		return "accepted, public name not readable"
	}
	return info.ECHPublicName
}

// certificateSummary describes the validated leaf without naming its subject:
// on the outer session the subject is the relay.
func certificateSummary(info *securetransport.TransportInfo) string {
	if info.CertificateExpiry.IsZero() {
		return "valid"
	}
	summary := "valid until " + info.CertificateExpiry.UTC().Format(time.DateOnly)
	if info.CertificateIssuer != "" {
		summary += ", issued by " + info.CertificateIssuer
	}
	return summary
}

// plural renders a count with the right noun.
func plural(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(count) + " " + plural
}
