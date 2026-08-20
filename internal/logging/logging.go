// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package logging builds the process logger and enforces redaction in the
// handler rather than at each call site, so a new call site cannot leak by
// naming the wrong attribute.
//
// Secrets are redacted by key in every mode. Destination hostnames are written
// only when the operator sets LogOptions.IncludeTargets; raising the level does
// not opt in. Application traffic is never logged: no attribute carries it.
package logging

import (
	"io"
	"log/slog"
	"strings"

	"github.com/wojciechpolak/dproxy/internal/config"
)

// Redacted is what a suppressed value renders as: a fixed string, so a reader
// can tell "withheld" from "absent".
const Redacted = "[redacted]"

// Attribute keys with a defined meaning. The handler redacts by key, so ad-hoc
// strings are not equivalent.
const (
	// KeyTarget carries a destination authority ("host:port"). It is
	// suppressed unless the operator opted in.
	KeyTarget = "target"
	// KeyHost carries a destination hostname. Suppressed like KeyTarget.
	KeyHost = "host"
	// KeyRelay carries the dproxy relay hostname, under the same opt-in.
	KeyRelay = "relay"
	// KeyError carries an error value.
	KeyError = "error"
	// KeyReason carries a policy or protocol decision reason.
	KeyReason = "reason"
)

// secretKeys are always withheld, in every mode and at every level.
var secretKeys = map[string]bool{
	"token":         true,
	"secret":        true,
	"password":      true,
	"api_key":       true,
	"apikey":        true,
	"authorization": true,
	"credential":    true,
	"cookie":        true,
}

// targetKeys are attribute keys that name a destination. They are withheld
// unless LogOptions.IncludeTargets is set.
var targetKeys = map[string]bool{
	KeyTarget:   true,
	KeyHost:     true,
	KeyRelay:    true,
	"hostname":  true,
	"authority": true,
	"sni":       true,
	"url":       true,
}

// Logger carries the redaction policy with it, so a component handed one
// cannot log more than the operator allowed.
type Logger struct {
	*slog.Logger
	includeTargets bool
}

// New builds a logger that writes to w under the given options.
func New(w io.Writer, options config.LogOptions) *Logger {
	handlerOptions := &slog.HandlerOptions{
		Level:       level(options.Level),
		ReplaceAttr: redactor(options.IncludeTargets),
	}
	var handler slog.Handler
	if options.Format == config.LogFormatJSON {
		handler = slog.NewJSONHandler(w, handlerOptions)
	} else {
		handler = slog.NewTextHandler(w, handlerOptions)
	}
	return &Logger{Logger: slog.New(handler), includeTargets: options.IncludeTargets}
}

// Discard returns a logger that writes nothing.
func Discard() *Logger {
	return &Logger{Logger: slog.New(slog.DiscardHandler)}
}

// IncludeTargets reports whether destination names are being recorded.
func (l *Logger) IncludeTargets() bool { return l.includeTargets }

// With returns a logger with more attributes, preserving the policy.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{Logger: l.Logger.With(args...), includeTargets: l.includeTargets}
}

// Target builds the attribute for a destination authority. The handler redacts
// it too; doing it here as well survives a replaced handler.
func (l *Logger) Target(authority string) slog.Attr {
	if !l.includeTargets {
		return slog.String(KeyTarget, Redacted)
	}
	return slog.String(KeyTarget, authority)
}

// level maps the configured level onto slog's.
func level(configured config.LogLevel) slog.Level {
	switch configured {
	case config.LogLevelDebug:
		return slog.LevelDebug
	case config.LogLevelWarn:
		return slog.LevelWarn
	case config.LogLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// redactor runs for every attribute of every record, including those bound
// earlier with With and those nested in groups.
func redactor(includeTargets bool) func([]string, slog.Attr) slog.Attr {
	return func(_ []string, attr slog.Attr) slog.Attr {
		key := strings.ToLower(attr.Key)
		if secretKeys[key] {
			return slog.String(attr.Key, Redacted)
		}
		if !includeTargets && targetKeys[key] {
			return slog.String(attr.Key, Redacted)
		}
		return attr
	}
}
