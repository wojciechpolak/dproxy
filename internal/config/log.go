// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import "fmt"

// LogLevel is the minimum severity that reaches the log.
type LogLevel string

// The severities dproxy recognises, in increasing order.
const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// String implements fmt.Stringer.
func (l LogLevel) String() string { return string(l) }

// ParseLogLevel validates a level written by an operator.
func ParseLogLevel(raw string) (LogLevel, error) {
	switch LogLevel(raw) {
	case LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
		return LogLevel(raw), nil
	default:
		return "", fmt.Errorf("unknown log level %q (want debug, info, warn, or error)", raw)
	}
}

// LogFormat selects the encoding of a log record.
type LogFormat string

const (
	// LogFormatText is the human-readable default.
	LogFormatText LogFormat = "text"
	// LogFormatJSON is for log collectors.
	LogFormatJSON LogFormat = "json"
)

// String implements fmt.Stringer.
func (f LogFormat) String() string { return string(f) }

// ParseLogFormat validates a format written by an operator.
func ParseLogFormat(raw string) (LogFormat, error) {
	switch LogFormat(raw) {
	case LogFormatText, LogFormatJSON:
		return LogFormat(raw), nil
	default:
		return "", fmt.Errorf("unknown log format %q (want text or json)", raw)
	}
}

// LogOptions controls verbosity and, independently, whether target hostnames
// may be recorded: debugging a transport problem must not start writing down
// which providers the user talks to.
type LogOptions struct {
	Level  LogLevel
	Format LogFormat
	// IncludeTargets opts in to logging destination hostnames. No level or
	// error path may override it.
	IncludeTargets bool
}

// DefaultLogOptions returns the shipped defaults: text, info, no targets.
func DefaultLogOptions() LogOptions {
	return LogOptions{Level: LogLevelInfo, Format: LogFormatText, IncludeTargets: false}
}

// Validate checks the level and format.
func (o LogOptions) Validate() error {
	if _, err := ParseLogLevel(string(o.Level)); err != nil {
		return err
	}
	if _, err := ParseLogFormat(string(o.Format)); err != nil {
		return err
	}
	return nil
}
