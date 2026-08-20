// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/wojciechpolak/dproxy/internal/config"
)

func jsonLogger(t *testing.T, mutate func(*config.LogOptions)) (*Logger, *bytes.Buffer) {
	t.Helper()
	options := config.DefaultLogOptions()
	options.Format = config.LogFormatJSON
	options.Level = config.LogLevelDebug
	if mutate != nil {
		mutate(&options)
	}
	buffer := &bytes.Buffer{}
	return New(buffer, options), buffer
}

func TestSecretsAreRedactedByKey(t *testing.T) {
	logger, buffer := jsonLogger(t, nil)
	logger.Info("authenticated",
		"token", "0123456789abcdef0123456789abcdef",
		"authorization", "Bearer sk-secret",
		"api_key", "sk-also-secret",
		"Cookie", "session=secret",
	)
	output := buffer.String()
	for _, leaked := range []string{"0123456789abcdef", "sk-secret", "sk-also-secret", "session=secret"} {
		if strings.Contains(output, leaked) {
			t.Errorf("log leaked %q: %s", leaked, output)
		}
	}
	if strings.Count(output, Redacted) != 4 {
		t.Errorf("expected four redactions: %s", output)
	}
}

func TestTargetsAreWithheldUnlessRequested(t *testing.T) {
	logger, buffer := jsonLogger(t, nil)
	logger.Info("tunnel established",
		"target", "api.openai.com:443",
		"host", "api.anthropic.com",
		"relay", "dproxy.example.com",
		"reason", "ok",
	)
	output := buffer.String()
	for _, name := range []string{"api.openai.com", "api.anthropic.com", "dproxy.example.com"} {
		if strings.Contains(output, name) {
			t.Errorf("default log leaked destination %q: %s", name, output)
		}
	}
	if !strings.Contains(output, `"reason":"ok"`) {
		t.Errorf("redaction removed a non-sensitive attribute: %s", output)
	}
}

func TestTargetsAppearWhenOptedIn(t *testing.T) {
	logger, buffer := jsonLogger(t, func(o *config.LogOptions) { o.IncludeTargets = true })
	logger.Info("tunnel established", logger.Target("api.openai.com:443"))
	if !strings.Contains(buffer.String(), "api.openai.com:443") {
		t.Errorf("opt-in log withheld the destination: %s", buffer.String())
	}
}

// TestDebugLevelDoesNotOptIntoTargets: verbosity and privacy are separate
// switches.
func TestDebugLevelDoesNotOptIntoTargets(t *testing.T) {
	logger, buffer := jsonLogger(t, func(o *config.LogOptions) { o.Level = config.LogLevelDebug })
	logger.Debug("dialing", "target", "api.openai.com:443")
	if strings.Contains(buffer.String(), "api.openai.com") {
		t.Errorf("debug level exposed a destination: %s", buffer.String())
	}
}

func TestRedactionSurvivesWithAndGroups(t *testing.T) {
	logger, buffer := jsonLogger(t, nil)
	bound := logger.With("token", "0123456789abcdef0123456789abcdef")
	bound.Info("session", slog.Group("tunnel", "host", "api.openai.com", "state", "open"))
	output := buffer.String()
	if strings.Contains(output, "0123456789abcdef") {
		t.Errorf("an attribute bound with With leaked: %s", output)
	}
	if strings.Contains(output, "api.openai.com") {
		t.Errorf("an attribute inside a group leaked: %s", output)
	}
	if !strings.Contains(output, `"state":"open"`) {
		t.Errorf("group attributes were dropped: %s", output)
	}
}

func TestTargetAttrRespectsPolicy(t *testing.T) {
	quiet, _ := jsonLogger(t, nil)
	if got := quiet.Target("api.openai.com:443"); got.Value.String() != Redacted {
		t.Errorf("Target() = %v, want a redacted value", got)
	}
	if quiet.IncludeTargets() {
		t.Error("IncludeTargets() = true for the default options")
	}
	loud, _ := jsonLogger(t, func(o *config.LogOptions) { o.IncludeTargets = true })
	if got := loud.Target("api.openai.com:443"); got.Value.String() != "api.openai.com:443" {
		t.Errorf("Target() = %v, want the authority", got)
	}
}

func TestLevelFiltering(t *testing.T) {
	logger, buffer := jsonLogger(t, func(o *config.LogOptions) { o.Level = config.LogLevelWarn })
	logger.Info("not recorded")
	logger.Warn("recorded")
	if strings.Contains(buffer.String(), "not recorded") {
		t.Errorf("info record passed a warn-level logger: %s", buffer.String())
	}
	var record map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	if record["msg"] != "recorded" {
		t.Errorf("record = %v", record)
	}
}

func TestTextFormatIsTheDefault(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := New(buffer, config.DefaultLogOptions())
	logger.Info("listening", "addr", "127.0.0.1:18080")
	if !strings.Contains(buffer.String(), "msg=listening") {
		t.Errorf("text handler output = %s", buffer.String())
	}
}

func TestDiscardWritesNothing(t *testing.T) {
	logger := Discard()
	logger.Info("dropped")
	if logger.IncludeTargets() {
		t.Error("Discard() opted into targets")
	}
}
