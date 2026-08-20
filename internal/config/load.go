// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wojciechpolak/dproxy/internal/policy"
)

// Shipped defaults: what a fresh installation runs with when the operator
// supplies only the endpoint, the pin, and the token.
const (
	// DefaultClientListen binds the loopback CONNECT listener.
	DefaultClientListen = "127.0.0.1:18080"
	// DefaultServerListen binds the remote endpoint that a private ingress
	// connects to. It is loopback so the host does not publish it.
	DefaultServerListen = "127.0.0.1:8686"
	// DefaultDoHURL is the in-process resolver used by both sides.
	DefaultDoHURL = "https://cloudflare-dns.com/dns-query"
)

// DefaultAllowlist permits every valid public hostname on port 443. Operators
// can configure an allowlist when they want to narrow that policy.
func DefaultAllowlist() policy.Allowlist {
	return policy.AllowAll()
}

// stringList collects a flag that may be repeated.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

// commonOptions are the flags both roles share.
type commonOptions struct {
	configFile    string
	tokenFile     string
	dohURL        string
	dohBootstrap  stringList
	allowlistFile string
	allow         stringList
	dial          time.Duration
	tlsHandshake  time.Duration
	control       time.Duration
	idle          time.Duration
	maxLifetime   time.Duration
	shutdown      time.Duration
	logLevel      string
	logFormat     string
	logTargets    bool
}

func (o *commonOptions) register(fs *flag.FlagSet, defaultTokenFile string) {
	defaults := DefaultTimeouts()
	log := DefaultLogOptions()
	fs.StringVar(&o.configFile, "config", "", "path to a TOML configuration file; defaults under $XDG_CONFIG_HOME/dproxy or ~/.config/dproxy")
	fs.StringVar(&o.tokenFile, "token-file", defaultTokenFile, "path to the file holding the shared secret")
	fs.StringVar(&o.dohURL, "doh-url", DefaultDoHURL, "DoH resolver endpoint; there is no OS-DNS fallback")
	fs.Var(&o.dohBootstrap, "doh-bootstrap", "IP address the DoH endpoint is dialed at; repeat to add more")
	fs.StringVar(&o.allowlistFile, "allowlist-file", "", "path to a destination allowlist file, one pattern per line")
	fs.Var(&o.allow, "allow", "destination pattern to permit; repeat to add more and restrict the default all-host policy")
	fs.DurationVar(&o.dial, "dial-timeout", defaults.Dial, "TCP connect timeout")
	fs.DurationVar(&o.tlsHandshake, "tls-handshake-timeout", defaults.TLSHandshake, "TLS handshake timeout, outer and inner")
	fs.DurationVar(&o.control, "control-timeout", defaults.Control, "timeout for the HELLO/OPEN exchange")
	fs.DurationVar(&o.idle, "idle-timeout", defaults.Idle, "end a relayed session idle for this long; 0 disables")
	fs.DurationVar(&o.maxLifetime, "max-lifetime", defaults.MaxLifetime, "end a relayed session after this long; 0 is unbounded")
	fs.DurationVar(&o.shutdown, "shutdown-timeout", defaults.Shutdown, "wait this long for active relays during shutdown")
	fs.StringVar(&o.logLevel, "log-level", string(log.Level), "log level: debug, info, warn, or error")
	fs.StringVar(&o.logFormat, "log-format", string(log.Format), "log format: text or json")
	fs.BoolVar(&o.logTargets, "log-targets", log.IncludeTargets, "record destination hostnames in the log (privacy opt-in)")
}

// ClientOptions holds the raw client flags before validation.
type ClientOptions struct {
	commonOptions
	listen             string
	server             string
	serverPin          string
	insecureDisableECH bool
	flags              *flag.FlagSet
}

// RegisterClientFlags binds the client flags to fs. The result is raw operator
// input; Load validates it.
func RegisterClientFlags(fs *flag.FlagSet) *ClientOptions {
	options := &ClientOptions{flags: fs}
	options.register(fs, defaultClientTokenFile())
	fs.StringVar(&options.listen, "listen", DefaultClientListen, "loopback address for the CONNECT listener")
	fs.StringVar(&options.server, "server", "", "public wss:// URL of the remote dproxy")
	fs.StringVar(&options.serverPin, "server-pin", "", "pinned remote identity, sha256:<base64|hex> of its SPKI")
	fs.BoolVar(&options.insecureDisableECH, "insecure-disable-ech", false,
		"INSECURE: connect without ECH, exposing the outer SNI; development only")
	return options
}

// ServerOptions holds the raw server flags before validation.
type ServerOptions struct {
	commonOptions
	listen              string
	identityFile        string
	maxSessions         int
	maxControlMsgLength int
	flags               *flag.FlagSet
}

// RegisterServerFlags binds the server flags to fs.
func RegisterServerFlags(fs *flag.FlagSet) *ServerOptions {
	limits := DefaultLimits()
	options := &ServerOptions{flags: fs}
	options.register(fs, "")
	fs.StringVar(&options.listen, "listen", DefaultServerListen, "private address for the WebSocket ingress")
	fs.StringVar(&options.identityFile, "identity-file", defaultServerIdentityFile(), "persistent inner TLS identity file; created with mode 0600 when absent")
	fs.IntVar(&options.maxSessions, "max-sessions", limits.MaxSessions, "maximum concurrently relayed sessions")
	fs.IntVar(&options.maxControlMsgLength, "max-control-message", limits.MaxControlMessageBytes, "maximum size of one control message in bytes")
	return options
}

// Keys shared by both roles. Written out rather than derived from struct tags:
// an unknown key is an error, so this list is also the operator documentation.
var commonKeys = []string{
	"token_file",
	"doh_url",
	"doh_bootstrap",
	"allowlist_file",
	"allowlist",
	"timeouts.dial",
	"timeouts.tls_handshake",
	"timeouts.control",
	"timeouts.idle",
	"timeouts.max_lifetime",
	"timeouts.shutdown",
	"log.level",
	"log.format",
	"log.include_targets",
}

// clientKeys is the full client schema.
var clientKeys = append([]string{
	"listen",
	"server",
	"server_pin",
	"ech",
}, commonKeys...)

// serverKeys is the full server schema.
var serverKeys = append([]string{
	"listen",
	"identity_file",
	"limits.max_sessions",
	"limits.max_control_message_bytes",
}, commonKeys...)

// readConfigFile rejects any key outside the schema, so a misspelled security
// setting fails startup instead of being ignored.
func readConfigFile(path string, schema []string) (*tomlDocument, error) {
	// #nosec G304 -- the path comes from the operator's flag or config directory.
	handle, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	defer func() { _ = handle.Close() }()
	document, err := parseTOML(handle, path)
	if err != nil {
		return nil, err
	}
	if err := document.rejectUnknownKeys(schema); err != nil {
		return nil, err
	}
	return document, nil
}

// applyCommonFile assigns the settings both roles share.
func applyCommonFile(
	document *tomlDocument,
	tokenFile, dohURL *string,
	bootstrap *[]string,
	allowlist *allowlistSource,
	timeouts *Timeouts,
	log *LogOptions,
) error {
	return errors.Join(
		document.applyString("token_file", tokenFile),
		document.applyString("doh_url", dohURL),
		document.applyStrings("doh_bootstrap", bootstrap),
		document.applyString("allowlist_file", &allowlist.path),
		document.applyStrings("allowlist", &allowlist.entries),
		document.applyDuration("timeouts.dial", &timeouts.Dial),
		document.applyDuration("timeouts.tls_handshake", &timeouts.TLSHandshake),
		document.applyDuration("timeouts.control", &timeouts.Control),
		document.applyDuration("timeouts.idle", &timeouts.Idle),
		document.applyDuration("timeouts.max_lifetime", &timeouts.MaxLifetime),
		document.applyDuration("timeouts.shutdown", &timeouts.Shutdown),
		applyLogFile(document, log),
	)
}

// Load turns the client flags and optional configuration file into a validated
// ClientConfig. Precedence is defaults, file, then flags explicitly given: a
// flag left at its default never overrides the file.
func (o *ClientOptions) Load() (*ClientConfig, error) {
	config := &ClientConfig{
		Listen:    DefaultClientListen,
		ECH:       ECHRequired,
		Timeouts:  DefaultTimeouts(),
		Log:       DefaultLogOptions(),
		Allowlist: DefaultAllowlist(),
	}
	dohURL := DefaultDoHURL
	relayURL := ""
	pin := ""
	tokenFile := defaultClientTokenFile()
	var bootstrap []string
	allowlist := allowlistSource{}

	configFile, required, err := resolveConfigFile(o.configFile, ModeClient)
	if err != nil {
		return nil, err
	}
	if configFile != "" {
		document, err := readConfigFile(configFile, clientKeys)
		if err != nil {
			if required || !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		} else {
			ech := string(config.ECH)
			if err := errors.Join(
				document.applyString("listen", &config.Listen),
				document.applyString("server", &relayURL),
				document.applyString("server_pin", &pin),
				document.applyString("ech", &ech),
				applyCommonFile(document, &tokenFile, &dohURL, &bootstrap, &allowlist, &config.Timeouts, &config.Log),
			); err != nil {
				return nil, err
			}
			mode, err := ParseECHMode(ech)
			if err != nil {
				return nil, err
			}
			config.ECH = mode
		}
	}

	var flagError error
	o.flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			config.Listen = o.listen
		case "server":
			relayURL = o.server
		case "server-pin":
			pin = o.serverPin
		case "token-file":
			tokenFile = o.tokenFile
		case "doh-url":
			dohURL = o.dohURL
		case "doh-bootstrap":
			bootstrap = o.dohBootstrap
		case "allowlist-file":
			allowlist.path = o.allowlistFile
		case "allow":
			allowlist.entries = o.allow
		case "insecure-disable-ech":
			if o.insecureDisableECH {
				config.ECH = ECHInsecureDisabled
			} else {
				config.ECH = ECHRequired
			}
		default:
			flagError = errors.Join(flagError, applyCommonFlag(f.Name, &o.commonOptions, &config.Timeouts, &config.Log))
		}
	})
	if flagError != nil {
		return nil, flagError
	}

	if relayURL == "" {
		return nil, errors.New("the relay URL is required (--server wss://…)")
	}
	parsedRelay, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("relay URL: %w", err)
	}
	config.RelayURL = parsedRelay
	if pin == "" {
		return nil, errors.New("the remote identity pin is required (--server-pin sha256:…)")
	}
	parsedPin, err := ParsePin(pin)
	if err != nil {
		return nil, err
	}
	config.ServerPin = parsedPin
	parsedDoH, err := url.Parse(dohURL)
	if err != nil {
		return nil, fmt.Errorf("DoH URL: %w", err)
	}
	config.DoHURL = parsedDoH
	config.DoHBootstrap, err = resolveBootstrap(parsedDoH, bootstrap)
	if err != nil {
		return nil, err
	}
	expanded, err := expandPath(tokenFile)
	if err != nil {
		return nil, err
	}
	config.TokenFile = TokenFile(expanded)
	if err := allowlist.apply(&config.Allowlist); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// Load turns the server flags and optional configuration file into a
// validated ServerConfig, with the same precedence as the client.
func (o *ServerOptions) Load() (*ServerConfig, error) {
	config := &ServerConfig{
		Listen:    DefaultServerListen,
		Timeouts:  DefaultTimeouts(),
		Limits:    DefaultLimits(),
		Log:       DefaultLogOptions(),
		Allowlist: DefaultAllowlist(),
	}
	dohURL := DefaultDoHURL
	tokenFile := ""
	identityFile := defaultServerIdentityFile()
	var bootstrap []string
	allowlist := allowlistSource{}

	configFile, required, err := resolveConfigFile(o.configFile, ModeServer)
	if err != nil {
		return nil, err
	}
	if configFile != "" {
		document, err := readConfigFile(configFile, serverKeys)
		if err != nil {
			if required || !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		} else {
			if err := errors.Join(
				document.applyString("listen", &config.Listen),
				document.applyString("identity_file", &identityFile),
				document.applyInt("limits.max_sessions", &config.Limits.MaxSessions),
				document.applyInt("limits.max_control_message_bytes", &config.Limits.MaxControlMessageBytes),
				applyCommonFile(document, &tokenFile, &dohURL, &bootstrap, &allowlist, &config.Timeouts, &config.Log),
			); err != nil {
				return nil, err
			}
		}
	}

	var flagError error
	o.flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			config.Listen = o.listen
		case "identity-file":
			identityFile = o.identityFile
		case "token-file":
			tokenFile = o.tokenFile
		case "doh-url":
			dohURL = o.dohURL
		case "doh-bootstrap":
			bootstrap = o.dohBootstrap
		case "allowlist-file":
			allowlist.path = o.allowlistFile
		case "allow":
			allowlist.entries = o.allow
		case "max-sessions":
			config.Limits.MaxSessions = o.maxSessions
		case "max-control-message":
			config.Limits.MaxControlMessageBytes = o.maxControlMsgLength
		default:
			flagError = errors.Join(flagError, applyCommonFlag(f.Name, &o.commonOptions, &config.Timeouts, &config.Log))
		}
	})
	if flagError != nil {
		return nil, flagError
	}

	parsedDoH, err := url.Parse(dohURL)
	if err != nil {
		return nil, fmt.Errorf("DoH URL: %w", err)
	}
	config.DoHURL = parsedDoH
	config.DoHBootstrap, err = resolveBootstrap(parsedDoH, bootstrap)
	if err != nil {
		return nil, err
	}
	if tokenFile == "" {
		return nil, errors.New("the token file is required (--token-file)")
	}
	expanded, err := expandPath(tokenFile)
	if err != nil {
		return nil, err
	}
	config.TokenFile = TokenFile(expanded)
	expandedIdentity, err := expandPath(identityFile)
	if err != nil {
		return nil, err
	}
	config.IdentityFile = expandedIdentity
	if err := allowlist.apply(&config.Allowlist); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// resolveBootstrap turns the operator's bootstrap entries into addresses,
// falling back to the built-in ones for an endpoint dproxy ships knowledge of.
// It does not fall back to the operating system resolver, which is why an
// unknown endpoint with no entries fails validation instead.
func resolveBootstrap(endpoint *url.URL, entries []string) ([]netip.Addr, error) {
	if len(entries) == 0 {
		return DefaultDoHBootstrap(endpoint), nil
	}
	return ParseBootstrapAddresses(entries)
}

// allowlistSource records where the allowlist comes from. Inline entries win
// over a file, and either narrows the default all-host policy.
type allowlistSource struct {
	entries []string
	path    string
}

func (s allowlistSource) apply(into *policy.Allowlist) error {
	switch {
	case len(s.entries) > 0:
		list, err := policy.ParseAllowlist(s.entries)
		if err != nil {
			return err
		}
		*into = list
	case s.path != "":
		path, err := expandPath(s.path)
		if err != nil {
			return err
		}
		// #nosec G304 -- the path is the operator's own allowlist setting.
		handle, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("allowlist file: %w", err)
		}
		defer func() { _ = handle.Close() }()
		list, err := policy.ReadAllowlist(handle)
		if err != nil {
			return fmt.Errorf("allowlist file %s: %w", path, err)
		}
		*into = list
	}
	return nil
}

// applyCommonFlag handles the flags both roles share, erroring on an unexpected
// name so a new flag cannot be added to the FlagSet and ignored here.
func applyCommonFlag(name string, options *commonOptions, timeouts *Timeouts, log *LogOptions) error {
	switch name {
	case "config":
		return nil
	case "dial-timeout":
		timeouts.Dial = options.dial
	case "tls-handshake-timeout":
		timeouts.TLSHandshake = options.tlsHandshake
	case "control-timeout":
		timeouts.Control = options.control
	case "idle-timeout":
		timeouts.Idle = options.idle
	case "max-lifetime":
		timeouts.MaxLifetime = options.maxLifetime
	case "shutdown-timeout":
		timeouts.Shutdown = options.shutdown
	case "log-level":
		level, err := ParseLogLevel(options.logLevel)
		if err != nil {
			return err
		}
		log.Level = level
	case "log-format":
		format, err := ParseLogFormat(options.logFormat)
		if err != nil {
			return err
		}
		log.Format = format
	case "log-targets":
		log.IncludeTargets = options.logTargets
	default:
		return fmt.Errorf("internal: flag %q is registered but not applied", name)
	}
	return nil
}

// applyLogFile assigns the logging settings, validating as it reads.
func applyLogFile(document *tomlDocument, into *LogOptions) error {
	level := string(into.Level)
	format := string(into.Format)
	if err := errors.Join(
		document.applyString("log.level", &level),
		document.applyString("log.format", &format),
		document.applyBool("log.include_targets", &into.IncludeTargets),
	); err != nil {
		return err
	}
	parsedLevel, err := ParseLogLevel(level)
	if err != nil {
		return err
	}
	parsedFormat, err := ParseLogFormat(format)
	if err != nil {
		return err
	}
	into.Level = parsedLevel
	into.Format = parsedFormat
	return nil
}

// resolveConfigFile selects an explicit path or the role-specific file in the
// user's config directory. A missing discovered file is optional. An explicit
// path is required.
func resolveConfigFile(explicit string, role Mode) (path string, required bool, err error) {
	if explicit != "" {
		expanded, err := expandPath(explicit)
		return expanded, true, err
	}
	dir, err := userConfigDir()
	if err != nil {
		return "", false, fmt.Errorf("locate config directory: %w", err)
	}
	return filepath.Join(dir, "dproxy", role.String()+".toml"), false, nil
}

// userConfigDir follows XDG_CONFIG_HOME on every supported operating system.
// When it is unset, dproxy uses ~/.config, including on macOS.
func userConfigDir() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("XDG_CONFIG_HOME must be an absolute path, got %q", dir)
		}
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config"), nil
}

// defaultClientTokenFile is the per-user location of the shared secret. A path
// only; nothing reads it until a tunnel is built.
func defaultClientTokenFile() string {
	dir, err := userConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "dproxy", "token")
}

// defaultServerIdentityFile keeps the generated key in the user's config
// directory. Container deployments should mount and configure a persistent
// path such as /var/lib/dproxy/identity.pem.
func defaultServerIdentityFile() string {
	dir, err := userConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "dproxy", "server-identity.pem")
}

// expandPath resolves a leading "~/".
func expandPath(path string) (string, error) {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path, nil
	}
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return "", fmt.Errorf("path %q: only a leading \"~/\" is expanded", path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand %q: %w", path, err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
}
