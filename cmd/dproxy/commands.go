// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/localproxy"
	"github.com/wojciechpolak/dproxy/internal/logging"
	"github.com/wojciechpolak/dproxy/internal/relay"
)

// newFlagSet builds a FlagSet that never calls os.Exit, so every command path
// is testable.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("dproxy "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parse maps the flag parser's outcome onto an exit code. A requested --help is
// success; anything else is a usage error.
func parse(fs *flag.FlagSet, args []string) (exitCode, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(fs.Output(), "dproxy: unexpected argument %q\n", fs.Arg(0))
		return exitUsage, false
	}
	return exitOK, true
}

// runClient loads and validates the client configuration and starts the local
// CONNECT proxy.
func runClient(args []string, _, stderr io.Writer) exitCode {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runClientContext(ctx, args, stderr)
}

func runClientContext(ctx context.Context, args []string, stderr io.Writer) exitCode {
	fs := newFlagSet("client", stderr)
	options := config.RegisterClientFlags(fs)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	settings, err := options.Load()
	if err != nil {
		fmt.Fprintf(stderr, "dproxy client: %v\n", err)
		return exitUsage
	}
	logger := logging.New(stderr, settings.Log)
	server, err := localproxy.NewServer(localproxy.ServerOptions{Config: settings, Logger: logger})
	if err != nil {
		fmt.Fprintf(stderr, "dproxy client: %v\n", err)
		return exitFailure
	}
	listener, err := net.Listen("tcp", settings.Listen)
	if err != nil {
		fmt.Fprintf(stderr, "dproxy client: listen: %v\n", err)
		return exitFailure
	}
	defer func() { _ = listener.Close() }()
	logger.Info("client configuration loaded",
		"listen", settings.Listen,
		"ech", settings.ECH.String(),
		"allow_all_destinations", settings.Allowlist.AllowsAll(),
		"allowlist_patterns", settings.Allowlist.Len(),
		"token_file", settings.TokenFile.String(),
		logging.KeyRelay, settings.RelayURL.Hostname(),
	)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case err := <-serveErrors:
		if err != nil {
			fmt.Fprintf(stderr, "dproxy client: %v\n", err)
			return exitFailure
		}
		return exitOK
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), settings.Timeouts.Shutdown)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "dproxy client: %v\n", err)
			return exitFailure
		}
		if err := <-serveErrors; err != nil {
			fmt.Fprintf(stderr, "dproxy client: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
}

// runServer loads and validates the server configuration and starts the
// remote relay endpoint.
func runServer(args []string, _, stderr io.Writer) exitCode {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServerContext(ctx, args, stderr)
}

func runServerContext(ctx context.Context, args []string, stderr io.Writer) exitCode {
	fs := newFlagSet("server", stderr)
	options := config.RegisterServerFlags(fs)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	settings, err := options.Load()
	if err != nil {
		fmt.Fprintf(stderr, "dproxy server: %v\n", err)
		return exitUsage
	}
	logger := logging.New(stderr, settings.Log)
	server, err := relay.NewServer(relay.ServerOptions{Config: settings, Logger: logger})
	if err != nil {
		fmt.Fprintf(stderr, "dproxy server: %v\n", err)
		return exitFailure
	}
	listener, err := net.Listen("tcp", settings.Listen)
	if err != nil {
		fmt.Fprintf(stderr, "dproxy server: listen: %v\n", err)
		return exitFailure
	}
	defer func() { _ = listener.Close() }()
	logger.Info("server configuration loaded",
		"listen", settings.Listen,
		"allow_all_destinations", settings.Allowlist.AllowsAll(),
		"allowlist_patterns", settings.Allowlist.Len(),
		"max_sessions", settings.Limits.MaxSessions,
		"token_file", settings.TokenFile.String(),
		"identity_file", settings.IdentityFile,
		"identity_pin", server.IdentityPin().String(),
	)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case err := <-serveErrors:
		if err != nil {
			fmt.Fprintf(stderr, "dproxy server: %v\n", err)
			return exitFailure
		}
		return exitOK
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), settings.Timeouts.Shutdown)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "dproxy server: %v\n", err)
			return exitFailure
		}
		if err := <-serveErrors; err != nil {
			fmt.Fprintf(stderr, "dproxy server: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
}

// runTest reports transport diagnostics: it establishes the transport the
// client would use and prints what each stage negotiated, proxying nothing.
//
// It exits non-zero when a transport invariant did not hold, so it is usable
// as a check rather than only as something to read.
func runTest(args []string, stdout, stderr io.Writer) exitCode {
	fs := newFlagSet("test", stderr)
	options := config.RegisterClientFlags(fs)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	settings, err := options.Load()
	if err != nil {
		fmt.Fprintf(stderr, "dproxy test: %v\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result := diagnose(ctx, settings)
	result.write(stdout)
	if result.failed {
		return exitFailure
	}
	return exitOK
}
