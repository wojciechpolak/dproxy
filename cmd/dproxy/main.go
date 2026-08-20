// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Command dproxy runs a local HTTP CONNECT proxy. It carries allowed HTTPS
// traffic through an ECH-capable WSS relay. dproxy leaves application TLS
// end to end and does not inspect it.
package main

import (
	"fmt"
	"io"
	"os"
)

// exitCode is the process status. The values are part of the CLI contract, so
// they are named rather than spelled as literals at each return.
type exitCode int

const (
	// exitOK reports success.
	exitOK exitCode = 0
	// exitFailure reports an operation that ran and failed, a tunnel failing
	// closed included.
	exitFailure exitCode = 1
	// exitUsage reports a malformed invocation: an unknown command, a bad
	// flag, or a configuration that does not validate.
	exitUsage exitCode = 2
)

func main() {
	os.Exit(int(run(os.Args[1:], os.Stdout, os.Stderr)))
}

// run holds the whole command so tests can drive it with explicit arguments
// and captured output instead of a process.
func run(args []string, stdout, stderr io.Writer) exitCode {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	case "version", "-V", "--version":
		fmt.Fprintln(stdout, versionLine())
		return exitOK
	case "client":
		return runClient(args[1:], stdout, stderr)
	case "server":
		return runServer(args[1:], stdout, stderr)
	case "test":
		return runTest(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "dproxy: unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `dproxy is a discreet proxy

dproxy carries allowed HTTPS traffic through an ECH-capable WSS relay using DoH,
TLS 1.3, and ECH. It leaves application TLS end to end and does not inspect it.

Usage:
  dproxy <command> [flags]

Commands:
  client    run the local loopback CONNECT proxy
  server    run the remote relay behind a WSS front end
  test      report transport diagnostics without proxying anything
  version   print the version
  help      print this message

Run "dproxy <command> --help" for the flags of a command.

Point a client at the local proxy with:
  export HTTPS_PROXY=http://127.0.0.1:18080
`)
}
