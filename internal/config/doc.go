// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package config loads and validates the client and server configuration:
// mode, listening addresses, relay URL, remote identity pin, token file,
// timeouts, and optional destination allowlists.
//
// Every value is validated here and carries an explicit named type. Invalid
// configuration is a startup failure, never a silent default.
package config
