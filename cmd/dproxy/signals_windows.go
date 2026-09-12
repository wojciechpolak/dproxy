// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build windows

package main

import "os"

func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
