// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build !windows

package tunnel

import "syscall"

// connectionResetErrors are the errors a peer's reset produces.
var connectionResetErrors = []error{syscall.ECONNRESET}
