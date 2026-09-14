// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build windows

package tunnel

import "syscall"

// connectionResetErrors are the errors a peer's reset produces. Windows reports
// WSAECONNRESET on a read. A write can report either constant, so both are
// listed. Its own syscall.ECONNRESET is unrelated and matches no socket error.
var connectionResetErrors = []error{syscall.WSAECONNRESET, syscall.WSAECONNABORTED}
