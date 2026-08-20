// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package securetransport establishes the outer connection to the public WSS
// front end under hard-mode transport rules: in-process DoH resolution, HTTPS
// RR and ECHConfig retrieval, TLS 1.3 only, mandatory ECH, chain validation,
// and no redirects during establishment.
//
// Every rule here fails closed. There is no OS-DNS fallback, no TLS 1.2
// retry, and no attempt without ECH.
package securetransport
