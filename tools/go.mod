module github.com/wojciechpolak/dproxy/tools

go 1.26.6

tool (
	github.com/Kunde21/markdownfmt/v3/cmd/markdownfmt
	golang.org/x/tools/cmd/deadcode
	golang.org/x/tools/cmd/goimports
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/Kunde21/markdownfmt/v3 v3.1.0 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect
	github.com/yuin/goldmark v1.7.17 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/telemetry v0.0.0-20260811182544-a038080d80e5 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.org/x/vuln v1.7.0 // indirect
	honnef.co/go/tools v0.7.0 // indirect
)
