module github.com/go-filesystems/smb

// ⛔ THE PATCH, AND THIS REPOSITORY IS ONE OF THE NINE THE FLEET SWEEPS FOR
// EXPOSURE. This line is the only one of the three Go pins a CONSUMER honours:
// `go install` with GOTOOLCHAIN=local obeys it, while the CI pin merely builds
// our artefacts and the toolchain stamped in a binary describes one executable.
//
// Raised to 1.27.4 on 2026-11-15 for GO-2026-6859 — published 2026-11-11,
// CVE-2026-97054, "HTTP/1 server crash due to MaxBytesReader header race in
// net/http", stdlib, fixed in 1.26.11 and 1.27.4. Read at
// https://vuln.go.dev/ID/GO-2026-6859.json rather than quoted from notes.
//
// ⛔ AND HERE IT IS NOT MERELY A CONTRACT. This repository is named in
// go-fleettools/fleettools/.github/vulnscan-exposed.txt, the list cut BY
// EXPOSURE rather than by convenience: both repositories that actually REACHED
// an advisory in the fleet's 58 decoders were network-facing ones.
//
// Measured, not assumed: `modfloor --floor 1.27.4` read the directive this
// module PUBLISHED at v0.11.0 as `go 1.27.1` — three patch releases behind the
// fix — so every consumer installing it under GOTOOLCHAIN=local built against
// an unpatched standard library. Eight of the nine network-facing modules read
// BELOW at that moment; only go-webengine/engine was already at 1.27.4.
//
// ⛔ Renovate will never offer this edit, measured on 2026-11-15: its
// github-actions manager maintains the CI pin and its gomod manager SEES this
// directive while proposing nothing for it. Of the three pins, the only one a
// consumer honours is the unwatched one.
go 1.27.4

require (
	github.com/cloudsoda/go-smb2 v0.0.0-20261105190815-95be04a983b8
	github.com/go-filesystems/hostcopy v0.1.0
	github.com/go-filesystems/inflight v0.6.0
	github.com/go-filesystems/interface v0.6.0
	github.com/jcmturner/gofork v1.7.6
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/quic-go/quic-go v0.64.1
)

require (
	github.com/cloudsoda/sddl v0.0.0-20261105185302-1c8f96799263 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
