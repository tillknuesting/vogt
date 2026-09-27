# Vogt

Vogt is a local broker that keeps credentials away from AI agents. An agent
asks Vogt for access, a human approves it with Touch ID, and the agent calls
the provider through Vogt's proxy, which adds the real credential for a few
minutes. The agent never holds the key itself.

This repository is at milestone M0: the crypto foundations. There is no
broker yet.

## Rules this code follows

- Go code uses the standard library only. `go.mod` has no `require` lines
  and CI fails if one appears. There is no cgo.
- The macOS helper will use only Apple's frameworks.
- Secrets stored or passed between the daemon and the helper are protected
  by a classical and a post-quantum algorithm together.

## What M0 contains

| Package | Purpose |
| --- | --- |
| `internal/wire` | Canonical binary encoding for everything signed or encrypted |
| `internal/secmem` | Locked, guard-paged, wiped memory for secret bytes |
| `internal/sig` | Composite ML-DSA-65 + ECDSA P-256 signatures |
| `internal/envelope` | AES-256-GCM records and HPKE key wrapping (MLKEM768-P256, X-Wing) |
| `internal/interop` | Test vectors shared with CryptoKit |
| `cmd/vogt` | `vogt version` and `vogt selftest` |

`spikes/cryptokit/interop.swift` checks the formats against CryptoKit on
macOS 26. It verifies Go's signatures and opens Go's X-Wing wraps. It then
signs with Secure Enclave ML-DSA-65 and P-256 keys and seals to a Go key, and
the Go tests check the results.

## Build and test

Needs Go 1.27 or later.

```sh
scripts/ci.sh                        # all CI gates; FUZZTIME=0 skips fuzzing
go run ./cmd/vogt selftest
swift spikes/cryptokit/interop.swift # macOS 26, then: go test ./internal/interop
```

## Design

The design spec and the implementation plan (milestones M0 to M4, crypto
choices, test strategy) are in the project's design doc.
