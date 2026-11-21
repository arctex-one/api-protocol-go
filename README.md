# Arctex API protocol helpers for Go

This module provides the wire rules shared by Arctex API producers, the development emulator, and the Go SDK. It uses the Go standard library.

- request validates an Arctex request against the supplied OpenAPI document and returns the canonical JSON used for idempotency comparison. It preserves field presence and exact decimal strings.
- webhook builds and verifies HMAC-SHA256 and detached Ed25519 callbacks over the original callback body. The caller resolves signing and verification keys, limits the body size, and stores event identities for replay protection.

Use the OpenAPI revision supported by your application. Run go test -race ./... and go vet ./... from this repository to check the maintained synthetic vectors.
