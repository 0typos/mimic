# Third-party notices

Mimic depends on open-source software. This summary is informational; the
license files distributed by each dependency are authoritative.

## Go runtime dependencies

| Project | Purpose | License family |
|---|---|---|
| `github.com/BurntSushi/toml` | TOML decoding | MIT |
| `github.com/refraction-networking/utls` | ClientHello construction and TLS | BSD-3-Clause |
| `github.com/andybalholm/brotli` | uTLS compression support | MIT |
| `github.com/klauspost/compress` | uTLS compression support | BSD-3-Clause |
| `golang.org/x/crypto` | Cryptographic support | BSD-3-Clause |
| `golang.org/x/net` | HTTP/2 and networking support | BSD-3-Clause |
| `golang.org/x/sys` | Platform support | BSD-3-Clause |
| `golang.org/x/text` | Text/IDNA support | BSD-3-Clause |

Exact versions and cryptographic hashes are recorded in `go.mod` and `go.sum`.

## Caido build dependencies

The plugin build uses the Caido SDK, Caido community build tooling, TypeScript,
and their locked transitive development dependencies. Exact versions and
integrity hashes are recorded in `integrations/caido/pnpm-lock.yaml`. The
packaged backend imports Caido-provided virtual runtime modules rather than
embedding the build toolchain.
