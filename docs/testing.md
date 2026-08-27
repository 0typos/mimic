# Testing

## Local gates

```sh
make check
make audit
make caido
make build VERSION=0.1.0
```

`make check` verifies formatting, runs race-enabled tests, enforces at least 60%
statement coverage, and runs `go vet`. `make audit` scans reachable Go symbols
with a pinned `govulncheck` release and audits the Caido dependency tree. `make caido`
installs the locked plugin toolchain, runs its protocol-framing tests, typechecks
it, builds it, and validates the package manifest.

## Automated coverage

The Go suite includes:

- strict TOML/default/path and invalid-relationship tests;
- profile registry and malformed captured-ClientHello tests;
- FoxIO JA4 reference-vector, parser, GREASE, and ALPN edge-case tests;
- emitted-ClientHello capture and golden JA4 checks for every built-in profile;
- CA generation, permissions, loading, and leaf issuance;
- runtime selection, routes, reload, and counters;
- modern TLS 1.2 and actual TLS 1.0 fallback handshakes;
- Unix control RPC, profile/log changes, protocol errors, and shutdown;
- end-to-end plain HTTP proxying and Unix listener startup;
- HTTP CONNECT byte tunneling;
- CA-backed HTTPS interception;
- negotiated HTTP/2 upstream translation;
- Caido bridge framing and plaintext relay;
- SOCKS5 TCP CONNECT and UDP relay;
- CLI validation, CA creation, JA4 probe pass/mismatch, and daemon lifecycle.

All network tests bind loopback or use in-memory pipes. They do not contact
external targets.

## Manual release checks

Before tagging:

1. Validate a clean example configuration.
2. Confirm the Linux archive binary is statically linked.
3. Install the built Caido package in the oldest and newest supported Caido
   versions.
4. Exercise Burp interception with a temporary CA.
5. Run `mimic probe` for every bundled profile, then independently compare the
   traffic against a controlled JA4/JA4H sensor.
6. Verify release archive checksums on a separate host.
