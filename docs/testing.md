# Testing

## Local gates

```sh
make check
make audit
make caido
make lab-check
make build VERSION=0.1.0
```

`make check` verifies formatting, runs race-enabled tests, enforces an 80%
statement-coverage floor, tracks a 90% maintained target, and runs `go vet`.
The floor is the merge-blocking safety net; the target protects the existing
margin as production code changes. Both values can be overridden locally with
`COVERAGE_MIN` and `COVERAGE_GOAL`. `make audit` scans reachable Go symbols
with a pinned `govulncheck` release and audits the Caido dependency tree. `make caido`
installs the locked plugin toolchain, runs its protocol-framing tests, typechecks
it, builds it, and validates the package manifest.

`make lab-check` compiles and tests the build-tagged deterministic origin,
verifies the PEP 723 launcher's `uv` lock and CLI, validates the Compose model,
and checks the container shell entry point without starting containers.

## Tutorial lab

The CI lab job performs the public workflow against real containers:

```sh
./lab/mimic-lab up
./lab/mimic-lab check
./lab/mimic-lab down
```

The check tour verifies modern JA4 conformance, profiled HTTP, HTTPS
interception with the generated CA, live profile changes, route precedence,
actual TLS 1.0 fallback, SOCKS identity preservation, the Caido bridge, the
Unix-socket listener, live log-level/profile evidence, and daemon counters. The
`down` step runs even if an assertion fails.

## Automated coverage

The Go suite includes:

- strict TOML/default/path and invalid-relationship tests;
- profile registry, metadata, generated TOML, live Unix-socket capture,
  raw/hex import, PCAP/PCAPNG reassembly, and malformed capture tests;
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
- CLI validation, CA creation, JA4 probe pass/mismatch, and daemon lifecycle;
- control commands, live reload boundaries, protocol failure responses,
  malformed TLS/SOCKS/Caido inputs, and listener lifecycle edge cases.

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
6. Recalculate every fixture hash in `docs/profile-captures.md` and confirm
   current profile source versions have not been silently replaced upstream.
7. Verify release archive checksums on a separate host.
8. Extract one release archive on a Docker host and complete the five-minute
   quickstart from the packaged `lab/` directory.
