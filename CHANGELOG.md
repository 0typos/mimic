# Changelog

All notable changes to Mimic will be documented here. The project follows
Semantic Versioning once public tags begin.

## [Unreleased]

### Added

- Single-binary daemon and control client.
- Strict TOML configuration, built-in profiles, captured ClientHello loading,
  and per-host routes.
- HTTP tunnel/intercept listeners, Unix sockets, SOCKS5 TCP/UDP, and the Caido
  upstream bridge.
- uTLS browser/device ClientHello presets and bounded TLS 1.0/1.1 retry.
- Local control protocol v1, structured logging, reload, counters, and shutdown.
- Caido backend plugin package.
- Outbound ClientHello capture, JA4 calculation, built-in conformance fixtures,
  and a text/JSON `mimic probe` command.
- Expanded protocol, CLI, configuration, certificate, and failure-path tests,
  with an 80% enforced coverage floor and 90% maintained target.
- Unit, race, protocol integration, vulnerability, and release build gates.
- Operator, integration, protocol, security, testing, and release documentation.
