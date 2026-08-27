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
- Unit, race, protocol integration, vulnerability, and release build gates.
- Operator, integration, protocol, security, testing, and release documentation.
