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
- Caido backend/frontend plugin with persistent loopback settings, daemon
  health and counters, live profile control, and an operator page.
- Outbound ClientHello capture, JA4 calculation, built-in conformance fixtures,
  and a text/JSON `mimic probe` command.
- Expanded protocol, CLI, configuration, certificate, and failure-path tests,
  with an 80% enforced coverage floor and 90% maintained target.
- Unit, race, protocol integration, vulnerability, and release build gates.
- Operator, integration, protocol, security, testing, and release documentation.
- A sub-five-minute quickstart and operator-focused hands-on tutorial backed by
  a deterministic Docker Compose lab for daily browser, Caido, Burp, routing,
  profile capture, modern TLS, bounded TLS 1.0 fallback, and live control.
- A locked PEP 723 `uv` launcher for running or installing the tutorial lab
  without manually managing a Python environment.
- A 10-profile lifecycle-labeled catalog with real Chrome 152, Chromium 151,
  Edge 151, Firefox 154, and Firefox 153 ESR Linux captures; Chrome 152 is the
  new default and the former preset-backed catalog remains labeled legacy.
- `mimic profiles` catalog inspection plus `mimic profile capture` and
  `mimic profile import` workflows for TCP/Unix live capture, raw or hexadecimal
  ClientHello files, PCAP, and PCAPNG.
- Auditable built-in capture provenance, profile refresh policy, generated
  metadata validation, and conformance tests for every emitted built-in JA4.
