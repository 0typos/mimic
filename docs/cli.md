# CLI reference

Mimic uses one binary for both the daemon and its local control client.

## Global configuration selection

Commands accepting `-config` default to `MIMIC_CONFIG`, then to the operating
system's user configuration directory under `mimic/config.toml`. Flags must
appear before positional arguments, for example:

```sh
mimic ctl -config /etc/mimic/config.toml status
```

## `mimic daemon`

```text
mimic daemon [-config PATH]
```

Loads and validates configuration, binds all listeners, loads the optional CA,
and starts the control endpoint. `SIGINT`, `SIGTERM`, or `mimic ctl shutdown`
stops the daemon. Startup fails if any configured listener cannot bind.

## `mimic ctl`

```text
mimic ctl [-config PATH] [-socket ENDPOINT] COMMAND
```

`-socket` overrides `[control].listen` without loading that endpoint from the
configuration file.

| Command | Result |
|---|---|
| `info` | Control protocol version and capabilities |
| `status` | Uptime, selected profile, profile names, counters, and config path |
| `profiles` | Current status including available profile names |
| `use PROFILE` | Changes the daemon-wide default profile for new connections |
| `log-level LEVEL` | Changes the live level to `debug`, `info`, `warn`, or `error` |
| `reload` | Reloads mutable configuration from disk |
| `shutdown` | Requests graceful daemon shutdown |

Profile selection is not persisted to TOML. A reload retains the live selection
if that profile still exists; a restart uses `runtime.default_profile`.

Reloadable fields include profiles, routes, runtime timeouts, legacy policy, and
log level. Listener addresses, the control endpoint, logging format, and MITM CA
configuration require a restart.

## `mimic probe`

```text
mimic probe [-config PATH] -target HTTPS_URL [-profile NAME] [-expect JA4]
            [-format text|json] [-raw]
```

Opens a TLS connection without sending an HTTP request, captures the
ClientHello bytes Mimic actually writes, calculates JA4, and reports the
negotiated TLS version, cipher, and ALPN. A hostname target defaults to port
443; an `https://` URL is also accepted and its path/query are ignored.

Without `-profile`, normal default and host-route selection applies. `-expect`
overrides the selected profile's expected JA4 for this invocation. `-raw`
includes sorted `JA4_r` and original-order `JA4_ro` evidence in text output;
JSON output always contains the structured calculation inputs.

Exit behavior:

- success when observed and expected values match;
- success with `UNVERIFIED` when the profile has no expected JA4;
- failure after printing the report when values mismatch or TLS fails.

The profile attempt is always the value used for comparison. If compatibility
policy permits a legacy retry, both attempts appear in the report. Certificate
verification and route policy are identical to daemon traffic.

## `mimic validate`

```text
mimic validate [-config PATH]
```

Checks unknown TOML keys, field relationships, endpoint syntax, CIDRs, duration
ranges, profile names, route references, CA files when enabled, and captured
ClientHello parsing. It parses and verifies the configured CA/key pair but makes
no network connections.

## `mimic init-ca`

```text
mimic init-ca [-cert PATH] [-key PATH]
```

Creates an ECDSA P-256 local interception CA. Existing files are never
overwritten. The certificate uses mode `0644`; the private key uses `0600`.

## `mimic profiles`

```text
mimic profiles [-config PATH] [-format text|json]
```

Lists built-in profile identity, lifecycle, platform, and expected JA4 without
requiring a running daemon or configuration file. Supply `-config` to include
custom profiles after strict TOML validation. JSON output is intended for UI
and automation consumers; text output is tab-separated and human-readable.

This differs from `mimic ctl profiles`: the top-level command reads catalog
metadata locally, while the control command reports the running daemon's status
and loaded profile names.

## `mimic profile capture`

```text
mimic profile capture -listen ENDPOINT -name NAME [-output PATH] [-timeout 1m]
```

Starts a temporary TCP or Unix listener, accepts one TLS ClientHello, calculates
JA4, and writes a TOML snippet plus a normalized hexadecimal sidecar. It does
not complete TLS or capture HTTP. The default endpoint is
`tcp://127.0.0.1:8443`; existing output files are preserved unless `-force` is
explicit.

## `mimic profile import`

```text
mimic profile import (-input CLIENTHELLO | -pcap CAPTURE) -name NAME
                     [-output PATH]
```

`-input` accepts a binary record/handshake or whitespace-separated hexadecimal
text. `-pcap` accepts PCAP or PCAPNG and extracts the first complete reassembled
TCP ClientHello. Both paths calculate and print JA4 and `JA4_r`, then write the
same two-file output as live capture.

Both profile commands accept `-browser`, `-browser-version`, `-platform`,
`-lifecycle`, `-source`, `-captured-at`, `-user-agent`, `-ja4h`,
`-header-order`, repeatable `-header`, `-min-version`, and `-max-version`.
See [Profiles](profiles.md) for a complete capture-to-install tutorial and
fidelity limitations.

## `mimic version`

Prints the version embedded at build time. Development builds print `dev`.
