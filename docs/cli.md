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

## `mimic version`

Prints the version embedded at build time. Development builds print `dev`.
