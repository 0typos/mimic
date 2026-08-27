# Configuration reference

Mimic reads strict TOML. Unknown keys are errors. Relative CA and captured
ClientHello paths are resolved relative to the configuration file, not the
process working directory.

See [`config.example.toml`](../config.example.toml) for a complete example.

## Top level

| Key | Type | Required | Description |
|---|---|---:|---|
| `version` | integer | yes | Configuration schema; currently `1` |
| `listeners` | array | yes | At least one proxy listener |
| `profiles` | table | no | User-defined profiles keyed by name |
| `routes` | array | no | First-match hostname routing rules |

## `[control]`

| Key | Default | Description |
|---|---|---|
| `listen` | `unix:///tmp/mimic/control.sock` | `unix://` path or loopback `tcp://host:port` |

The control server refuses non-loopback TCP binds. Unix sockets are created with
mode `0600`. There is no application-level authentication in protocol v1, so do
not forward the endpoint or place it in a shared directory.

## `[logging]`

| Key | Default | Values |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn`, `error` |
| `format` | `text` | `text`, `json` |

The level can change live. Format changes require a restart. `warning` is
accepted as an alias for `warn`.

## `[runtime]`

| Key | Default | Description |
|---|---|---|
| `default_profile` | `chrome-152-linux` | Profile used when no route or per-request override matches |
| `connect_timeout` | `10s` | Positive TCP connection timeout |
| `handshake_timeout` | `15s` | Positive upstream TLS handshake deadline |

Durations use Go syntax such as `250ms`, `10s`, or `2m`.

## `[mitm]`

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Loads the CA and permits intercept listeners |
| `ca_cert` | none | PEM CA certificate path |
| `ca_key` | none | PEM ECDSA CA private-key path |
| `leaf_ttl` | `168h` | Positive generated leaf lifetime, capped by CA expiry |

Both CA paths must exist when enabled. Only HTTP listeners with
`mode = "intercept"` use this CA.

## `[legacy]`

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Loads the legacy retry capability |
| `min_version` | `tls1.0` | Retry floor: `tls1.0`, `tls1.1`, or `tls1.2` |
| `retry` | `true` | Permits a second handshake after an eligible failure |
| `retry_on` | protocol/cipher fragments | Case-insensitive error fragments eligible for retry |
| `allow_hosts` | local hostnames | Glob allowlist required before retry |
| `insecure_skip_verify` | `false` | Disables certificate verification on legacy-enabled paths |

`insecure_skip_verify` is global and high risk. Prefer a narrowly scoped route
override only in isolated test environments. Mimic never retries certificate
verification failures solely to obtain a connection.

## `[[listeners]]`

| Key | Required | Description |
|---|---:|---|
| `name` | yes | Unique log/display name |
| `protocol` | yes | `http`, `socks5`, or `caido` |
| `listen` | yes | `tcp://host:port` or `unix:///absolute/path` |
| `mode` | HTTP only | `tunnel` or `intercept` |
| `udp_listen` | SOCKS5 only | `udp://host:port` for UDP ASSOCIATE relay |
| `allow_cidrs` | no | Remote IP allowlist for TCP and UDP; empty permits all |

Use explicit loopback CIDRs unless remote clients are intentional. Unix socket
access is controlled by filesystem permissions. A SOCKS5 UDP relay accepts
unfragmented datagrams; SOCKS fragmentation is rejected.

## `[profiles.NAME]`

See [profiles.md](profiles.md). Each profile selects exactly one of `hello` or
`client_hello_file`. Optional fields are `ja4` (the probe expectation), `ja4h`
(operator metadata), `browser`, `browser_version`, `platform`, `lifecycle`,
`source`, `captured_at`, `user_agent`, `header_order`, `headers`, `min_version`,
and `max_version`. `lifecycle` is `current`, `legacy`, or `custom`;
`captured_at` must use RFC 3339.
Configured `ja4` values must use the normalized, lowercase hashed TLS-over-TCP
form, such as `t13d1516h2_8daaf6152771_d8a2da3f94cd`.

## `[[routes]]`

Routes are evaluated in file order; the first matching glob wins.

| Key | Required | Description |
|---|---:|---|
| `host` | yes | Case-insensitive hostname glob, without a port |
| `profile` | yes | Built-in or user-defined profile name |
| `legacy_retry` | no | Overrides global retry enablement for this route |
| `insecure_skip_verify` | no | Disables upstream certificate verification for this route |

Example:

```toml
[[routes]]
host = "*.lab.example"
profile = "firefox-120"
legacy_retry = true
insecure_skip_verify = false
```

Route settings apply only when a caller has not supplied an explicit profile
override. An explicit profile changes identity but does not inherit route-only
verification settings in protocol v1.
