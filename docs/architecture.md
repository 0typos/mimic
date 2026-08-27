# Architecture

Mimic is deliberately split into a small control plane and a data plane.

```text
Browser/Burp ── HTTP intercept ─┐
Browser/tool ── HTTP tunnel ────┼─> listeners ─> routing/profile ─> origin
SOCKS client ── TCP/UDP ────────┤                     │
Caido plugin ── MIMIC/1 ────────┘                     └─> uTLS + legacy retry

mimic ctl ── JSON lines over Unix/loopback TCP ─> daemon state
```

## Packages

| Package | Responsibility |
|---|---|
| `cmd/mimic` | CLI, process lifecycle, logging setup, reload boundaries |
| `internal/config` | Strict TOML schema, defaults, endpoint and relationship validation |
| `internal/profiles` | Built-ins, captured ClientHello loading, HTTP identity |
| `internal/engine` | Runtime state, host routing, uTLS handshakes, legacy policy |
| `internal/mitm` | CA generation/loading and cached per-host leaf certificates |
| `internal/proxy` | HTTP, CONNECT, Caido, SOCKS5 TCP, and SOCKS5 UDP data planes |
| `internal/control` | Versioned newline-framed local RPC |

## Connection behavior

- Tunnel-mode CONNECT and SOCKS5 CONNECT copy bytes without changing TLS.
- Intercept mode terminates downstream TLS with a generated leaf, reads HTTP,
  then creates a new profiled upstream connection.
- Caido already has plaintext request bytes. Its plugin supplies the target
  out-of-band so Mimic can establish profiled TLS without another CA boundary.
- Each HTTP/1 request currently receives a new upstream connection. Persistent
  downstream connections remain supported.
- SOCKS5 UDP creates one ephemeral outbound UDP socket per client endpoint and
  expires idle sessions after two minutes.

## Configuration reload

Runtime state is swapped under a read/write lock. Live connections continue
with the profile and policy selected at creation. New connections see the new
state. Socket and CA changes are rejected during reload because rebinding them
atomically is not yet implemented.
