# Local protocols

Both protocols in this document are local integration surfaces. They are not
designed for untrusted networks.

## Control protocol v1

The daemon accepts newline-delimited JSON over the endpoint configured at
`control.listen`. Each connection may carry multiple request/response pairs.
Requests are limited to 1 MiB by the server.

Request:

```json
{"id":1,"method":"status","params":{}}
```

Success:

```json
{"id":1,"result":{"profile":"chrome-152-linux"}}
```

Failure:

```json
{"id":1,"error":"unknown method \"example\""}
```

`id` is an integer copied into the response. Available methods:

| Method | Params | Result |
|---|---|---|
| `ping` | none | `{ "ok": true }` |
| `protocol.info` | none | Protocol version and capability names |
| `status` | none | Daemon status snapshot |
| `profiles.list` | none | Status snapshot including profile names |
| `profile.use` | `{ "name": string }` | Updated status |
| `log.set` | `{ "level": string }` | Applied level |
| `config.reload` | none | Updated status or validation error |
| `daemon.shutdown` | none | `{ "stopping": true }` |

Protocol v1 has no authentication. The daemon restricts TCP control to loopback
and creates Unix control sockets with mode `0600`.

## Caido bridge protocol v1

A Caido bridge connection begins with one UTF-8 line no larger than 8192 bytes:

```text
MIMIC/1 {"target":"example.com:443","tls":true,"profile":"chrome-152-linux"}\n
```

Fields:

| Field | Type | Description |
|---|---|---|
| `target` | string | Required explicit `host:port` destination |
| `tls` | boolean | Whether Mimic establishes upstream TLS |
| `profile` | string | Optional profile override; empty uses normal routing |

After the preface, Caido writes the raw HTTP request. If TLS negotiates
HTTP/1.1, Mimic relays the bytes without reparsing. If TLS negotiates `h2`, Mimic
parses one HTTP/1 request, translates it upstream through HTTP/2, and translates
the response back to HTTP/1.1.

There is no acknowledgement frame: connect or handshake failure closes the
connection and Caido reports an upstream error. Bind this listener to loopback
or a permission-protected Unix socket.
