# Profiles

A profile combines a TLS ClientHello shape with HTTP identity hints. Profiles
are loaded at startup and reload, and captured ClientHellos are parsed during
validation so malformed files fail before traffic is accepted.

## Built-in profiles

The daemon always provides:

| Name | uTLS preset |
|---|---|
| `chrome-133` | Chrome 133 |
| `firefox-120` | Firefox 120 |
| `safari-16` | Safari 16.0 |
| `ios-14` | iOS 14 |
| `android-11` | Android 11 OkHttp |

These names are stable within the `0.x` series. They are intentionally pinned;
updating Mimic does not silently turn `chrome-133` into a different browser.

## Preset-backed custom profile

```toml
[profiles.lab-chrome]
hello = "chrome-133"
ja4 = "expected-ja4-metadata"
ja4h = "expected-ja4h-metadata"
user_agent = "Mozilla/5.0 ... Chrome/133.0.0.0 Safari/537.36"
header_order = ["host", "connection", "user-agent", "accept", "cookie"]
min_version = "tls1.2"
max_version = "tls1.3"

[profiles.lab-chrome.headers]
Accept-Language = "en-US,en;q=0.9"
```

Accepted `hello` values:

- Chrome: `chrome-58`, `chrome-62`, `chrome-70`, `chrome-83`, `chrome-96`,
  `chrome-120`, `chrome-131`, `chrome-133`
- Firefox: `firefox-55`, `firefox-65`, `firefox-99`, `firefox-120`
- Apple: `safari-16`, `ios-11.1`, `ios-12.1`, `ios-13`, `ios-14`
- Other: `android-11`, `edge-85`, `edge-106`, `go`

## Captured ClientHello

```toml
[profiles.captured-device]
client_hello_file = "./profiles/device-clienthello.hex"
user_agent = "DeviceClient/1.0"
header_order = ["host", "user-agent", "accept"]
```

The file may contain a binary TLS ClientHello record or hexadecimal text.
Whitespace around hexadecimal text is ignored. Mimic uses uTLS to parse and
reapply the captured record. Captures can include dynamic values such as GREASE,
key shares, tickets, or extensions that do not replay meaningfully; test them
against a controlled server before relying on them.

## HTTP behavior

For intercepted HTTP/1.1 traffic, Mimic:

1. removes proxy and hop-by-hop headers;
2. replaces `User-Agent` when the profile defines one;
3. applies configured default headers;
4. writes configured headers in `header_order`; and
5. writes remaining headers in deterministic lexical order.

`X-Mimic-Profile` selects a profile for one intercepted request and is removed
before forwarding. The Caido bridge carries this value out-of-band instead.

HTTP/2 requests use the same header values but Go's HTTP/2 encoder controls
pseudo-header, HPACK, SETTINGS, and frame behavior.

## JA4 metadata

`ja4` and `ja4h` are labels for operator reference. They are not validation
assertions. Reported fingerprints can change with SNI presence, ALPN, GREASE,
session resumption, the edited request, cookies, or the sensor implementation.
