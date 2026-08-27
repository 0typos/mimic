# Profiles

A profile combines a TLS ClientHello shape with HTTP identity hints. Profiles
are loaded at startup and reload, and captured ClientHellos are parsed during
validation so malformed files fail before traffic is accepted.

## Built-in catalog

Mimic loads 10 built-ins: five current, reproducible real-client captures and
five pinned legacy compatibility profiles. List the catalog and its metadata
without a configuration file:

```sh
mimic profiles
mimic profiles -format json
```

Current captures, refreshed on 2026-08-27:

| Name | Captured client | Platform | Expected emitted JA4 |
|---|---|---|---|
| `chrome-152-linux` | Chrome 152.0.7977.64 | Fedora 44 x86_64 | `t13d1517h2_8daaf6152771_cb7bf5808d99` |
| `chromium-151-linux` | Chromium 151.0.7922.173 | Fedora 44 x86_64 | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `edge-151-linux` | Edge 151.0.4129.101 | Fedora 44 x86_64 | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `firefox-154-linux` | Firefox 154.0 | Fedora 44 x86_64 | `t13d1517h2_8daaf6152771_3e9721a6796e` |
| `firefox-153-esr-linux` | Firefox ESR 153.1.0 | Fedora 44 x86_64 | `t13d1617h2_86a278354501_3cbfd9057e0d` |

Legacy profiles remain available for compatibility and regression work:

| Name | Source identity | Expected emitted JA4 |
|---|---|---|
| `chrome-133` | uTLS Chrome 133 preset | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| `firefox-120` | uTLS Firefox 120 preset | `t13d1715h2_5b57614c22b0_5c2c66f702b0` |
| `safari-16` | uTLS Safari 16 preset | `t13d2014h2_a09f3c656075_14788d8d241b` |
| `ios-14` | uTLS iOS 14 preset | `t13d2613h2_2802a3db6c62_845d286b0d67` |
| `android-11` | uTLS Android 11 OkHttp preset | `t12d120700_d34a8e72043a_036209cd1ead` |

Names are versioned and stable: a future update will add `chrome-153-linux`,
not silently change `chrome-152-linux`. `chrome-152-linux` is the default for a
new configuration. The lifecycle label is maintenance guidance, not access
control; legacy profiles continue to work when selected explicitly.

Capture provenance, fixture hashes, and the exact audit procedure are in
[profile-captures.md](profile-captures.md).

## Why 10 profiles

The maintained target is 8–12 built-ins and a hard review threshold around
15–20. That is large enough to cover the dominant browser families, stable and
ESR channels, and a few device/client shapes without shipping an opaque catalog
that becomes stale. As of the 2026-08 review, Chrome, Safari, Edge, Firefox, and
Samsung Internet are the largest worldwide browser families according to
[StatCounter](https://gs.statcounter.com/browser-market-share/desktop-mobile/worldwide).
The versions in this refresh are supported by the official
[Chrome 152 notes](https://developer.chrome.com/release-notes/152),
[Firefox 154 notes](https://www.firefox.com/en-US/firefox/154.0/releasenotes/),
[Firefox 153 ESR notes](https://www.firefox.com/en-US/firefox/153.0esr/releasenotes/),
and [Edge stable notes](https://learn.microsoft.com/deployedge/microsoft-edge-relnote-stable-channel).

The next capture priorities are current Safari on macOS and iOS, Chrome on
Android, Samsung Internet, and a current Android OkHttp client. Those require
the actual operating system/device; Mimic does not relabel a Linux capture as a
mobile or Apple fingerprint. The legacy Apple and Android profiles remain
available until verified replacements can be captured.

## Capture a new profile directly

The shortest workflow needs no packet-capture privileges. Start a temporary
listener that accepts exactly one TLS ClientHello:

```sh
mimic profile capture \
  -listen tcp://127.0.0.1:8443 \
  -name my-browser-1-linux \
  -output ./profiles/my-browser-1-linux.toml \
  -browser "My Browser" \
  -browser-version "1.0.0" \
  -platform "Linux x86_64" \
  -lifecycle custom \
  -source "clean-profile capture on a controlled workstation" \
  -user-agent "MyBrowser/1.0.0"
```

Open `https://localhost:8443/` in the client being captured. The page will fail
to load because the one-shot listener intentionally stops after ClientHello;
that is expected. Use a DNS hostname such as `localhost`, not an IP literal, so
the capture contains SNI and represents normal hostname traffic. Capture a
fresh, non-resumed connection from a clean client profile.

Mimic writes two files:

- `my-browser-1-linux.toml`, a strict profile snippet with calculated `ja4`;
- `my-browser-1-linux.clienthello.hex`, the normalized bare ClientHello.

The command refuses to overwrite either file unless `-force` is explicit. The
TOML file is a snippet, not a standalone configuration and not an automatic
include. Copy its `[profiles.NAME]` table into the main configuration, or merge
it mechanically while keeping the sidecar capture path relative to that file.

## Import an existing capture

Import a binary TLS record or whitespace-separated hexadecimal capture:

```sh
mimic profile import \
  -input ./clienthello.bin \
  -name captured-device \
  -output ./profiles/captured-device.toml \
  -browser "Device Client" \
  -browser-version "4.2" \
  -platform "test appliance" \
  -captured-at "2026-08-27T18:00:00-04:00"
```

Or extract the first complete TCP ClientHello from PCAP or PCAPNG:

```sh
mimic profile import \
  -pcap ./dedicated-browser-capture.pcapng \
  -name captured-browser \
  -output ./profiles/captured-browser.toml
```

Use a narrow, authorized capture containing one client connection. The importer
reassembles out-of-order and duplicate TCP segments but deliberately selects
the first complete ClientHello. It caps total payload, flow count, and per-flow
memory; it is an importer, not a general-purpose TCP forensics engine.

Useful optional flags are repeatable `-header 'Name: value'`, comma-separated
`-header-order`, `-ja4h`, `-min-version`, and `-max-version`. Generated metadata
and HTTP header values are validated before files are written.

## Install and verify a captured profile

After merging the snippet into the main TOML:

```sh
mimic validate -config ./config.toml
mimic profiles -config ./config.toml
mimic probe -config ./config.toml \
  -profile captured-device \
  -target https://controlled-sensor.example \
  -raw
```

Only then select it in the live daemon:

```sh
mimic ctl -config ./config.toml reload
mimic ctl -config ./config.toml use captured-device
```

The file may contain a TLS record stream or a bare handshake. Mimic normalizes
it and asks uTLS to reconstruct a usable ClientHello. Known dynamic fields such
as key shares are regenerated where uTLS supports them; unknown extensions may
be replayed as captured opaque data. A successful JA4 match proves the hashed
TLS shape, not byte-for-byte browser equivalence, session behavior, HTTP/2
framing, or every component of JA4+.

## Preset-backed custom profile

Pinned uTLS presets are useful for regression or compatibility profiles:

```toml
[profiles.lab-chrome]
hello = "chrome-133"
ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
ja4h = "expected-ja4h-metadata"
browser = "Chrome"
browser_version = "133"
platform = "Windows 10 x86_64"
lifecycle = "legacy"
source = "uTLS preset"
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

## JA4 verification

`ja4` is the expected TLS fingerprint used by `mimic probe`. The calculator
operates on captured outbound bytes and follows FoxIO's JA4 TLS specification,
including GREASE exclusion. Run:

```sh
mimic probe -config ./config.toml -profile lab-chrome -target https://example.com
mimic probe -config ./config.toml -profile lab-chrome -target https://example.com -format json
```

SNI presence changes JA4, so a built-in expectation for a DNS hostname will not
match an IP-address target. Session resumption or a future uTLS change can also
change the extension set; a mismatch is intentionally a failing probe.

`ja4h` remains operator-provided metadata. Mimic does not calculate JA4H because
it is governed separately from the BSD-licensed JA4 TLS method. HTTP edits,
cookies, and sensor behavior can change the externally observed value.
