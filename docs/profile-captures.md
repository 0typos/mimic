# Built-in profile capture provenance

This page is the audit record for ClientHello fixtures embedded in Mimic. The
fixtures contain only a TLS ClientHello sent to a controlled local endpoint; no
HTTP request, cookies, production hostname, server certificate, or response
traffic is stored.

## Capture environment

- Capture date: 2026-08-27, America/New_York
- Host: Fedora Linux 44 Workstation, x86_64
- Kernel: Linux 7.1.9-200.fc44.x86_64
- Capture command: the working-tree `mimic profile capture` implementation
- Client state: a new temporary browser profile with session resumption absent
- Target: a one-shot local TCP listener; `capture.mimic.test` or `localhost`
  supplied DNS-hostname SNI
- Browser mode: headless, with first-run, sync, component update, and background
  network activity disabled where the browser exposed those switches

The listener closed immediately after receiving one complete ClientHello. The
browser therefore reported a navigation failure or timed out after capture;
that is expected and does not invalidate the outbound handshake bytes.

## Fixture inventory

Hashes below are SHA-256 over the checked-in lowercase hexadecimal file,
including its final newline. JA4 values are recalculated from the decoded bytes
and then verified again from bytes emitted by Mimic in the automated suite.

| Fixture | Source version | Captured at | Bytes | Fixture SHA-256 | Emitted JA4 |
|---|---|---|---:|---|---|
| `chrome-152-linux.hex` | `google-chrome-stable-152.0.7977.64-1.x86_64` | `2026-08-27T18:35:54-04:00` | 1973 | `d3946b65ba1acb213e8be4a9a9418ba38bbacd585a092592dad2ea81b5a377be` | `t13d1517h2_8daaf6152771_cb7bf5808d99` |
| `chromium-151-linux.hex` | `chromium-151.0.7922.173-1.fc44.x86_64` | `2026-08-27T18:47:09-04:00` | 1761 | `cc518c6048d7940357b1d577065cae35fcd4c6195ba66d5ba5d7c0ccc764cd2d` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `edge-151-linux.hex` | Microsoft Edge 151.0.4129.101 | `2026-08-27T18:45:37-04:00` | 1825 | `cd62c919a4215d38f938e05f1a374c929ab786e93de7b84c22d53d14cc6106c5` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `firefox-154-linux.hex` | `firefox-154.0-5.fc44.x86_64` | `2026-08-27T18:54:42-04:00` | 1879 | `54938fd93302a398e92a6d2aad653db2b454bb2233961624140e773e99fe4428` | `t13d1517h2_8daaf6152771_3e9721a6796e` |
| `firefox-153-esr-linux.hex` | Firefox ESR 153.1.0 | `2026-08-27T18:55:12-04:00` | 1887 | `cf103f1a3397c25b857e87040312edbb30535bb2d7fa70f0777788963192aea9` | `t13d1617h2_86a278354501_3cbfd9057e0d` |

Chrome, Chromium, and Firefox came from signed packages installed on the capture
host. The additional clients came from these vendor artifacts:

- [Microsoft Edge 151.0.4129.101 RPM](https://packages.microsoft.com/yumrepos/edge/Packages/m/microsoft-edge-stable-151.0.4129.101-1.x86_64.rpm),
  SHA-256 `444002396269c2b106fef8cc61caef42fe5c17519f0ee089845df235d5278857`.
- [Firefox ESR 153.1.0 Linux archive](https://archive.mozilla.org/pub/firefox/releases/153.1.0esr/linux-x86_64/en-US/firefox-153.1.0esr.tar.xz),
  SHA-256 `d2e7c2b22128cd8ebedd2fa6d09e2552012d2a37c65284c0c91bfc2c3de4c6ad`.

Chrome 152 was the stable release for Linux on the capture date, Firefox 154
was the rapid release, Firefox 153 was the new ESR line, and Edge 151 was its
vendor's stable channel. Release references are linked from the selection
policy in [profiles.md](profiles.md).

## Reproduce a capture

Build the exact working tree, start a clean capture, and record the reported JA4:

```sh
go build -o ./mimic ./cmd/mimic

./mimic profile capture \
  -listen tcp://127.0.0.1:8443 \
  -timeout 1m \
  -name browser-version-platform \
  -output ./browser-version-platform.toml \
  -browser Browser \
  -browser-version Version \
  -platform "OS architecture" \
  -lifecycle current \
  -source "controlled clean-profile capture"
```

Launch the exact browser version with a new profile and navigate to
`https://localhost:8443/`. Browser-specific automation switches are allowed,
but do not enable experimental TLS flags, enterprise policies, a VPN TLS
interceptor, or session restoration. Record the full browser build identifier,
OS, architecture, time zone, capture time, artifact URL/hash, fixture hash,
reported JA4, and matching HTTP `User-Agent`.

Re-running the procedure is not expected to reproduce the fixture byte for
byte: randoms, GREASE values, key shares, and other dynamic data change. It must
reproduce the normalized JA4 and material extension behavior. Inspect `JA4_r`
as well as the hash before accepting a refresh.

## Review and refresh policy

1. Capture only an actual released client on the platform named by the profile.
2. Use a versioned name; never replace the identity behind an existing name.
3. Add provenance and both TLS and HTTP identity metadata.
4. Run the emitted-ClientHello conformance test for every built-in.
5. Probe a controlled independent JA4 sensor before release.
6. Keep the former profile as `legacy` while it has compatibility value; remove
   it only in a documented breaking release when the catalog crosses the
   15–20-profile review threshold.

Current Apple and Android replacements must be captured on those platforms.
Substituting a Linux Chromium handshake and merely changing its label is not an
acceptable contribution.

## Fidelity boundary

Mimic asks uTLS to parse these records with blunt mimicry enabled so that newer,
unknown extensions can be retained. For example, Chrome 152 contains the
fingerprint-visible `trust_anchors` extension that the newest named uTLS Chrome
preset does not yet model. Unknown extension bodies may therefore be replayed
as opaque captured data.

The regression test proves that Mimic can complete a handshake and emit the
recorded JA4. It does not prove browser-equivalent extension semantics,
resumption, HTTP/2 settings, HTTP/3, JA4H, JA4S, JA4X, or byte-for-byte parity.
