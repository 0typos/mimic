# Mimic

Mimic is a fingerprint-aware HTTP/HTTPS compatibility proxy for authorized
testing and interoperability work. It is designed to sit beside Burp Suite or
Caido: those tools edit, replay, and organize traffic while Mimic owns the final
upstream TLS handshake and HTTP presentation.

One statically linked Go binary provides the daemon and its control client. A
separate, small Caido plugin bridges Caido's upstream connection hook to the
daemon.

## Status

Mimic is pre-release software approaching its first public release. The wire
and control protocols are versioned, but backward compatibility is not promised
until `v1.0.0`.

Implemented today:

- named and captured uTLS ClientHello profiles;
- pinned Chrome, Firefox, Safari, iOS, and Android presets;
- JA4 calculation from the ClientHello bytes actually written to the network;
- profile conformance probes with text/JSON evidence and mismatch exit status;
- per-host routing and live default-profile changes;
- HTTP forward proxy listeners on TCP and Unix sockets;
- opaque CONNECT tunneling and optional CA-backed HTTPS interception;
- a native Caido upstream bridge without a second TLS interception layer;
- SOCKS5 CONNECT and UDP ASSOCIATE;
- HTTP/1.1 header ordering and HTTP/2 upstream translation;
- host-allowlisted TLS 1.0/1.1 compatibility retries;
- structured text or JSON logs with a live-adjustable level;
- strict TOML validation and a newline-framed local control API.

## Start here

The [five-minute quickstart](docs/quickstart.md) builds a disposable local lab
and proves JA4 conformance, profiled HTTP, and HTTPS interception:

```sh
./lab/mimic-lab up
./lab/mimic-lab demo
```

Continue with the [complete hands-on tutorial](docs/tutorial.md) for routes,
live control, legacy TLS, SOCKS, the Caido plugin, and Burp Suite. The lab uses
a locked, self-contained `uv` script plus Docker Compose, starts in two to three
minutes on a typical development machine, and never installs its CA into the
host trust store.

For a native build, Mimic requires Go 1.25 or newer. Release archives contain a
standalone binary that needs no Go or Node runtime for normal operation:

```sh
cp config.example.toml config.toml
make build VERSION=0.1.0
./mimic validate -config ./config.toml
./mimic daemon -config ./config.toml
```

`MIMIC_CONFIG` sets the default configuration path. Otherwise Mimic uses
`$XDG_CONFIG_HOME/mimic/config.toml` or the platform-equivalent user config
directory.

## Choosing a listener

An ordinary CONNECT proxy cannot change the ClientHello inside an opaque TLS
tunnel. Use an interception or native bridge path when Mimic must originate the
upstream handshake.

| Listener | Changes upstream TLS | Intended use |
|---|---:|---|
| HTTP `mode = "tunnel"` | No | Ordinary forward proxy and opaque HTTPS |
| HTTP `mode = "intercept"` | Yes | Browser or Burp trusts the local Mimic CA |
| `caido` | Yes | Caido supplies plaintext requests through `onUpstream` |
| SOCKS5 | No | General TCP and SOCKS5 UDP tunneling |

For interception, generate a local CA, enable `[mitm]`, enable the intercept
listener, and trust only the public certificate in the client:

```sh
./mimic init-ca -cert ./certs/mimic-ca.pem -key ./certs/mimic-ca-key.pem
```

The private key is created with mode `0600`, is never served by Mimic, and must
not be shared or imported into a trust store.

## Fingerprint scope

Mimic controls the client-side TLS ClientHello and, when it handles plaintext
HTTP, the HTTP identity. `mimic probe` calculates JA4 from the exact ClientHello
bytes written by uTLS and compares it with the profile's expected value. Bundled
expectations are regression fixtures for Mimic's pinned uTLS presets; they do
not by themselves certify parity with a real browser or every sensor.

JA4H remains optional operator metadata and is not calculated. Validate
important TLS and HTTP profiles against a controlled external sensor.

JA4S and JA4X describe server-side behavior and certificates. They are not
generally properties an outbound client proxy can reproduce. HTTP/2 uses Go's
frame implementation, so Mimic does not claim browser-identical SETTINGS or
frame ordering.

## Legacy TLS boundary

The configured browser/device profile is always attempted first. A lower retry
occurs only if all of the following are true:

1. legacy support and retry are enabled;
2. the hostname matches `legacy.allow_hosts`;
3. the failure matches an allowed protocol or cipher error; and
4. the failure is not a certificate-verification error.

Retries are warned and counted in daemon status. Certificate verification stays
enabled unless an operator explicitly opts out for a route or the legacy policy.
Mimic supports TLS 1.0 through TLS 1.3. It does not support SSLv2 or SSLv3.

## Documentation

- [Five-minute quickstart](docs/quickstart.md)
- [Complete hands-on tutorial](docs/tutorial.md)
- [CLI reference](docs/cli.md)
- [Configuration reference](docs/configuration.md)
- [Profile format](docs/profiles.md)
- [Control and Caido bridge protocols](docs/protocols.md)
- [Burp and Caido integration](docs/integrations.md)
- [Architecture](docs/architecture.md)
- [Deployment](docs/deployment.md)
- [Testing](docs/testing.md)
- [Release process](docs/releasing.md)
- [Threat model](docs/threat-model.md)
- [Security policy](SECURITY.md)

## Known limitations

- HTTP/3/QUIC is not implemented. UDP support is SOCKS5 datagram relay only.
- Intercepted WebSocket upgrades are not yet tunneled.
- HTTP/2 translation does not emulate browser frame-level fingerprints.
- Built-in profiles are pinned rather than automatically tracking browsers.
- Listener, control endpoint, and CA changes require a daemon restart. Profiles,
  routes, legacy policy, and log level can reload live.
- The Caido plugin is currently backend-only and targets `127.0.0.1:7777`.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Mimic is
licensed under the [MIT License](LICENSE). Dependency licensing is summarized in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). JA4 TLS fingerprinting is
covered by the separate [FoxIO JA4 license](LICENSE-JA4).

Use Mimic only with systems and traffic you are authorized to test.
