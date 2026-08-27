# Complete hands-on tutorial

This tutorial starts with a disposable local environment and ends with the
same operating model used for a real deployment. It covers JA4 conformance,
HTTP identity, interception, routes, live control, bounded legacy TLS, SOCKS,
Caido, Burp Suite, logs, and cleanup. Allow 25–40 minutes to explore it; setup
itself is designed to finish in two to three minutes.

Use Mimic only with systems and traffic you are authorized to test.

## 1. Understand the lab boundary

Docker Compose is a better fit than a VM here: it gives each origin a stable
DNS name and isolates its intentionally obsolete TLS policy, while requiring a
single command and no guest operating-system boot.

| Component | Purpose |
|---|---|
| `mimic` | Daemon, control client, five proxy listeners, and generated CA |
| `modern-origin:8443` | Self-signed HTTPS server accepting TLS 1.2–1.3 |
| `legacy-origin:9443` | Self-signed HTTPS server accepting only TLS 1.0 |
| `default-origin:8080` | Plain HTTP identity inspector with no host route |

The origin aliases share one container but use distinct ports and policies.
They return JSON describing the protocol, TLS version, cipher, user agent, and
headers they observed.

The lab publishes only loopback ports. Its `insecure_skip_verify = true` and
container-wide listener CIDRs are deliberate concessions for ephemeral,
self-signed origins. Never copy those values into a production configuration.

## 2. Start and inspect the environment

Prerequisites are Docker with Compose v2.20+ and `curl`. From a source checkout
or release archive:

```sh
time ./lab/run.sh up
docker compose -f lab/compose.yaml ps
```

Both services should be `healthy`. The target startup time is under three
minutes, including the first image build. Cached starts should take seconds.
If startup fails, see [Troubleshooting](#12-troubleshooting).

View the loaded profiles and daemon state:

```sh
./lab/run.sh profiles
./lab/run.sh status
```

The control endpoint stays inside the container on loopback. The wrapper runs
the same `mimic ctl` binary in that container; there is no separate admin API.

## 3. Verify the emitted JA4

Run a conformance probe against the modern origin:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  mimic probe -config /etc/mimic/config.toml \
  -profile chrome-133 -target modern-origin:8443 -raw
```

Look for:

```text
expected JA4: t13d1516h2_8daaf6152771_d8a2da3f94cd
observed JA4: t13d1516h2_8daaf6152771_d8a2da3f94cd
result:       PASS
```

The observed value comes from the exact ClientHello bytes Mimic wrote. `JA4_r`
is the normalized input and `JA4_ro` preserves extension order for diagnosis.
This verifies Mimic's pinned uTLS preset, not eternal parity with a browser of
the same marketing version. Important profiles should also be checked against
your controlled external sensor.

JA4 is the JA4+ member Mimic calculates directly. A profile may store an
expected JA4H as operator metadata, but Mimic does not calculate it. JA4S and
JA4X describe server/certificate behavior and are not properties this outbound
client proxy can reproduce. Mimic also does not claim browser-identical HTTP/2
SETTINGS, HPACK, or frame ordering.

## 4. Know which proxy modes change TLS

The central rule is simple:

| Path | Mimic sees plaintext HTTP | Mimic creates upstream TLS | Fingerprint source |
|---|---:|---:|---|
| Plain HTTP through tunnel listener | yes | no TLS involved | Mimic HTTP profile |
| HTTPS `CONNECT` through tunnel listener | no | no | original client |
| HTTPS through intercept listener | yes | yes | Mimic |
| SOCKS5 | no | no | original client |
| Caido bridge | yes | yes | Mimic |

Send plain HTTP through the tunnel listener:

```sh
curl --noproxy "" --proxy http://127.0.0.1:18080 \
  http://default-origin:8080/inspect?lesson=http
```

The response contains the Chrome 133 `user_agent` because Mimic handled a
plaintext request and applied the active profile's HTTP identity.

Now use interception for HTTPS:

```sh
curl --noproxy "" --proxy http://127.0.0.1:18081 \
  --cacert lab/.state/mimic-ca.pem \
  https://modern-origin:8443/inspect?lesson=intercept
```

The returned `tls` value describes Mimic's connection to the origin. `curl`
trusts the lab CA only for this invocation. Do not use `-k`: that would hide a
broken downstream trust setup.

## 5. Change profiles without restarting

The lab defines `lab-firefox`, a saved profile backed by the Firefox 120
ClientHello plus a distinctive HTTP header. Change the daemon-wide default:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  mimic ctl -socket tcp://127.0.0.1:9090 use lab-firefox

curl --noproxy "" --proxy http://127.0.0.1:18080 \
  http://default-origin:8080/inspect?lesson=profile
```

The result now includes `Firefox/120.0` and `X-Lab-Profile: lab-firefox`.
Selection is live but not persisted: restart uses `runtime.default_profile`.

Reset it when finished:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  mimic ctl -socket tcp://127.0.0.1:9090 use chrome-133
```

To try your own saved profile, edit `lab/mimic.toml`, add a
`[profiles.NAME]` table, then reload:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  mimic ctl -socket tcp://127.0.0.1:9090 reload
```

Profiles, routes, runtime timeouts, legacy policy, and log level reload live.
Listener, control, logging-format, and CA changes require a restart. See the
[profile format](profiles.md) before using a captured ClientHello.

## 6. Apply host routes and per-request overrides

`modern-origin` and `legacy-origin` have explicit Chrome routes in
`lab/mimic.toml`. Set the default to Firefox again, then request the routed host:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  mimic ctl -socket tcp://127.0.0.1:9090 use lab-firefox

curl --noproxy "" --proxy http://127.0.0.1:18081 \
  --cacert lab/.state/mimic-ca.pem \
  https://modern-origin:8443/inspect?lesson=route
```

The origin sees Chrome because first-match host routing overrides the live
default. For one intercepted HTTP request, `X-Mimic-Profile: lab-firefox`
selects a profile and is removed before forwarding:

```sh
curl --noproxy "" --proxy http://127.0.0.1:18081 \
  --cacert lab/.state/mimic-ca.pem \
  -H 'X-Mimic-Profile: lab-firefox' \
  https://modern-origin:8443/inspect?lesson=override
```

Reset the default to Chrome before continuing:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  mimic ctl -socket tcp://127.0.0.1:9090 use chrome-133
```

## 7. Exercise bounded legacy TLS

Mimic first presents the selected modern profile. It retries lower only when
the host allowlist, route policy, enabled switch, and eligible error list all
permit it. Probe the TLS-1.0-only origin:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  mimic probe -config /etc/mimic/config.toml \
  -target legacy-origin:9443 -format json
```

The JSON contains two attempts: the first modern handshake fails, and the
second has `"legacy": true` with `"negotiated_version": "TLS1.0"`. Confirm the
same policy through interception:

```sh
curl --noproxy "" --proxy http://127.0.0.1:18081 \
  --cacert lab/.state/mimic-ca.pem \
  https://legacy-origin:9443/inspect?lesson=legacy

./lab/run.sh status
```

The daemon's `tls_fallbacks` counter increases. A certificate validation error
does not by itself authorize a downgrade. Mimic supports TLS 1.0–1.3; it does
not support SSLv2 or SSLv3.

## 8. Use Unix sockets and compare SOCKS behavior

First exercise the Unix-socket HTTP listener. The socket has mode `0600`, so
the lab invokes its small request helper inside the Mimic container:

```sh
docker compose -f lab/compose.yaml exec -T mimic \
  /usr/local/bin/lab-origin unix-check \
  /etc/mimic/.state/http.sock default-origin:8080
```

This is the same forward-proxy protocol as a TCP HTTP listener, carried over a
filesystem-scoped connection. In a native deployment, put the socket in a
directory accessible only to the intended service account.

SOCKS is useful for connectivity, including UDP ASSOCIATE, but it relays the
client's TLS bytes. It does not impersonate a browser:

```sh
curl --noproxy "" --socks5-hostname 127.0.0.1:11080 --insecure \
  https://modern-origin:8443/inspect?lesson=socks
```

The origin sees curl's user agent. `--insecure` is needed here because curl is
talking directly to the self-signed lab origin through an opaque SOCKS tunnel;
Mimic's interception CA is not involved.

## 9. Use the Caido bridge

First prove the wire path without installing Caido:

```sh
docker compose -f lab/compose.yaml exec -T origin \
  /lab-origin caido-check mimic:7777 modern-origin:8443 lab-firefox
```

The helper sends the versioned `MIMIC/1` preface followed by a plaintext HTTP
request. Mimic selects `lab-firefox` for TLS, originates the connection, and
returns the response. On HTTP/1.1, the bridge deliberately retains Caido's raw
request headers rather than replacing them with the profile's HTTP identity.

For the real UI workflow:

1. Use the release asset `mimic-caido-VERSION.zip`, or build it from source with
   `corepack enable && make caido` and use
   `integrations/caido/dist/plugin_package.zip`.
2. In Caido, open **Plugins**, choose **Install Package**, and select the ZIP.
3. In **Plugins > Installed**, ensure the backend component is enabled.
4. In Caido's **Upstream Plugins** settings, enable **Mimic Upstream** only for
   `modern-origin` and `legacy-origin` while using the lab.
5. With the lab running, send `https://modern-origin:8443/inspect` through
   Caido's Replay or proxied browser and inspect the response JSON.

Caido retains Proxy, Intercept, Replay, Automate, and history. Its `onUpstream`
hook gives Mimic a plaintext request path, so no second Mimic CA is required.
The current backend-only plugin targets fixed `127.0.0.1:7777` and does not yet
offer profile selection or daemon status in Caido's UI.

Official Caido references: [installing plugins](https://docs.caido.io/app/guides/plugins_installing)
and [enabling plugin components](https://docs.caido.io/app/guides/plugins_managing).

## 10. Put Mimic behind Burp Suite

Burp terminates the browser TLS connection, then Mimic terminates Burp's
upstream TLS connection. Each side must trust the CA presented directly to it:

1. Keep Burp's normal proxy listener and make the browser trust Burp's CA (or
   use Burp's preconfigured browser).
2. In **Settings > Network > TLS > Custom CA certificates**, add the public
   `lab/.state/mimic-ca.pem`. Never add the matching private key.
3. In **Settings > Network > Connections > Upstream proxy servers**, add a
   project rule for destination host `modern-origin`, proxy host `127.0.0.1`,
   and proxy port `18081`. Add `legacy-origin` separately if desired.
4. Send `https://modern-origin:8443/inspect` from Burp's browser or Repeater.
5. Confirm the response shows the routed Chrome user agent and modern TLS, then
   inspect `./lab/run.sh logs` for the selected profile.

Do not point Burp at port `18080` when the goal is fingerprint replacement:
that tunnel listener sees only Burp's opaque CONNECT payload. Start with narrow
destination rules before considering a wildcard.

Official Burp references: [upstream proxy rules](https://portswigger.net/burp/documentation/desktop/settings/network/connections),
[custom CA trust](https://portswigger.net/burp/documentation/desktop/settings/network/tls),
and [Burp browser/CA setup](https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate).

## 11. Operate and diagnose the daemon

Follow logs and change verbosity live:

```sh
./lab/run.sh logs

docker compose -f lab/compose.yaml exec -T mimic \
  mimic ctl -socket tcp://127.0.0.1:9090 log-level debug
```

Use `Ctrl-C` to leave the log view; the containers keep running. Status reports
connections, handled requests, legacy fallbacks, uptime, and current profile.
The one-command regression tour is useful after configuration changes:

```sh
./lab/run.sh smoke
```

## 12. Troubleshooting

- **Docker permission denied:** start Docker Desktop/Engine and ensure your user
  can access its socket, then retry `docker info`.
- **Port already allocated:** stop the conflicting local service or change the
  host side of the mapping in `lab/compose.yaml`. Port `7777` is fixed because
  the current Caido plugin expects it.
- **Service is unhealthy:** run `docker compose -f lab/compose.yaml ps` and
  `docker compose -f lab/compose.yaml logs --no-color`.
- **Certificate error on port 18081:** use the generated public CA at
  `lab/.state/mimic-ca.pem`; do not use the origin's self-signed certificate.
- **Hostname does not resolve locally:** keep proxy-side DNS enabled. Curl needs
  `--noproxy ""`; SOCKS needs `--socks5-hostname`, not `--socks5`.
- **JA4 mismatch:** use `mimic probe -raw`, verify the profile and DNS hostname,
  and compare both values. An IP target changes the SNI-related JA4 field.
- **Reload rejected:** listener, control, and MITM endpoint changes require
  `./lab/run.sh down && ./lab/run.sh up`.

## 13. Clean up and move toward deployment

Stop and remove the lab containers and network:

```sh
./lab/run.sh down
```

Compose deliberately preserves `lab/.state/` for fast restarts. The only trust
you granted with the documented curl commands was process-local, so there is no
host trust-store entry to undo. To discard the lab CA and its private key,
delete `lab/.state/` after the containers are down.

For deployment, return to loopback listeners and narrow CIDRs, restore
certificate verification, set a host allowlist for any legacy retry, protect
the Unix or loopback control endpoint, and store the interception key with mode
`0600`. Continue with the [deployment guide](deployment.md),
[configuration reference](configuration.md), and [threat model](threat-model.md).
