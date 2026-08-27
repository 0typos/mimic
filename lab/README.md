# Mimic lab

This Docker Compose lab is the executable companion to the
[quickstart](../docs/quickstart.md) and [full tutorial](../docs/tutorial.md).
It builds Mimic, creates an isolated interception CA, and starts deterministic
HTTP, TLS 1.2/1.3, and TLS-1.0-only origins. No public target is contacted and
no CA is added to the host trust store.

## Commands

Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/) first.
The executable PEP 723 launcher uses its adjacent lockfile, so `uv` supplies the
exact Python dependencies without a manually managed virtual environment.

```sh
./lab/mimic-lab up        # build and wait for healthy services (target: <3 min)
./lab/mimic-lab demo      # three-step, five-minute quickstart
./lab/mimic-lab check     # verify every lab transport and control workflow
./lab/mimic-lab status    # daemon profile, counters, and uptime
./lab/mimic-lab profiles  # available profiles
./lab/mimic-lab logs      # follow daemon logs (Ctrl-C exits log view)
./lab/mimic-lab down      # remove containers and network
```

Run `./lab/mimic-lab install` to make `mimic-lab` available from any directory.
It creates a guarded symlink in `uv tool dir --bin`; `mimic-lab uninstall`
removes only a symlink that points back to this checkout.

| File | Purpose |
|---|---|
| `mimic-lab` | PEP 723 `uv` CLI for `up`, `demo`, `check`, operation, and installation |
| `mimic-lab.lock` | Resolved Python versions and package hashes for reproducible runs |
| `compose.yaml` | Isolated Mimic and deterministic-origin services |
| `mimic.toml` | Lab-only profiles, routes, listeners, and legacy policy |

The first launcher run fetches Typer and its dependencies into `uv`'s cache;
subsequent runs reuse that environment.

The generated lab CA and key remain in the ignored `lab/.state/` directory so
restarts are quick. Delete that directory after `down` if you want to remove
them. The private key must never be imported into a trust store or shared.

## Published host ports

| Port | Interface |
|---:|---|
| `18080/tcp` | HTTP tunnel proxy |
| `18081/tcp` | HTTP/HTTPS interception proxy |
| `11080/tcp,udp` | SOCKS5 CONNECT and UDP relay |
| `7777/tcp` | Caido native upstream bridge |

Every port binds `127.0.0.1`. The permissive listener CIDRs and disabled
upstream certificate verification in `mimic.toml` are safe only inside this
isolated lab and must not be copied into a deployed configuration.

The lab also creates an HTTP proxy Unix socket at
`/etc/mimic/.state/http.sock` inside the Mimic container. The `check` command
exercises it from the same container so its `0600` permissions remain portable
across Docker hosts.

## Troubleshooting

Run `docker compose -f lab/compose.yaml ps` and `./lab/mimic-lab logs`. A local
service already using port `7777`, `11080`, `18080`, or `18081` must be stopped
or the corresponding host-side mapping changed. Rebuild after source changes
with `./lab/mimic-lab up`; Compose reuses unchanged layers.
