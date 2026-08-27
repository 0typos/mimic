# Mimic lab

This Docker Compose lab is the executable companion to the
[quickstart](../docs/quickstart.md) and [full tutorial](../docs/tutorial.md).
It builds Mimic, creates an isolated interception CA, and starts deterministic
HTTP, TLS 1.2/1.3, and TLS-1.0-only origins. No public target is contacted and
no CA is added to the host trust store.

## Commands

```sh
./lab/run.sh up        # build and wait for healthy services (target: <3 min)
./lab/run.sh demo      # three-step, five-minute quickstart
./lab/run.sh smoke     # verify every lab transport and control workflow
./lab/run.sh status    # daemon profile, counters, and uptime
./lab/run.sh profiles  # available profiles
./lab/run.sh logs      # follow daemon logs (Ctrl-C exits log view)
./lab/run.sh down      # remove containers and network
```

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
`/etc/mimic/.state/http.sock` inside the Mimic container. The smoke command
exercises it from the same container so its `0600` permissions remain portable
across Docker hosts.

## Troubleshooting

Run `docker compose -f lab/compose.yaml ps` and `./lab/run.sh logs`. A local
service already using port `7777`, `11080`, `18080`, or `18081` must be stopped
or the corresponding host-side mapping changed. Rebuild after source changes
with `./lab/run.sh up`; Compose reuses unchanged layers.
