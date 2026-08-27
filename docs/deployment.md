# Deployment

## Standalone binary

Official release archives contain one `mimic` executable, documentation, the
systemd example, an example config, and the source subset needed by the optional
Docker tutorial lab. The executable itself has no runtime dependency on that
source, Docker, Go, or Node. Verify the published checksum before installing.

```sh
install -m 0755 mimic /usr/local/bin/mimic
install -d -m 0750 /etc/mimic
install -m 0640 config.example.toml /etc/mimic/config.toml
/usr/local/bin/mimic validate -config /etc/mimic/config.toml
```

Keep listeners on loopback by default. If remote access is required, combine a
narrow `allow_cidrs` list with host firewall rules. Mimic does not provide proxy
authentication.

## systemd

An example unit is provided at [`packaging/systemd/mimic.service`](../packaging/systemd/mimic.service).
It assumes:

- executable: `/usr/local/bin/mimic`;
- configuration: `/etc/mimic/config.toml`;
- service account: `mimic`;
- runtime sockets: `/run/mimic/`.

Create the service user and adjust the example configuration's Unix endpoints
to `/run/mimic/*.sock`. If interception is enabled, store the CA private key
outside the repository with mode `0600` and ownership restricted to the service
account.

```sh
install -m 0644 packaging/systemd/mimic.service /etc/systemd/system/mimic.service
systemctl daemon-reload
systemctl enable --now mimic
journalctl -u mimic -f
```

## Containers

No container image is required for normal deployment. The Compose setup under
`lab/` is intentionally an educational environment, not a production image. If
packaging Mimic in a container, mount the TOML and CA key read-only, expose only
intended proxy ports, and use a persistent or host-visible control socket only
when necessary.

## Resource behavior

- The daemon uses a goroutine per TCP connection.
- HTTP upstream connections are not pooled in the current release.
- Generated interception certificates are cached in memory per hostname.
- SOCKS5 UDP sessions expire after two idle minutes.
