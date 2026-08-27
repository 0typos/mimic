# Threat model

## Assets

- intercepted plaintext HTTP requests and responses;
- the local interception CA private key;
- upstream authentication headers, cookies, and bodies;
- control authority to change profiles, reload config, or stop the daemon;
- network reachability available to HTTP, Caido, SOCKS, and UDP listeners.

## Trust boundaries

1. Client to proxy listener.
2. Client to generated MITM certificate in intercept mode.
3. Caido plugin to the local `MIMIC/1` bridge.
4. CLI/plugin to the local control endpoint.
5. Mimic to DNS and the upstream target.

## Defenses

- Example TCP/UDP listeners bind loopback and use explicit loopback CIDRs.
- The control server refuses non-loopback TCP and creates Unix sockets `0600`.
- Unix parent directories are created `0700`.
- Existing non-socket paths are never replaced when binding Unix endpoints.
- CA generation refuses overwrites and writes the private key `0600`.
- Certificate verification is enabled by default.
- Legacy retries require both a host allowlist and an eligible error.
- Certificate errors are not in the default retry list.
- TOML is strict and captured ClientHellos are parsed before daemon startup.
- Caido prefaces have a fixed size limit and explicit `host:port` target syntax.

## Operator responsibilities

- Use the tool only with explicit authorization.
- Keep listeners on loopback or behind a firewall and narrow CIDR allowlists.
- Protect the CA key and control socket as credentials.
- Treat debug logs as potentially sensitive metadata.
- Avoid global `insecure_skip_verify`; use isolated route overrides only when
  certificate validation cannot be made to work in a test lab.
- Review `legacy.allow_hosts`; never use `*` casually.

## Known residual risks

- Proxy listeners have no username/password authentication.
- Control protocol v1 has no application authentication.
- Any process running as the same account can normally reach loopback and may
  reach a TCP control/bridge endpoint.
- Interception intentionally exposes plaintext inside the Mimic process.
- The in-memory leaf cache is not bounded by count.
- SOCKS5 UDP association is protected by listener CIDRs but is not tied to a
  live authenticated TCP association.
- TLS 1.0/1.1 and disabled certificate verification provide weak or absent peer
  authentication by design and can expose sensitive data.
- Fingerprint emulation can be inaccurate; it is not an anonymity guarantee.

## Out of scope

- Endpoint malware or a compromised root account;
- hiding traffic from the operator of Mimic;
- anonymity, anti-forensics, or bypassing an authorization boundary;
- SSLv2, SSLv3, QUIC, and SSH fingerprint emulation.
