# Security policy

## Supported versions

Until the first public release, only the current `main` branch receives security
fixes. After release, the latest minor release will be supported; older `0.x`
versions may require upgrading rather than receiving a backport.

## Reporting a vulnerability

Do not open a public issue containing an exploit, CA material, credentials,
captured traffic, or target details. Use the repository's private GitHub Security
Advisory reporting flow after publication. If private reporting is unavailable,
contact a maintainer privately and provide only enough non-sensitive information
to establish a secure reporting channel.

Include:

- affected Mimic version or commit;
- operating system and architecture;
- listener and mode involved;
- minimal reproduction without third-party secrets;
- impact and whether the issue is remotely reachable; and
- any suggested mitigation.

Maintainers should acknowledge a complete report within seven days, coordinate
a fix and advisory privately, and credit the reporter unless anonymity is
requested.

## Security-sensitive configuration

The following are deliberate capabilities rather than safe defaults for general
internet traffic:

- `insecure_skip_verify = true`;
- TLS 1.0/1.1 retry;
- a remote proxy listener with an empty `allow_cidrs` list;
- exposing the control or Caido bridge endpoint beyond the local host;
- installing the interception CA into a broad system trust store.

See [the threat model](docs/threat-model.md) for trust boundaries and residual
risks.
