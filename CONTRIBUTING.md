# Contributing

Contributions are welcome for authorized testing, protocol interoperability,
documentation, and defensive research use cases.

## Development setup

- Go 1.25 or newer;
- Node.js 20 or newer plus Corepack for Caido plugin work;
- a C toolchain for race-enabled Go tests.

```sh
git clone https://github.com/msmythe/mimic.git
cd mimic
make check
make caido
```

## Change expectations

- Add tests for observable behavior and failure paths.
- Keep fingerprint claims measurable and avoid calling metadata “verified.”
- Do not implement non-JA4 methods from the JA4+ family without first reviewing
  and documenting their separate licensing requirements.
- Preserve strict TOML validation and document new fields.
- Treat new network binds, trust changes, downgrade behavior, and subprocesses
  as security-sensitive design changes.
- Do not add inline secrets, captured production traffic, private CA keys, or
  target-specific data to fixtures.
- Keep the daemon independent from Burp or Caido-specific APIs; integrations
  should use versioned local protocols.

Run before submitting:

```sh
make check
make audit
make caido
```

## Commit and pull-request guidance

Use focused commits with an imperative summary. Explain protocol or security
tradeoffs in the pull request. Breaking configuration or local-protocol changes
must update the schema version or protocol version and include migration notes.

By contributing, you agree that your contribution is licensed under the MIT
License.
