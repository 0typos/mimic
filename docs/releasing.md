# Release process

Mimic uses semantic version tags such as `v0.1.0`. The binary and Caido plugin
should use the same version for coordinated releases.

## Prepare

1. Update `CHANGELOG.md` and remove any unresolved release blockers.
2. Update the version in `integrations/caido/caido.config.ts` and both plugin
   `package.json` files.
3. Run `make check audit caido` from a clean checkout.
4. Run `./scripts/build-release.sh 0.1.0` and inspect every archive.
5. Complete the manual checks in `docs/testing.md`.

Run the packaging script on Linux with GNU tar. Set `SOURCE_DATE_EPOCH` to a
release timestamp when deterministic archive metadata must differ from the
default earliest ZIP timestamp (`1980-01-01T00:00:00Z`).

## Tag

```sh
git tag -s v0.1.0 -m "Mimic v0.1.0"
git push origin main v0.1.0
```

The release workflow rebuilds Linux and macOS archives, rebuilds the Caido
package, generates SHA-256 checksums, and attaches them to a draft GitHub
release. Review the draft before publishing it.

## Supported release targets

- Linux amd64 and arm64, built with `CGO_ENABLED=0`;
- macOS amd64 and arm64;
- Caido plugin package zip.

Windows is not an initial release target because the default control and local
proxy deployment relies on Unix sockets. TCP loopback operation may work, but it
is not yet included in the tested release matrix.
