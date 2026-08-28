#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: $0 VERSION (for example, 0.1.0)" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$repo_root/dist"
stage_dir="$(mktemp -d)"
trap 'rm -rf "$stage_dir"' EXIT
# ZIP cannot represent timestamps before 1980. Using its earliest timestamp as
# the default also gives tar archives stable metadata across repeated builds.
source_date_epoch="${SOURCE_DATE_EPOCH:-315532800}"

mkdir -p "$output_dir"
plugin_dir="$repo_root/integrations/caido/dist/plugin_package"
if [[ -d "$plugin_dir" ]]; then
  plugin_version="$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)",*$/\1/p' "$plugin_dir/manifest.json")"
  if [[ "$plugin_version" != "$version" ]]; then
    echo "Caido manifest version $plugin_version does not match release version $version" >&2
    exit 1
  fi
  for package_file in "$repo_root/integrations/caido/package.json" "$repo_root"/integrations/caido/packages/*/package.json; do
    package_version="$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)",*$/\1/p' "$package_file" | head -1)"
    if [[ "$package_version" != "$version" ]]; then
      echo "Caido package $package_file version $package_version does not match release version $version" >&2
      exit 1
    fi
  done
fi

find "$output_dir" -maxdepth 1 -type f -name 'mimic-*' -delete
find "$output_dir" -maxdepth 1 -type f -name 'SHA256SUMS' -delete

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
)

for target in "${targets[@]}"; do
  read -r target_os target_arch <<<"$target"
  archive_name="mimic-${version}-${target_os}-${target_arch}"
  package_dir="$stage_dir/$archive_name"
  mkdir -p "$package_dir"

  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
    go build -trimpath -ldflags="-s -w -X main.version=$version" \
    -o "$package_dir/mimic" "$repo_root/cmd/mimic"
  cp "$repo_root/README.md" "$repo_root/LICENSE" "$repo_root/LICENSE-JA4" \
    "$repo_root/CHANGELOG.md" "$repo_root/CONTRIBUTING.md" \
    "$repo_root/SECURITY.md" \
    "$repo_root/THIRD_PARTY_NOTICES.md" "$repo_root/config.example.toml" \
    "$repo_root/go.mod" "$repo_root/go.sum" "$repo_root/.dockerignore" \
    "$package_dir/"
  cp -R "$repo_root/cmd" "$repo_root/internal" "$repo_root/lab" \
    "$repo_root/docs" "$repo_root/packaging" "$package_dir/"
  # Never package the generated tutorial CA private key from a local lab run.
  rm -rf "$package_dir/lab/.state"
  mkdir -p "$package_dir/integrations/caido"
  cp "$repo_root/integrations/caido/README.md" "$package_dir/integrations/caido/"
  tar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@$source_date_epoch" -C "$stage_dir" -czf \
    "$output_dir/$archive_name.tar.gz" "$archive_name"
done

if [[ -d "$plugin_dir" ]]; then
  plugin_stage="$stage_dir/caido-plugin"
  mkdir -p "$plugin_stage"
  cp -R "$plugin_dir/." "$plugin_stage/"
  find "$plugin_stage" -exec touch -d "@$source_date_epoch" {} +
  (
    cd "$plugin_stage"
    find . -type f -printf '%P\n' | LC_ALL=C sort | \
      zip -X -q "$output_dir/mimic-caido-${version}.zip" -@
  )
fi

(
  cd "$output_dir"
  sha256sum mimic-* > SHA256SUMS
)

echo "release artifacts written to $output_dir"
