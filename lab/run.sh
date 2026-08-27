#!/usr/bin/env bash
set -euo pipefail

lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "$lab_dir/compose.yaml")

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Mimic lab requires $1." >&2
    exit 1
  fi
}

ctl() {
  "${compose[@]}" exec -T mimic mimic ctl -socket tcp://127.0.0.1:9090 "$@"
}

probe() {
  "${compose[@]}" exec -T mimic mimic probe -config /etc/mimic/config.toml "$@"
}

http_request() {
  curl --silent --show-error --fail --noproxy "" --proxy http://127.0.0.1:18080 "$@"
}

intercept_request() {
  curl --silent --show-error --fail --noproxy "" --proxy http://127.0.0.1:18081 \
    --cacert "$lab_dir/.state/mimic-ca.pem" "$@"
}

assert_contains() {
  local output="$1"
  local expected="$2"
  local label="$3"
  if ! grep -Fq "$expected" <<<"$output"; then
    echo "FAIL: $label (missing: $expected)" >&2
    echo "$output" >&2
    exit 1
  fi
  printf 'PASS: %s\n' "$label"
}

assert_matches() {
  local output="$1"
  local pattern="$2"
  local label="$3"
  if ! grep -Eq "$pattern" <<<"$output"; then
    echo "FAIL: $label (pattern: $pattern)" >&2
    echo "$output" >&2
    exit 1
  fi
  printf 'PASS: %s\n' "$label"
}

up() {
  need docker
  mkdir -p "$lab_dir/.state"
  local started=$SECONDS
  "${compose[@]}" up --build --detach --wait --wait-timeout 180
  local elapsed=$((SECONDS - started))
  printf '\nMimic lab is ready in %ss. Run: ./lab/run.sh demo\n' "$elapsed"
}

demo() {
  need docker
  need curl
  echo "1/3  Prove the configured Chrome ClientHello matches its expected JA4"
  probe -profile chrome-133 -target modern-origin:8443

  echo
  echo "2/3  Send plaintext HTTP through Mimic and inspect its HTTP identity"
  http_request http://default-origin:8080/inspect?via=quickstart

  echo
  echo "3/3  Let Mimic intercept HTTPS and originate the upstream TLS connection"
  intercept_request https://modern-origin:8443/inspect?via=quickstart

  echo
  echo "Success: JA4 conformance, profiled HTTP, and HTTPS interception all worked."
}

smoke() {
  need docker
  need curl
  echo "Running the complete Mimic lab workflow..."

  local output
  output="$(probe -profile chrome-133 -target modern-origin:8443 -format json)"
  assert_contains "$output" '"status": "pass"' "modern ClientHello matches Chrome JA4"
  assert_contains "$output" '"negotiated_version": "TLS1.3"' "modern origin negotiates TLS 1.3"

  output="$(http_request http://default-origin:8080/inspect?via=http)"
  assert_contains "$output" 'Chrome/133.0.0.0' "HTTP proxy applies the default profile identity"

  ctl use lab-firefox >/dev/null
  output="$(http_request http://default-origin:8080/inspect?via=live-profile)"
  assert_contains "$output" 'Firefox/120.0' "control API changes the live default profile"
  assert_contains "$output" 'lab-firefox' "custom profile headers reach the origin"

  output="$(intercept_request https://modern-origin:8443/inspect?via=route)"
  assert_contains "$output" 'Chrome/133.0.0.0' "host route overrides the live default"
  assert_contains "$output" '"tls":"TLS1.3"' "interception creates modern upstream TLS"

  ctl use chrome-133 >/dev/null
  output="$(probe -target legacy-origin:9443 -format json)"
  assert_contains "$output" '"legacy": true' "eligible TLS failure triggers the bounded fallback"
  assert_contains "$output" '"negotiated_version": "TLS1.0"' "legacy endpoint negotiates TLS 1.0"

  output="$(intercept_request https://legacy-origin:9443/inspect?via=legacy)"
  assert_contains "$output" '"tls":"TLS1.0"' "intercepted request reaches the legacy origin"

  output="$(curl --silent --show-error --fail --insecure --noproxy "" --socks5-hostname 127.0.0.1:11080 https://modern-origin:8443/inspect?via=socks)"
  assert_contains "$output" 'curl/' "SOCKS preserves the client HTTP/TLS identity"

  output="$("${compose[@]}" exec -T mimic /usr/local/bin/lab-origin unix-check /etc/mimic/.state/http.sock default-origin:8080)"
  assert_contains "$output" '"path":"/inspect?via=unix"' "Unix-socket HTTP listener forwards requests"
  assert_contains "$output" 'Chrome/133.0.0.0' "Unix-socket listener applies the active profile"

  ctl log-level debug >/dev/null
  output="$("${compose[@]}" exec -T origin /lab-origin caido-check mimic:7777 modern-origin:8443 lab-firefox)"
  assert_contains "$output" '"path":"/inspect?via=caido"' "Caido bridge relays the plaintext request"
  assert_contains "$output" '"tls":"TLS1.3"' "Caido bridge originates upstream TLS"
  output="$("${compose[@]}" logs --no-color mimic)"
  assert_contains "$output" 'profile=lab-firefox' "Caido preface selects its TLS profile"
  ctl log-level info >/dev/null

  output="$(ctl status)"
  assert_matches "$output" '"tls_fallbacks": [1-9][0-9]*' "daemon status counts legacy fallbacks"
  echo "All Mimic lab checks passed."
}

case "${1:-}" in
  up) up ;;
  demo) demo ;;
  smoke) smoke ;;
  status) ctl status ;;
  profiles) ctl profiles ;;
  logs) "${compose[@]}" logs --follow mimic ;;
  down) "${compose[@]}" down --remove-orphans ;;
  *)
    echo "usage: $0 up|demo|smoke|status|profiles|logs|down" >&2
    exit 2
    ;;
esac
