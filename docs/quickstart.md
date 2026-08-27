# Five-minute quickstart

This path proves Mimic can emit a selected browser ClientHello, apply its HTTP
identity, and originate an intercepted upstream TLS connection. It uses only
local containers and normally takes under five minutes, including a first
build. The lab itself has a three-minute startup timeout.

## Before you start

Install Docker with Docker Compose v2.20 or newer and `curl`. Allocate at least
1 GB of free memory. From either a source checkout or an extracted Mimic release
archive, confirm the Compose plugin is available:

```sh
docker compose version
curl --version
```

The first run downloads a Go builder and Alpine base image. A slow or filtered
network can make that one-time download exceed the target time.

## Minute 0–3: start the lab

From the repository or release directory:

```sh
./lab/run.sh up
```

This builds two local images, starts three deterministic origin endpoints,
generates a lab-only Mimic CA under `lab/.state/`, and waits for both containers
to report healthy. It does not contact a test target or trust a CA globally.

## Minute 3–5: run the guided demo

```sh
./lab/run.sh demo
```

The three checks show:

1. `mimic probe` reports `PASS` because the emitted Chrome 133 ClientHello
   matches the profile's expected JA4.
2. A plaintext request through the forward proxy reaches the origin with the
   profile's Chrome `User-Agent`.
3. An HTTPS request trusts only the lab CA for that command; Mimic intercepts
   it and creates a new profiled TLS connection to the modern origin.

You are now using the parts of Mimic that actually change an upstream
fingerprint. A tunnel-only HTTP proxy or SOCKS connection does not do that.

## Useful next commands

```sh
./lab/run.sh status
./lab/run.sh profiles
./lab/run.sh smoke
./lab/run.sh logs
./lab/run.sh down
```

`smoke` walks all automated paths: a live profile change, host routing, TLS 1.0
fallback, SOCKS, and the Caido bridge. For a hands-on explanation and Burp/Caido
setup, continue with the [complete tutorial](tutorial.md).

The CA and key remain in the ignored `lab/.state/` directory after `down` for
fast restarts. To remove them, delete that directory only after the lab is down.
