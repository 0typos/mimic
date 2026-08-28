# Five-minute quickstart

This path proves Mimic can emit a selected browser ClientHello, apply its HTTP
identity, and originate an intercepted upstream TLS connection. It uses only
local containers and normally takes under five minutes, including a first
build. The lab itself has a three-minute startup timeout.

## Before you start

Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/), Docker
with Docker Compose v2.20 or newer, and `curl`. Allocate at least 1 GB of free
memory. From either a source checkout or an extracted Mimic release archive,
confirm the prerequisites are available:

```sh
uv --version
docker compose version
curl --version
```

The launcher is an executable PEP 723 Python script. `uv` creates its locked
environment automatically; no virtual environment or manual `pip` install is
needed. The first run also downloads a Go builder and Alpine base image. A slow
or filtered network can make those one-time downloads exceed the target time.

## Minute 0–3: start the lab

From the repository or release directory:

```sh
./lab/mimic-lab up
```

This builds two local images, starts three deterministic origin endpoints,
generates a lab-only Mimic CA under `lab/.state/`, and waits for both containers
to report healthy. It does not contact a test target or trust a CA globally.

## Minute 3–5: run the guided demo

```sh
./lab/mimic-lab demo
```

The three checks show:

1. `mimic probe` reports `PASS` because the emitted Chrome 152 ClientHello
   matches the profile's expected JA4.
2. A plaintext request through the forward proxy reaches the origin with the
   profile's Chrome `User-Agent`.
3. An HTTPS request trusts only the lab CA for that command; Mimic intercepts
   it and creates a new profiled TLS connection to the modern origin.

![The three-step Mimic lab quickstart](tutorial/demos/01-quickstart.gif)

<sub>▶ [`01-quickstart.cast`](tutorial/demos/01-quickstart.cast) — play it with `asciinema play` for a real terminal session.</sub>

You are now using the parts of Mimic that actually change an upstream
fingerprint. A tunnel-only HTTP proxy or SOCKS connection does not do that.

## Useful next commands

```sh
./lab/mimic-lab status
./lab/mimic-lab profiles
./lab/mimic-lab check
./lab/mimic-lab logs
./lab/mimic-lab down
```

`check` walks all automated paths: a live profile change, host routing, TLS 1.0
fallback, SOCKS, and the Caido bridge. For a hands-on explanation and Burp/Caido
setup, continue with the [complete tutorial](tutorial.md).

If you use the lab frequently, install its command into `uv`'s executable
directory. The symlink still uses this checkout's Compose files, so it works
from any directory:

```sh
./lab/mimic-lab install
mimic-lab status
mimic-lab uninstall
```

The CA and key remain in the ignored `lab/.state/` directory after `down` for
fast restarts. To remove them, delete that directory only after the lab is down.
