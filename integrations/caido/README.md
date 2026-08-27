# Mimic Upstream for Caido

This backend plugin uses Caido's `onUpstream` hook to hand the final connection
to Mimic. Caido keeps its Proxy, Intercept, Replay, Automate, and history UX;
Mimic creates the destination TLS connection with the selected profile.

## Development install

1. Start Mimic with the `caido` listener from `../../config.example.toml`.
2. Install pnpm, then run `pnpm install && pnpm build` in this directory.
3. Install `dist/plugin_package.zip` in Caido.
4. Enable **Mimic Upstream** for the intended domains in Caido's Upstream
   Plugins settings. Caido intentionally requires this per-domain opt-in.

The first bridge version targets `127.0.0.1:7777` and uses Mimic's daemon-wide
or per-host routed profile. `PROFILE` in `packages/backend/src/index.ts` can pin
a profile for development.

## Why this is a bridge, not the TLS implementation

Caido backend plugins run JavaScript and expose request APIs plus TCP connection
hooks, but do not expose control over ClientHello cipher/extension ordering.
Keeping uTLS in the standalone daemon also avoids shipping a separate native
plugin build for every Caido platform.

`onInterceptRequest` and `onInterceptResponse` are asynchronous observation
events and cannot modify messages. `onUpstream` is the correct hook: it runs
before target connection use and can return a custom `Connection`. It is on the
request path, so the plugin does only a loopback connect and a small preface;
the daemon performs DNS, TLS, and fallback work.

When the server selects HTTP/2, Mimic translates Caido's raw HTTP/1 request to
HTTP/2 upstream and translates the response back. For HTTP/1.1 it relays the raw
bytes, retaining Caido's header order. This does not claim a browser-identical
HTTP/2 SETTINGS/frame fingerprint.
