# Mimic Upstream for Caido

Mimic Upstream lets Caido keep its Proxy, Intercept, Replay, Automate, and
history workflow while Mimic creates the final upstream TLS connection with a
selected transport profile.

The installable package contains:

- a backend plugin that handles Caido's `onUpstream` connection hook;
- a Mimic sidebar page for bridge settings, daemon health, metrics, and profile
  control;
- a shared typed contract between the two components.

## What the integration changes

```text
browser or Replay -> Caido plaintext request -> Mimic bridge -> destination
                                               selected TLS
```

Caido sends the edited plaintext HTTP request to the local bridge. Mimic opens
the destination connection and applies the selected TLS profile. When upstream
negotiates HTTP/1.1, the bridge preserves Caido's raw request bytes. When it
negotiates HTTP/2, Mimic parses and translates one request and applies the
profile's configured HTTP identity during that translation.

This path does not need Mimic's interception CA. A browser proxied through
Caido still trusts Caido's CA as usual.

## Mimic configuration

Run Mimic on the same machine as the Caido backend. The plugin defaults expect:

```toml
[control]
listen = "tcp://127.0.0.1:9090"

[[listeners]]
name = "caido"
protocol = "caido"
listen = "tcp://127.0.0.1:7777"
allow_cidrs = ["127.0.0.0/8", "::1/128"]
```

The control protocol has no application-level authentication, so the plugin
accepts only `localhost`, `127.0.0.1`, or `::1` for both endpoints. Do not
publish either port to another host. If Caido runs on a remote server, Mimic
must run on that server too; these addresses are relative to the Caido backend,
not the desktop browser displaying its UI.

## Install

Use the Caido ZIP from a Mimic release, or build one from source:

```sh
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm build
```

Install `dist/plugin_package.zip` from Caido's plugin installation page. Enable
both the backend and frontend components.

Caido invokes upstream plugins only for opted-in domains. In Caido's
**Upstream Plugins** settings, enable **Mimic Upstream** for the intended test
domains. Start with one exact domain before widening scope.

## Use the Mimic page

Open **Mimic** from Caido's sidebar.

The status area shows:

- whether the control endpoint is reachable;
- the active daemon profile and loaded profile count;
- connections, handled requests, legacy fallbacks, and uptime;
- the daemon configuration path.

**Daemon profile** changes Mimic's live default for new connections. Host routes
still take precedence. The change is intentionally not written to Mimic's TOML
and is reset by a daemon restart.

**Bridge profile override** is carried in each bridge preface. The saved setting
applies to every domain currently handled by the plugin. It wins over Mimic host
routes, so leave it empty for normal routing and clear it after a temporary A/B
comparison.

**Enabled** is a plugin-side bypass. When disabled, the upstream hook returns
control to Caido's ordinary connection handling even for domains that remain
opted in.

Bridge settings are validated and stored in Caido's backend database. They are
available to the connection hook before the page is opened.

## Development

Requirements are Node.js 22.13 or newer, Corepack, and the pnpm version pinned
by `packageManager`.

```sh
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
```

The build produces `dist/plugin_package.zip`. The backend tests cover settings
validation/storage, control framing/status parsing, profile selection, and the
bridge preface. Frontend tests cover the view model; `vue-tsc` and the production
Vite build verify the page and typed backend calls.

For iterative UI work, run `corepack pnpm watch` and connect Caido's Devtools
plugin to the reported development URL.

## Why TLS remains in the daemon

Caido backend plugins expose request APIs and TCP connection hooks but do not
provide low-level ClientHello cipher and extension ordering. Keeping uTLS in
the standalone Mimic daemon also avoids shipping a native plugin build for each
Caido platform.

`onInterceptRequest` and `onInterceptResponse` are observation events and do
not replace the destination connection. `onUpstream` is the appropriate hook:
it can return the local Mimic connection that Caido uses for the request.

When the destination selects HTTP/2, Mimic translates Caido's HTTP/1 request to
HTTP/2 upstream and translates the response back. This does not claim a
browser-identical HTTP/2 SETTINGS, HPACK, or frame fingerprint.

## Current boundaries

- endpoints are loopback TCP only;
- one profile override applies to all plugin-selected domains;
- the plugin cannot edit Mimic listeners, routes, CA configuration, or legacy
  allowlists; those remain deliberate TOML policy;
- disabling or uninstalling the frontend does not remove backend settings;
- a reachable status endpoint does not prove a particular destination will
  accept its selected TLS profile.

The complete [operator tutorial](../../docs/tutorial.md) walks through a Caido
session using the deterministic local lab.
