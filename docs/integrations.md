# Integrations

The [complete hands-on tutorial](tutorial.md) includes a deterministic local
origin and end-to-end setup for both tools. Use this page as the shorter
reference after completing that workflow.

## Burp Suite

To let Mimic originate upstream TLS, use an HTTP listener in `intercept` mode:

1. Generate the Mimic CA with `mimic init-ca`.
2. Enable `[mitm]` and an intercept listener.
3. Import only the public Mimic CA certificate into Burp's server-certificate
   trust configuration.
4. Configure a Burp upstream proxy rule pointing to the intercept listener.
5. Start with a narrow destination scope and confirm Mimic's debug log shows the
   expected profile and negotiated TLS values.

Current Burp UI paths and the lab values are documented in the
[Burp tutorial section](tutorial.md#7-workflow-c-put-mimic-behind-burp-suite).

Using a tunnel-mode listener as Burp's upstream proxy will not change the TLS
ClientHello because Burp's TLS bytes remain opaque inside CONNECT.

The interception listener currently handles HTTP/1.1 requests and translates
negotiated HTTP/2 upstream. Intercepted WebSocket upgrades are not supported.

## Caido

The plugin source and installation instructions are in
[`integrations/caido`](../integrations/caido/README.md).

The integration uses Caido's `onUpstream` hook. Enable **Mimic Upstream** for
each intended domain in Caido's Upstream Plugins settings. Its **Mimic** sidebar
page configures the loopback bridge and control ports, reports daemon health and
counters, changes the live daemon default, and can attach a persistent bridge
profile override. Settings are stored in Caido's backend database.

The defaults are bridge `127.0.0.1:7777` and control
`127.0.0.1:9090`. Mimic and the Caido backend must run on the same host. Both
addresses are intentionally restricted to loopback; the unauthenticated control
protocol must not be forwarded to another machine.

No Mimic CA is required for this path: Caido supplies plaintext HTTP over a
custom connection and Mimic creates TLS only toward the target.

Leave the plugin profile override empty for normal Mimic host routing. Setting
it affects every domain currently opted into the plugin and takes precedence
over daemon routes until cleared.

See the [Caido tutorial section](tutorial.md#6-workflow-b-use-the-caido-plugin)
for plugin installation, domain opt-in, and everyday profile control.

## Direct clients

- Set `HTTP_PROXY`/`HTTPS_PROXY` or application proxy settings to an HTTP
  listener. HTTPS fingerprint changes require intercept mode and CA trust.
- Point SOCKS-aware applications to a SOCKS5 listener for transparent TCP or
  UDP relay. SOCKS traffic retains the application's own TLS fingerprint.
- Unix HTTP sockets are useful for same-host applications that support Unix
  proxy endpoints or a local adapter such as `socat`.
