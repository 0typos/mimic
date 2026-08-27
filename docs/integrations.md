# Integrations

## Burp Suite

To let Mimic originate upstream TLS, use an HTTP listener in `intercept` mode:

1. Generate the Mimic CA with `mimic init-ca`.
2. Enable `[mitm]` and an intercept listener.
3. Import only the public Mimic CA certificate into Burp's server-certificate
   trust configuration.
4. Configure a Burp upstream proxy rule pointing to the intercept listener.
5. Start with a narrow destination scope and confirm Mimic's debug log shows the
   expected profile and negotiated TLS values.

Using a tunnel-mode listener as Burp's upstream proxy will not change the TLS
ClientHello because Burp's TLS bytes remain opaque inside CONNECT.

The interception listener currently handles HTTP/1.1 requests and translates
negotiated HTTP/2 upstream. Intercepted WebSocket upgrades are not supported.

## Caido

The plugin source and installation instructions are in
[`integrations/caido`](../integrations/caido/README.md).

The integration uses Caido's `onUpstream` hook. Enable **Mimic Upstream** for
each intended domain in Caido's Upstream Plugins settings. The first plugin
release is backend-only, connects to `127.0.0.1:7777`, and uses daemon-wide or
host-routed profile selection.

No Mimic CA is required for this path: Caido supplies plaintext HTTP over a
custom connection and Mimic creates TLS only toward the target.

## Direct clients

- Set `HTTP_PROXY`/`HTTPS_PROXY` or application proxy settings to an HTTP
  listener. HTTPS fingerprint changes require intercept mode and CA trust.
- Point SOCKS-aware applications to a SOCKS5 listener for transparent TCP or
  UDP relay. SOCKS traffic retains the application's own TLS fingerprint.
- Unix HTTP sockets are useful for same-host applications that support Unix
  proxy endpoints or a local adapter such as `socat`.
