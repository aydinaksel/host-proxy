# Host proxy

A [Pingora](https://github.com/cloudflare/pingora) reverse proxy that owns
ports 80 and 443 on a host and routes requests to upstream services by
hostname. One instance runs per public-facing server; the route table is
configuration, so the same binary serves every host.

-   Port 443 terminates TLS and selects a certificate per connection by SNI, so
    you can load several certificates and each must merely cover the hostnames
    it serves.
-   Port 80 only redirects to HTTPS.
-   Both ports listen on IPv4 and IPv6. IPv6 clients only arrive once the
    routed hostnames publish AAAA records; without them nothing changes.
    Private routes accept IPv6 loopback and unique local addresses
    (`fc00::/7`, which covers Tailscale's IPv6 range).
-   Hostname matching is exact. Requests for unrouted hosts receive a 404 and
    never reach an upstream.

## Route kinds

A route is one of:

-   **Proxy** the request to an upstream `host:port`.
-   **Private proxy**, which additionally rejects clients that are not on
    loopback, an RFC 1918 network, or the Tailscale CGNAT range (`100.64.0.0/10`)
    with a 403.
-   **Authenticated proxy**, which additionally requires an
    `Authorization: Bearer <token>` header matching one of the tokens in a file,
    and answers 401 otherwise. Tokens are compared in constant time and the file
    may list several, so a token can be rotated by adding the replacement,
    moving every client over, and only then removing the old one. The file is
    re-read on reload (see below) and on `SIGHUP`, so token changes take
    effect without dropping connections. Suits
    machine-to-machine endpoints that must be publicly reachable; access and
    authentication compose, so a route can require both.
-   **Redirect**, which answers `301` with `Location: https://<target><path>`.
    TLS still terminates here, so a certificate covering the redirected
    hostname is required. The target is fixed configuration and is never taken
    from the request, so it cannot become an open redirect.

## Configuration

The `host-proxy` binary reads two environment variables:

-   `HOST_PROXY_ROUTES`: comma-separated entries, each one of:
    -   `hostname=host:port` — public proxy.
    -   `hostname=host:port!private` — private proxy.
    -   `hostname=host:port!bearer=/path/to/tokens` — authenticated proxy.
    -   `hostname=>targethost` — permanent redirect to `https://targethost`.

    Tags combine, so `hostname=host:port!private!bearer=/path/to/tokens`
    requires both a private client address and a valid token.

    For example:
    `example.org=127.0.0.1:3000,admin.example.org=127.0.0.1:4000!private,www.example.org=>example.org`
-   `HOST_PROXY_CERTIFICATES`: comma-separated `certificate_path:private_key_path`
    pairs, one per certificate to load.
-   `HOST_PROXY_RATE_LIMIT_PER_SECOND` (optional): maximum requests per second
    accepted from a single client IP address. Clients over the limit receive a
    429 with `Retry-After: 1` before any routing or authentication work
    happens. Unset means no rate limiting; the NixOS module defaults to 100.
-   `HOST_PROXY_METRICS_ADDRESS` (optional): `host:port` to serve Prometheus
    metrics on, e.g. `127.0.0.1:9184`. The endpoint carries no authentication
    of its own, so bind it to loopback or a private interface. Alongside the
    process metrics, `host_proxy_http_requests_total` counts requests by
    routed hostname and response status, and
    `host_proxy_rate_limited_requests_total` counts 429s from the rate limit.
    Every request is also logged as a structured `proxy.request.completed`
    event with method, hostname, path, status, and client address.

## Library

The crate also exposes the proxy as a library, so a host that ever needs custom
proxy logic can ship its own thin binary:

```rust
use host_proxy::{Access, Certificate, HostProxy};

fn main() {
    HostProxy::new()
        .route("example.org", "127.0.0.1:3000", Access::Public)
        .route("admin.example.org", "127.0.0.1:4000", Access::Private)
        .authenticated_route(
            "ingest.example.org",
            "127.0.0.1:5000",
            Access::Public,
            "/run/secrets/ingest-tokens",
        )
        .redirect("www.example.org", "example.org")
        .certificate(Certificate::new(
            "/var/lib/acme/example.org/fullchain.pem".to_string(),
            "/var/lib/acme/example.org/key.pem".to_string(),
        ))
        .run();
}
```

## NixOS

The flake exposes `nixosModules.default`:

```nix
services.hostProxy = {
  enable = true;
  routes = {
    "example.org" = { upstreamAddress = "127.0.0.1:3000"; };
    "admin.example.org" = { upstreamAddress = "127.0.0.1:4000"; access = "private"; };
    "ingest.example.org" = {
      upstreamAddress = "127.0.0.1:5000";
      bearerTokenFile = "/run/secrets/ingest-tokens";
    };
    "www.example.org" = { redirectTo = "example.org"; };
  };
  certificates = [
    {
      certificateFile = "/var/lib/acme/example.org/fullchain.pem";
      privateKeyFile = "/var/lib/acme/example.org/key.pem";
    }
  ];
};
```

Each route sets exactly one of `upstreamAddress` or `redirectTo`.

## Reloads and zero-downtime upgrades

`systemctl reload host-proxy` performs a full zero-downtime replacement using
Pingora's graceful upgrade: a new process starts, takes over the listening
sockets from the old one, and the old process finishes its in-flight requests
before exiting. No connection is dropped, and the new process picks up
everything: a new binary, changed routes, renewed certificates, and rotated
bearer tokens. The NixOS module marks the unit `reloadIfChanged`, so
`nixos-rebuild switch` upgrades the running proxy the same way, and ACME's
`reloadServices` picks up renewed certificates through it.

Sending `SIGHUP` directly to the process re-reads only the bearer token files
in place, without replacing the process.
