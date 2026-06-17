# Host proxy

A [Pingora](https://github.com/cloudflare/pingora) reverse proxy that owns
ports 80 and 443 on a host and routes requests to upstream services by
hostname. One instance runs per public-facing server; the route table is
configuration, so the same binary serves every host.

-   Port 443 terminates TLS and selects a certificate per connection by SNI, so
    you can load several certificates and each must merely cover the hostnames
    it serves.
-   Port 80 only redirects to HTTPS.
-   Hostname matching is exact. Requests for unrouted hosts receive a 404 and
    never reach an upstream.

## Route kinds

A route is one of:

-   **Proxy** the request to an upstream `host:port`.
-   **Private proxy**, which additionally rejects clients that are not on
    loopback, an RFC 1918 network, or the Tailscale CGNAT range (`100.64.0.0/10`)
    with a 403.
-   **Redirect**, which answers `301` with `Location: https://<target><path>`.
    TLS still terminates here, so a certificate covering the redirected
    hostname is required. The target is fixed configuration and is never taken
    from the request, so it cannot become an open redirect.

## Configuration

The `host-proxy` binary reads two environment variables:

-   `HOST_PROXY_ROUTES`: comma-separated entries, each one of:
    -   `hostname=host:port` — public proxy.
    -   `hostname=host:port!private` — private proxy.
    -   `hostname=>targethost` — permanent redirect to `https://targethost`.

    For example:
    `example.org=127.0.0.1:3000,admin.example.org=127.0.0.1:4000!private,www.example.org=>example.org`
-   `HOST_PROXY_CERTIFICATES`: comma-separated `certificate_path:private_key_path`
    pairs, one per certificate to load.

## Library

The crate also exposes the proxy as a library, so a host that ever needs custom
proxy logic can ship its own thin binary:

```rust
use host_proxy::{Access, Certificate, HostProxy};

fn main() {
    HostProxy::new()
        .route("example.org", "127.0.0.1:3000", Access::Public)
        .route("admin.example.org", "127.0.0.1:4000", Access::Private)
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
