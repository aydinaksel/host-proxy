# Host proxy

A [Pingora](https://github.com/cloudflare/pingora) reverse proxy that owns
ports 80 and 443 on a host and routes requests to upstream services by
hostname. One instance runs per public-facing server; the route table is
configuration, so the same binary serves every host.

-   Port 443 terminates TLS with a single certificate, so the certificate
    must cover every routed hostname (a SAN certificate).
-   Port 80 only redirects to HTTPS.
-   Hostname matching is exact. Requests for unrouted hosts receive a 404
    and never reach an upstream.

## Configuration

The `host-proxy` binary reads three environment variables:

-   `HOST_PROXY_ROUTES`: comma-separated `hostname=address` entries, for
    example `example.org=127.0.0.1:3000,www.example.org=127.0.0.1:3000`.
-   `HOST_PROXY_CERTIFICATE_FILE`: PEM certificate served on port 443.
-   `HOST_PROXY_PRIVATE_KEY_FILE`: PEM private key for the certificate.

## Library

The crate also exposes the proxy as a library, so a host that ever needs
custom proxy logic can ship its own thin binary:

```rust
use host_proxy::HostProxy;

fn main() {
    HostProxy::new()
        .route("example.org", "127.0.0.1:3000")
        .certificate(
            "/var/lib/acme/example.org/fullchain.pem",
            "/var/lib/acme/example.org/key.pem",
        )
        .run();
}
```

## NixOS

The flake exposes `nixosModules.default`:

```nix
services.hostProxy = {
  enable = true;
  routes = {
    "example.org" = "127.0.0.1:3000";
    "www.example.org" = "127.0.0.1:3000";
  };
  certificateFile = "/var/lib/acme/example.org/fullchain.pem";
  privateKeyFile = "/var/lib/acme/example.org/key.pem";
};
```
