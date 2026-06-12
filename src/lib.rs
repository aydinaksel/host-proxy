use std::collections::HashMap;

use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::{Error, ErrorType};
use tracing::{Level, event};

/// A reverse proxy that owns ports 80 and 443 on a host and routes
/// requests to upstream addresses by exact hostname match.
///
/// Port 443 terminates TLS with a single certificate, which must cover
/// every routed hostname. Port 80 only redirects to HTTPS. Requests for
/// hostnames without a route receive a 404 and never reach an upstream.
///
/// ```no_run
/// use host_proxy::HostProxy;
///
/// HostProxy::new()
///     .route("example.org", "127.0.0.1:3000")
///     .route("www.example.org", "127.0.0.1:3000")
///     .certificate(
///         "/var/lib/acme/example.org/fullchain.pem",
///         "/var/lib/acme/example.org/key.pem",
///     )
///     .run();
/// ```
pub struct HostProxy {
    upstream_addresses_by_hostname: HashMap<String, String>,
    certificate_file: Option<String>,
    private_key_file: Option<String>,
}

impl HostProxy {
    pub fn new() -> Self {
        HostProxy {
            upstream_addresses_by_hostname: HashMap::new(),
            certificate_file: None,
            private_key_file: None,
        }
    }

    /// Routes requests for `hostname` to `upstream_address`, an address
    /// such as `127.0.0.1:3000`. Matching is exact and case-insensitive,
    /// so subdomains need their own routes.
    pub fn route(
        mut self,
        hostname: impl Into<String>,
        upstream_address: impl Into<String>,
    ) -> Self {
        self.upstream_addresses_by_hostname
            .insert(hostname.into().to_ascii_lowercase(), upstream_address.into());
        self
    }

    /// Sets the PEM certificate and private key presented on port 443.
    pub fn certificate(
        mut self,
        certificate_file: impl Into<String>,
        private_key_file: impl Into<String>,
    ) -> Self {
        self.certificate_file = Some(certificate_file.into());
        self.private_key_file = Some(private_key_file.into());
        self
    }

    /// Starts the proxy and never returns.
    ///
    /// Panics if no routes are configured or the certificate is missing,
    /// since a host proxy that cannot serve anything should fail loudly
    /// at startup.
    pub fn run(self) -> ! {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        if self.upstream_addresses_by_hostname.is_empty() {
            panic!("no routes configured, call route() before run()");
        }
        let certificate_file = self
            .certificate_file
            .expect("no certificate configured, call certificate() before run()");
        let private_key_file = self
            .private_key_file
            .expect("no private key configured, call certificate() before run()");

        for (hostname, upstream_address) in &self.upstream_addresses_by_hostname {
            event!(
                name: "proxy.route.configured",
                Level::INFO,
                server.address = hostname,
                upstream.address = upstream_address,
                "routing {{server.address}} to {{upstream.address}}",
            );
        }

        let mut server = Server::new(None).expect("failed to create pingora server");
        server.bootstrap();

        let mut router_service = http_proxy_service(
            &server.configuration,
            HostRouter {
                upstream_addresses_by_hostname: self.upstream_addresses_by_hostname,
            },
        );
        let mut tls_settings = pingora::listeners::tls::TlsSettings::intermediate(
            &certificate_file,
            &private_key_file,
        )
        .expect("failed to configure TLS");
        tls_settings.enable_h2();
        router_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings);

        let mut redirect_service = http_proxy_service(&server.configuration, RedirectToHttps);
        redirect_service.add_tcp("0.0.0.0:80");

        server.add_service(router_service);
        server.add_service(redirect_service);
        server.run_forever();
    }
}

impl Default for HostProxy {
    fn default() -> Self {
        HostProxy::new()
    }
}

struct HostRouter {
    upstream_addresses_by_hostname: HashMap<String, String>,
}

struct RedirectToHttps;

fn requested_hostname(session: &Session) -> Option<String> {
    if let Some(authority) = session.req_header().uri.authority() {
        return Some(authority.host().to_ascii_lowercase());
    }

    session
        .req_header()
        .headers
        .get("host")
        .and_then(|header_value| header_value.to_str().ok())
        .map(|header_value| {
            header_value
                .split(':')
                .next()
                .unwrap_or(header_value)
                .to_ascii_lowercase()
        })
}

#[async_trait]
impl ProxyHttp for HostRouter {
    type CTX = Option<String>;

    fn new_ctx(&self) -> Self::CTX {
        None
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        routed_upstream_address: &mut Self::CTX,
    ) -> Result<bool> {
        let Some(hostname) = requested_hostname(session) else {
            session.respond_error(400).await?;
            return Ok(true);
        };

        let Some(upstream_address) = self.upstream_addresses_by_hostname.get(&hostname) else {
            event!(
                name: "proxy.route.unmatched",
                Level::WARN,
                server.address = hostname,
                url.path = session.req_header().uri.path(),
                "no route for {{server.address}}{{url.path}}, responding 404",
            );
            session.respond_error(404).await?;
            return Ok(true);
        };

        *routed_upstream_address = Some(upstream_address.clone());
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        routed_upstream_address: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let upstream_address = routed_upstream_address.clone().ok_or_else(|| {
            Error::explain(
                ErrorType::InternalError,
                "upstream requested for a session that request_filter did not route",
            )
        })?;

        Ok(Box::new(HttpPeer::new(upstream_address, false, String::new())))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _routed_upstream_address: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(client_socket_address) = session.client_addr() {
            let client_socket_address = client_socket_address.to_string();
            let client_ip_address = client_socket_address
                .split(':')
                .next()
                .unwrap_or(&client_socket_address);
            upstream_request.insert_header("X-Forwarded-For", client_ip_address)?;
        }
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        Ok(())
    }
}

#[async_trait]
impl ProxyHttp for RedirectToHttps {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _context: &mut Self::CTX,
    ) -> Result<bool> {
        let Some(hostname) = requested_hostname(session) else {
            session.respond_error(400).await?;
            return Ok(true);
        };

        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|path_and_query| path_and_query.as_str())
            .unwrap_or("/");

        let redirect_location = format!("https://{hostname}{path_and_query}");
        let mut response_header = ResponseHeader::build(301, None)?;
        response_header.insert_header("Location", redirect_location)?;
        response_header.insert_header("Content-Length", "0")?;
        session
            .write_response_header(Box::new(response_header), true)
            .await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _context: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Error::e_explain(
            ErrorType::InternalError,
            "the redirect service never proxies upstream",
        )
    }
}
