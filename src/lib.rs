use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::thread;

use async_trait::async_trait;
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use pingora::http::ResponseHeader;
use pingora::listeners::TcpSocketOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::tls::nid::Nid;
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::{
    AlpnError, NameType, SslContext, SslMethod, SslRef, SslVersion, select_next_proto,
};
use pingora::tls::x509::X509;
use pingora::{Error, ErrorType};
use tracing::{Level, event};

const NEGOTIATED_ALPN_PROTOCOLS: &[u8] = b"\x02h2\x08http/1.1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Public,
    Private,
}

fn is_private_client(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ipv4) => {
            // Tailscale CGNAT: 100.64.0.0/10
            let octets = ipv4.octets();
            let is_tailscale = octets[0] == 100 && (octets[1] & 0xC0) == 64;

            ipv4.is_loopback()
                || ipv4.is_private()
                || is_tailscale
        }
        IpAddr::V6(ipv6) => {
            if let Some(mapped_ipv4) = ipv6.to_ipv4_mapped() {
                return is_private_client(IpAddr::V4(mapped_ipv4));
            }
            // Unique local addresses: fc00::/7, which includes Tailscale's
            // fd7a:115c:a1e0::/48
            let is_unique_local = (ipv6.segments()[0] & 0xfe00) == 0xfc00;

            ipv6.is_loopback() || is_unique_local
        }
    }
}

/// Bearer tokens accepted on a route. Holding several lets a token be rotated
/// by adding the new one, redeploying every client, and only then removing the
/// old one. The set is reloaded from its file on SIGHUP, so rotation needs no
/// restart and no dropped connections.
#[derive(Clone)]
pub struct BearerTokens {
    token_file_path: Arc<str>,
    tokens: Arc<RwLock<Vec<String>>>,
}

fn read_tokens(token_file_path: &str) -> Result<Vec<String>, String> {
    let contents = fs::read_to_string(token_file_path)
        .map_err(|error| format!("failed to read {token_file_path}: {error}"))?;

    let tokens: Vec<String> = contents
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    if tokens.is_empty() {
        return Err(format!("bearer token file {token_file_path} contains no tokens"));
    }

    Ok(tokens)
}

impl BearerTokens {
    fn load(token_file_path: &str) -> Self {
        let tokens = read_tokens(token_file_path)
            .unwrap_or_else(|error| panic!("failed to load bearer tokens: {error}"));

        BearerTokens {
            token_file_path: Arc::from(token_file_path),
            tokens: Arc::new(RwLock::new(tokens)),
        }
    }

    fn reload(&self) {
        match read_tokens(&self.token_file_path) {
            Ok(reloaded_tokens) => {
                let token_count = reloaded_tokens.len();
                *self.tokens.write().expect("bearer token lock poisoned") = reloaded_tokens;
                event!(
                    name: "proxy.tokens.reloaded",
                    Level::INFO,
                    file.path = &*self.token_file_path,
                    token.count = token_count,
                    "reloaded {{token.count}} bearer tokens from {{file.path}}",
                );
            }
            Err(error) => {
                event!(
                    name: "proxy.tokens.reload_failed",
                    Level::ERROR,
                    file.path = &*self.token_file_path,
                    error.message = error,
                    "keeping existing bearer tokens, failed to reload {{file.path}}: {{error.message}}",
                );
            }
        }
    }

    fn accepts(&self, presented_token: &str) -> bool {
        let tokens = self.tokens.read().expect("bearer token lock poisoned");
        // fold rather than any: any short-circuits on the first match, which
        // would leak through timing which of the accepted tokens was presented.
        tokens.iter().fold(false, |accepted, token| {
            constant_time_equals(token.as_bytes(), presented_token.as_bytes()) || accepted
        })
    }
}

fn spawn_token_reload_signal_handler(reloadable_tokens: Vec<BearerTokens>) {
    let mut signals = Signals::new([SIGHUP]).expect("failed to register SIGHUP handler");
    thread::spawn(move || {
        for _signal in signals.forever() {
            event!(
                name: "proxy.tokens.reload_requested",
                Level::INFO,
                "received SIGHUP, reloading bearer tokens",
            );
            for tokens in &reloadable_tokens {
                tokens.reload();
            }
        }
    });
}

fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

pub struct Certificate {
    certificate_path: String,
    private_key_path: String,
}

impl Certificate {
    pub fn new(certificate_path: String, private_key_path: String) -> Self {
        Certificate {
            certificate_path,
            private_key_path,
        }
    }

    fn load(&self) -> LoadedCertificate {
        let certificate_pem = fs::read(&self.certificate_path).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", self.certificate_path)
        });
        let private_key_pem = fs::read(&self.private_key_path).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", self.private_key_path)
        });

        let chain = X509::stack_from_pem(&certificate_pem).unwrap_or_else(|error| {
            panic!("invalid certificate {}: {error}", self.certificate_path)
        });
        let x509 = chain
            .first()
            .expect("certificate file is empty")
            .clone();
        let private_key = PKey::private_key_from_pem(&private_key_pem).unwrap_or_else(|error| {
            panic!("invalid private key {}: {error}", self.private_key_path)
        });

        let mut context_builder = SslContext::builder(SslMethod::tls())
            .expect("failed to create SSL context builder");
        // Pin the same TLS 1.2+ floor the port-443 base listener gets from
        // TlsSettings::intermediate, so SNI-matched connections are not weaker
        // than the no-SNI fallback.
        context_builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .expect("failed to set minimum TLS version on SSL context");
        context_builder
            .set_certificate(&x509)
            .expect("failed to set certificate on SSL context");
        for intermediate in chain.iter().skip(1) {
            context_builder
                .add_extra_chain_cert(intermediate.clone())
                .expect("failed to add intermediate certificate");
        }
        context_builder
            .set_private_key(&private_key)
            .expect("failed to set private key on SSL context");
        context_builder.set_alpn_select_callback(|_ssl, client_protocols| {
            select_next_proto(NEGOTIATED_ALPN_PROTOCOLS, client_protocols)
                .ok_or(AlpnError::NOACK)
        });
        let ssl_context = context_builder.build();

        let mut hostnames = Vec::new();
        if let Some(common_name) = x509
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
        {
            if let Ok(name) = common_name.data().as_utf8() {
                hostnames.push(name.to_string().to_ascii_lowercase());
            }
        }
        if let Some(san) = x509.subject_alt_names() {
            for name in san {
                if let Some(dns_name) = name.dnsname() {
                    hostnames.push(dns_name.to_ascii_lowercase());
                }
            }
        }

        LoadedCertificate {
            hostnames,
            ssl_context,
        }
    }
}

struct LoadedCertificate {
    hostnames: Vec<String>,
    ssl_context: SslContext,
}

struct CertificateResolver {
    contexts_by_hostname: HashMap<String, Arc<SslContext>>,
}

impl CertificateResolver {
    fn resolve(&self, server_name: &str) -> Option<&Arc<SslContext>> {
        self.contexts_by_hostname
            .get(&server_name.to_ascii_lowercase())
    }
}

enum Route {
    Proxy {
        upstream_address: String,
        access: Access,
        bearer_tokens: Option<BearerTokens>,
    },
    Redirect {
        target_host: String,
    },
}

pub struct HostProxy {
    routes_by_hostname: HashMap<String, Route>,
    certificates: Vec<Certificate>,
}

impl HostProxy {
    pub fn new() -> Self {
        HostProxy {
            routes_by_hostname: HashMap::new(),
            certificates: Vec::new(),
        }
    }

    pub fn route(
        mut self,
        hostname: impl Into<String>,
        upstream_address: impl Into<String>,
        access: Access,
    ) -> Self {
        self.routes_by_hostname.insert(
            hostname.into().to_ascii_lowercase(),
            Route::Proxy {
                upstream_address: upstream_address.into(),
                access,
                bearer_tokens: None,
            },
        );
        self
    }

    /// Route requests only when they carry `Authorization: Bearer <token>` with
    /// a token listed in `token_file_path`, one per line. Unauthenticated
    /// requests receive a 401 and never reach the upstream, so this suits
    /// machine-to-machine endpoints that must be publicly reachable. The file is
    /// reloaded on SIGHUP, so tokens rotate without restarting the proxy.
    pub fn authenticated_route(
        mut self,
        hostname: impl Into<String>,
        upstream_address: impl Into<String>,
        access: Access,
        token_file_path: &str,
    ) -> Self {
        self.routes_by_hostname.insert(
            hostname.into().to_ascii_lowercase(),
            Route::Proxy {
                upstream_address: upstream_address.into(),
                access,
                bearer_tokens: Some(BearerTokens::load(token_file_path)),
            },
        );
        self
    }

    /// Permanently redirect (301) requests for `hostname` to
    /// `https://{target_host}{path_and_query}`. The target is fixed
    /// configuration and is never taken from the request, so this cannot
    /// become an open redirect.
    pub fn redirect(
        mut self,
        hostname: impl Into<String>,
        target_host: impl Into<String>,
    ) -> Self {
        self.routes_by_hostname.insert(
            hostname.into().to_ascii_lowercase(),
            Route::Redirect {
                target_host: target_host.into(),
            },
        );
        self
    }

    pub fn certificate(mut self, certificate: Certificate) -> Self {
        self.certificates.push(certificate);
        self
    }

    pub fn run(self) -> ! {
        if self.routes_by_hostname.is_empty() {
            panic!("no routes configured");
        }
        if self.certificates.is_empty() {
            panic!("no certificates configured");
        }

        for (hostname, route) in &self.routes_by_hostname {
            match route {
                Route::Proxy { upstream_address, access, bearer_tokens } => {
                    let access_label = match access {
                        Access::Public => "public",
                        Access::Private => "private",
                    };
                    event!(
                        name: "proxy.route.configured",
                        Level::INFO,
                        server.address = hostname,
                        upstream.address = upstream_address,
                        route.access = access_label,
                        route.authenticated = bearer_tokens.is_some(),
                        "routing {{server.address}} to {{upstream.address}} ({{route.access}}, authenticated={{route.authenticated}})",
                    );
                }
                Route::Redirect { target_host } => {
                    event!(
                        name: "proxy.redirect.configured",
                        Level::INFO,
                        server.address = hostname,
                        redirect.target = target_host,
                        "redirecting {{server.address}} to https://{{redirect.target}}",
                    );
                }
            }
        }

        let reloadable_tokens: Vec<BearerTokens> = self
            .routes_by_hostname
            .values()
            .filter_map(|route| match route {
                Route::Proxy {
                    bearer_tokens: Some(bearer_tokens),
                    ..
                } => Some(bearer_tokens.clone()),
                _ => None,
            })
            .collect();

        let mut contexts_by_hostname = HashMap::new();
        let first_certificate = &self.certificates[0];

        for certificate in &self.certificates {
            let loaded = certificate.load();
            let shared_context = Arc::new(loaded.ssl_context);
            for hostname in &loaded.hostnames {
                event!(
                    name: "proxy.certificate.loaded",
                    Level::INFO,
                    certificate.hostname = hostname,
                    "loaded certificate for {{certificate.hostname}}",
                );
                contexts_by_hostname.insert(hostname.clone(), Arc::clone(&shared_context));
            }
        }

        let resolver = Arc::new(CertificateResolver {
            contexts_by_hostname,
        });

        let mut server = Server::new(None).expect("failed to create pingora server");
        server.bootstrap();

        let mut router_service = http_proxy_service(
            &server.configuration,
            HostRouter {
                routes_by_hostname: self.routes_by_hostname,
            },
        );
        router_service.threads = Some(available_worker_thread_count());

        let mut ipv6_only_options = TcpSocketOptions::default();
        ipv6_only_options.ipv6_only = Some(true);

        router_service.add_tls_with_settings(
            "0.0.0.0:443",
            None,
            build_tls_settings(first_certificate, &resolver),
        );
        router_service.add_tls_with_settings(
            "[::]:443",
            Some(ipv6_only_options.clone()),
            build_tls_settings(first_certificate, &resolver),
        );

        let mut redirect_service = http_proxy_service(&server.configuration, RedirectToHttps);
        redirect_service.add_tcp("0.0.0.0:80");
        redirect_service.add_tcp_with_settings("[::]:80", ipv6_only_options);

        server.add_service(router_service);
        server.add_service(redirect_service);

        spawn_token_reload_signal_handler(reloadable_tokens);

        server.run_forever();
    }
}

impl Default for HostProxy {
    fn default() -> Self {
        HostProxy::new()
    }
}

fn build_tls_settings(
    first_certificate: &Certificate,
    resolver: &Arc<CertificateResolver>,
) -> TlsSettings {
    let mut tls_settings = TlsSettings::intermediate(
        &first_certificate.certificate_path,
        &first_certificate.private_key_path,
    )
    .expect("failed to create TLS settings");

    let sni_resolver = Arc::clone(resolver);
    tls_settings.set_servername_callback(move |ssl: &mut SslRef, _| {
        if let Some(server_name) = ssl.servername(NameType::HOST_NAME) {
            if let Some(context) = sni_resolver.resolve(server_name) {
                ssl.set_ssl_context(context).ok();
            }
        }
        Ok(())
    });

    tls_settings.enable_h2();
    tls_settings
}

struct HostRouter {
    routes_by_hostname: HashMap<String, Route>,
}

struct RedirectToHttps;

fn available_worker_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

async fn write_permanent_redirect(session: &mut Session, location: String) -> Result<()> {
    let mut response_header = ResponseHeader::build(301, None)?;
    response_header.insert_header("Location", location)?;
    response_header.insert_header("Content-Length", "0")?;
    session
        .write_response_header(Box::new(response_header), true)
        .await?;
    Ok(())
}

async fn write_unauthorized(session: &mut Session) -> Result<()> {
    let mut response_header = ResponseHeader::build(401, None)?;
    response_header.insert_header("WWW-Authenticate", "Bearer")?;
    response_header.insert_header("Content-Length", "0")?;
    session
        .write_response_header(Box::new(response_header), true)
        .await?;
    Ok(())
}

fn requested_path_and_query(session: &Session) -> &str {
    session
        .req_header()
        .uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str())
        .unwrap_or("/")
}

fn client_ip_address(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|socket_address| socket_address.as_inet())
        .map(|inet_socket_address| inet_socket_address.ip())
}

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

        let Some(route) = self.routes_by_hostname.get(&hostname) else {
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

        let (upstream_address, access, bearer_tokens) = match route {
            Route::Redirect { target_host } => {
                let redirect_location =
                    format!("https://{target_host}{}", requested_path_and_query(session));
                write_permanent_redirect(session, redirect_location).await?;
                return Ok(true);
            }
            Route::Proxy { upstream_address, access, bearer_tokens } => {
                (upstream_address, *access, bearer_tokens.as_ref())
            }
        };

        if access == Access::Private {
            let client_address = client_ip_address(session);
            let is_allowed = client_address.map(is_private_client).unwrap_or(false);

            if !is_allowed {
                event!(
                    name: "proxy.route.forbidden",
                    Level::WARN,
                    server.address = hostname,
                    client.address = client_address
                        .map(|address| address.to_string())
                        .unwrap_or_default(),
                    "denied public access to private route {{server.address}} from {{client.address}}",
                );
                session.respond_error(403).await?;
                return Ok(true);
            }
        }

        if let Some(accepted_tokens) = bearer_tokens {
            let presented_token = session
                .req_header()
                .headers
                .get("authorization")
                .and_then(|header_value| header_value.to_str().ok())
                .and_then(|header_value| header_value.strip_prefix("Bearer "));

            let is_authenticated = presented_token
                .map(|token| accepted_tokens.accepts(token.trim()))
                .unwrap_or(false);

            if !is_authenticated {
                event!(
                    name: "proxy.route.unauthenticated",
                    Level::WARN,
                    server.address = hostname,
                    url.path = session.req_header().uri.path(),
                    "rejected unauthenticated request for {{server.address}}{{url.path}}",
                );
                write_unauthorized(session).await?;
                return Ok(true);
            }
        }

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
        if let Some(client_address) = client_ip_address(session) {
            upstream_request.insert_header("X-Forwarded-For", client_address.to_string())?;
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

        let redirect_location =
            format!("https://{hostname}{}", requested_path_and_query(session));
        write_permanent_redirect(session, redirect_location).await?;
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::{Arc, RwLock};

    use super::{BearerTokens, constant_time_equals, is_private_client};

    fn parsed(address: &str) -> IpAddr {
        address.parse().expect("invalid test address")
    }

    #[test]
    fn private_clients_include_loopback_rfc1918_and_tailscale() {
        assert!(is_private_client(parsed("127.0.0.1")));
        assert!(is_private_client(parsed("10.0.0.2")));
        assert!(is_private_client(parsed("192.168.1.10")));
        assert!(is_private_client(parsed("100.64.0.1")));
        assert!(is_private_client(parsed("100.127.255.254")));
        assert!(!is_private_client(parsed("100.63.255.255")));
        assert!(!is_private_client(parsed("8.8.8.8")));
    }

    #[test]
    fn private_clients_include_ipv6_loopback_and_unique_local() {
        assert!(is_private_client(parsed("::1")));
        assert!(is_private_client(parsed("fc00::1")));
        assert!(is_private_client(parsed("fd7a:115c:a1e0::1")));
        assert!(!is_private_client(parsed("2001:db8::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_clients_follow_the_ipv4_rules() {
        assert!(is_private_client(parsed("::ffff:192.168.1.10")));
        assert!(!is_private_client(parsed("::ffff:8.8.8.8")));
    }

    fn tokens(values: &[&str]) -> BearerTokens {
        BearerTokens {
            token_file_path: Arc::from("test-tokens"),
            tokens: Arc::new(RwLock::new(
                values.iter().map(|value| value.to_string()).collect(),
            )),
        }
    }

    #[test]
    fn constant_time_equals_matches_only_identical_slices() {
        assert!(constant_time_equals(b"secret", b"secret"));
        assert!(!constant_time_equals(b"secret", b"secrey"));
        assert!(!constant_time_equals(b"secret", b"secre"));
        assert!(!constant_time_equals(b"", b"a"));
        assert!(constant_time_equals(b"", b""));
    }

    #[test]
    fn accepts_any_configured_token() {
        let accepted = tokens(&["first-token", "second-token"]);
        assert!(accepted.accepts("first-token"));
        assert!(accepted.accepts("second-token"));
    }

    #[test]
    fn rejects_unknown_and_partial_tokens() {
        let accepted = tokens(&["first-token"]);
        assert!(!accepted.accepts("wrong-token"));
        assert!(!accepted.accepts("first"));
        assert!(!accepted.accepts("first-token-extra"));
        assert!(!accepted.accepts(""));
    }

    fn temporary_token_file(contents: &str, label: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("host-proxy-{}-{label}", std::process::id()));
        std::fs::write(&path, contents).expect("failed to write temporary token file");
        path
    }

    #[test]
    fn reload_swaps_the_accepted_token_set() {
        let path = temporary_token_file("first-token\n", "reload-swap");
        let accepted = BearerTokens::load(path.to_str().unwrap());
        assert!(accepted.accepts("first-token"));

        std::fs::write(&path, "second-token\n").unwrap();
        accepted.reload();

        assert!(accepted.accepts("second-token"));
        assert!(!accepted.accepts("first-token"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn reload_keeps_existing_tokens_when_the_new_file_is_empty() {
        let path = temporary_token_file("only-token\n", "reload-empty");
        let accepted = BearerTokens::load(path.to_str().unwrap());

        std::fs::write(&path, "\n   \n").unwrap();
        accepted.reload();

        assert!(accepted.accepts("only-token"));

        std::fs::remove_file(&path).ok();
    }
}
