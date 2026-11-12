use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fs;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use http::uri::PathAndQuery;
pub use http::HeaderName;
use openssl::sha::sha256;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::TcpSocketOptions;
use pingora::prelude::*;
use pingora::protocols::l4::socket::SocketAddr;
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::configuration::Opt;
use pingora::server::ShutdownWatch;
use pingora::services::background::{background_service, BackgroundService};
use pingora::tls::nid::Nid;
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::{
    select_next_proto, AlpnError, NameType, SslContext, SslMethod, SslRef, SslVersion,
};
use pingora::tls::x509::X509;
use pingora::Error;
use pingora_limits::rate::Rate;
use pingora_prometheus::prometheus::{self, IntCounter, IntCounterVec};
use tracing::{event, Level};

pub use crate::client_networks::{ClientNetwork, InvalidClientNetwork};
pub use crate::tailnet::DEFAULT_TAILSCALED_SOCKET_PATH;
use crate::tailnet::{TailnetIdentity, TailnetWhois};

mod client_networks;
mod tailnet;

const NEGOTIATED_ALPN_PROTOCOLS: &[u8] = b"\x02h2\x08http/1.1";

#[derive(Debug)]
pub struct HostProxyError {
    message: String,
}

impl HostProxyError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        HostProxyError {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for HostProxyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for HostProxyError {}

const DEFAULT_HTTPS_ADDRESSES: [&str; 2] = ["0.0.0.0:443", "[::]:443"];
const DEFAULT_HTTP_ADDRESSES: [&str; 2] = ["0.0.0.0:80", "[::]:80"];

fn socket_options_for(address: &str) -> Option<TcpSocketOptions> {
    let is_ipv6 = address.starts_with('[');
    is_ipv6.then(|| {
        let mut ipv6_only_options = TcpSocketOptions::default();
        ipv6_only_options.ipv6_only = Some(true);
        ipv6_only_options
    })
}

const UPSTREAM_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_READ_TIMEOUT: Duration = Duration::from_mins(5);
const UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_mins(5);
const UPSTREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Public,
    Private,
}

fn is_private_client(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ipv4) => {
            // Tailscale CGNAT: 100.64.0.0/10
            let [first_octet, second_octet, _, _] = ipv4.octets();
            let is_tailscale = first_octet == 100 && (second_octet & 0xC0) == 64;

            ipv4.is_loopback() || ipv4.is_private() || is_tailscale
        }
        IpAddr::V6(ipv6) => {
            if let Some(mapped_ipv4) = ipv6.to_ipv4_mapped() {
                return is_private_client(IpAddr::V4(mapped_ipv4));
            }
            // Unique local addresses: fc00::/7, which includes Tailscale's
            // fd7a:115c:a1e0::/48
            let [first_segment, ..] = ipv6.segments();
            let is_unique_local = (first_segment & 0xfe00) == 0xfc00;

            ipv6.is_loopback() || is_unique_local
        }
    }
}

const SHA256_DIGEST_LENGTH_BYTES: usize = 32;
const SHA256_HEXADECIMAL_LENGTH: usize = 64;

type TokenDigest = [u8; SHA256_DIGEST_LENGTH_BYTES];

const MAXIMUM_TOKEN_IDENTITY_LENGTH: usize = 150;

/// Name a bearer token stands for, such as `fbrmarble.pan`.
///
/// It is made of ASCII letters, digits, `.`, `_` and `-`, at most 150
/// characters, so it is safe to pass upstream in a header and fits the tenant
/// identifiers Loki and Mimir accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenIdentity(Arc<str>);

impl TokenIdentity {
    fn parse(text: &str) -> Option<Self> {
        let is_identity_character =
            |character: char| character.is_ascii_alphanumeric() || "._-".contains(character);
        let is_valid = !text.is_empty()
            && text.len() <= MAXIMUM_TOKEN_IDENTITY_LENGTH
            && text.chars().all(is_identity_character);
        is_valid.then(|| TokenIdentity(Arc::from(text)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AcceptedToken {
    digest: TokenDigest,
    identity: Option<TokenIdentity>,
}

/// SHA-256 digests of the bearer tokens accepted on a route. Only digests are
/// configured, so the accepted set reveals no token and can live in public
/// configuration. Holding several lets a token be rotated by adding the new
/// digest, redeploying every client, and only then removing the old one. The
/// set is reloaded from its file on SIGHUP, so rotation needs no restart and no
/// dropped connections.
///
/// Each line of the file holds one digest, optionally followed by whitespace
/// and the [`TokenIdentity`] that token stands for. A route that passes the
/// identity upstream requires one on every line.
#[derive(Clone)]
pub struct BearerTokenDigests {
    digest_file_path: Arc<str>,
    requires_identities: bool,
    accepted_tokens: Arc<RwLock<Vec<AcceptedToken>>>,
}

fn parse_hexadecimal_digest(line: &str) -> Option<TokenDigest> {
    let is_hexadecimal_digest = line.len() == SHA256_HEXADECIMAL_LENGTH
        && line.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !is_hexadecimal_digest {
        return None;
    }

    let bytes: Option<Vec<u8>> = line
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect();
    bytes.and_then(|bytes| TokenDigest::try_from(bytes.as_slice()).ok())
}

fn parse_accepted_token(line: &str) -> Option<AcceptedToken> {
    let mut fields = line.split_whitespace();
    let digest = parse_hexadecimal_digest(fields.next()?)?;
    let identity = match fields.next() {
        Some(identity) => Some(TokenIdentity::parse(identity)?),
        None => None,
    };
    if fields.next().is_some() {
        return None;
    }
    Some(AcceptedToken { digest, identity })
}

fn read_accepted_tokens(
    digest_file_path: &str,
    requires_identities: bool,
) -> Result<Vec<AcceptedToken>, String> {
    let contents = fs::read_to_string(digest_file_path)
        .map_err(|error| format!("failed to read {digest_file_path}: {error}"))?;

    let accepted_tokens: Option<Vec<AcceptedToken>> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(parse_accepted_token)
        .collect();

    let Some(accepted_tokens) = accepted_tokens else {
        return Err(format!(
            "bearer token digest file {digest_file_path} has a line that is not a \
             {SHA256_HEXADECIMAL_LENGTH}-character hexadecimal SHA-256 digest, optionally \
             followed by an identity of letters, digits, '.', '_' and '-'"
        ));
    };

    if accepted_tokens.is_empty() {
        return Err(format!(
            "bearer token digest file {digest_file_path} contains no digests"
        ));
    }

    let lacks_an_identity = accepted_tokens
        .iter()
        .any(|accepted_token| accepted_token.identity.is_none());
    if requires_identities && lacks_an_identity {
        return Err(format!(
            "bearer token digest file {digest_file_path} has a digest without an identity, \
             which a route passing identities upstream cannot accept"
        ));
    }

    Ok(accepted_tokens)
}

/// A presented bearer token that matched one of the accepted digests.
pub struct AuthenticatedToken {
    pub identity: Option<TokenIdentity>,
}

impl BearerTokenDigests {
    fn load(digest_file_path: &str, requires_identities: bool) -> Result<Self, HostProxyError> {
        let accepted_tokens =
            read_accepted_tokens(digest_file_path, requires_identities).map_err(|error| {
                HostProxyError::new(format!("failed to load bearer token digests: {error}"))
            })?;

        Ok(BearerTokenDigests {
            digest_file_path: Arc::from(digest_file_path),
            requires_identities,
            accepted_tokens: Arc::new(RwLock::new(accepted_tokens)),
        })
    }

    fn reload(&self) {
        match read_accepted_tokens(&self.digest_file_path, self.requires_identities) {
            Ok(reloaded_tokens) => {
                let digest_count = reloaded_tokens.len();
                *self
                    .accepted_tokens
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = reloaded_tokens;
                event!(
                    name: "proxy.tokens.reloaded",
                    Level::INFO,
                    file.path = &*self.digest_file_path,
                    token.count = digest_count,
                    "reloaded {{token.count}} bearer token digests from {{file.path}}",
                );
            }
            Err(error) => {
                event!(
                    name: "proxy.tokens.reload_failed",
                    Level::ERROR,
                    file.path = &*self.digest_file_path,
                    error.message = error,
                    "keeping existing bearer token digests, failed to reload {{file.path}}: {{error.message}}",
                );
            }
        }
    }

    fn authenticate(&self, presented_token: &str) -> Option<AuthenticatedToken> {
        let presented_digest = sha256(presented_token.as_bytes());
        let accepted_tokens = self
            .accepted_tokens
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        // Every digest is compared even after a match, so the response time
        // does not reveal which of the accepted tokens was presented.
        let matched_token = accepted_tokens
            .iter()
            .fold(None, |matched, accepted_token| {
                let is_match = constant_time_equals(&accepted_token.digest, &presented_digest);
                matched.or(is_match.then_some(accepted_token))
            });
        matched_token.map(|accepted_token| AuthenticatedToken {
            identity: accepted_token.identity.clone(),
        })
    }
}

struct TokenReloadService {
    reloadable_digests: Vec<BearerTokenDigests>,
}

#[async_trait]
impl BackgroundService for TokenReloadService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let registration = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup());
        let Ok(mut hangup_signals) = registration else {
            event!(
                name: "proxy.tokens.reload_unavailable",
                Level::ERROR,
                "failed to register the SIGHUP handler, bearer tokens will not reload in place",
            );
            return;
        };
        loop {
            tokio::select! {
                _ = hangup_signals.recv() => {
                    event!(
                        name: "proxy.tokens.reload_requested",
                        Level::INFO,
                        "received SIGHUP, reloading bearer tokens",
                    );
                    for digests in &self.reloadable_digests {
                        digests.reload();
                    }
                }
                _ = shutdown.changed() => return,
            }
        }
    }
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

const UNROUTED_HOSTNAME_LABEL: &str = "unrouted";

struct RequestMetrics {
    requests_total: IntCounterVec,
    rate_limited_total: IntCounter,
}

impl RequestMetrics {
    fn register() -> Result<Self, HostProxyError> {
        Ok(RequestMetrics {
            requests_total: prometheus::register_int_counter_vec!(
                "host_proxy_http_requests_total",
                "Requests handled by the router, by routed hostname and response status",
                &["hostname", "status"]
            )
            .map_err(|error| {
                HostProxyError::new(format!("failed to register the request counter: {error}"))
            })?,
            rate_limited_total: prometheus::register_int_counter!(
                "host_proxy_rate_limited_requests_total",
                "Requests rejected with 429 by the per-client rate limit"
            )
            .map_err(|error| {
                HostProxyError::new(format!(
                    "failed to register the rate limit counter: {error}"
                ))
            })?,
        })
    }
}

struct RateLimit {
    requests_per_second_by_client: Rate,
    max_requests_per_second: isize,
}

impl RateLimit {
    fn new(max_requests_per_second: u32) -> Self {
        RateLimit {
            requests_per_second_by_client: Rate::new(Duration::from_secs(1)),
            max_requests_per_second: isize::try_from(max_requests_per_second).unwrap_or(isize::MAX),
        }
    }

    fn exceeded_by(&self, client_address: IpAddr) -> bool {
        let observed_requests = self
            .requests_per_second_by_client
            .observe(&client_address, 1);
        observed_requests > self.max_requests_per_second
    }
}

pub struct Certificate {
    certificate_path: String,
    private_key_path: String,
}

impl Certificate {
    #[must_use]
    pub fn new(certificate_path: String, private_key_path: String) -> Self {
        Certificate {
            certificate_path,
            private_key_path,
        }
    }

    fn load(&self) -> Result<LoadedCertificate, HostProxyError> {
        let certificate_pem = fs::read(&self.certificate_path).map_err(|error| {
            HostProxyError::new(format!("failed to read {}: {error}", self.certificate_path))
        })?;
        let private_key_pem = fs::read(&self.private_key_path).map_err(|error| {
            HostProxyError::new(format!("failed to read {}: {error}", self.private_key_path))
        })?;

        let chain = X509::stack_from_pem(&certificate_pem).map_err(|error| {
            HostProxyError::new(format!(
                "invalid certificate {}: {error}",
                self.certificate_path
            ))
        })?;
        let mut chain_certificates = chain.into_iter();
        let x509 = chain_certificates.next().ok_or_else(|| {
            HostProxyError::new(format!(
                "certificate file {} is empty",
                self.certificate_path
            ))
        })?;
        let private_key = PKey::private_key_from_pem(&private_key_pem).map_err(|error| {
            HostProxyError::new(format!(
                "invalid private key {}: {error}",
                self.private_key_path
            ))
        })?;

        let mut context_builder = SslContext::builder(SslMethod::tls()).map_err(|error| {
            HostProxyError::new(format!("failed to create an SSL context builder: {error}"))
        })?;
        // Pin the same TLS 1.2+ floor the port-443 base listener gets from
        // TlsSettings::intermediate, so SNI-matched connections are not weaker
        // than the no-SNI fallback.
        context_builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|error| {
                HostProxyError::new(format!(
                    "failed to set the minimum TLS version on the SSL context: {error}"
                ))
            })?;
        context_builder.set_certificate(&x509).map_err(|error| {
            HostProxyError::new(format!(
                "failed to set certificate {} on the SSL context: {error}",
                self.certificate_path
            ))
        })?;
        for intermediate in chain_certificates {
            context_builder
                .add_extra_chain_cert(intermediate)
                .map_err(|error| {
                    HostProxyError::new(format!(
                        "failed to add an intermediate certificate from {}: {error}",
                        self.certificate_path
                    ))
                })?;
        }
        context_builder
            .set_private_key(&private_key)
            .map_err(|error| {
                HostProxyError::new(format!(
                    "failed to set private key {} on the SSL context: {error}",
                    self.private_key_path
                ))
            })?;
        context_builder.set_alpn_select_callback(|_ssl, client_protocols| {
            select_next_proto(NEGOTIATED_ALPN_PROTOCOLS, client_protocols).ok_or(AlpnError::NOACK)
        });
        let ssl_context = context_builder.build();

        let mut hostnames = Vec::new();
        if let Some(common_name) = x509.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
            if let Ok(name) = common_name.data().to_string() {
                hostnames.push(name.to_ascii_lowercase());
            }
        }
        if let Some(san) = x509.subject_alt_names() {
            for name in san {
                if let Some(dns_name) = name.dnsname() {
                    hostnames.push(dns_name.to_ascii_lowercase());
                }
            }
        }

        Ok(LoadedCertificate {
            hostnames,
            ssl_context,
        })
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
        bearer_token_digest_file_path: Option<String>,
        identifies_tailnet_users: bool,
        allowed_client_networks: Option<Vec<ClientNetwork>>,
        allowed_paths: Option<Vec<String>>,
        identity_header: Option<HeaderName>,
    },
    Redirect {
        target_host: String,
    },
}

enum LoadedRoute {
    Proxy {
        upstream_address: String,
        access: Access,
        bearer_token_digests: Option<BearerTokenDigests>,
        identifies_tailnet_users: bool,
        allowed_client_networks: Option<Vec<ClientNetwork>>,
        allowed_paths: Option<Vec<String>>,
        identity_header: Option<HeaderName>,
    },
    Redirect {
        target_host: String,
    },
}

impl Route {
    fn log_configured(&self, hostname: &str) {
        match self {
            Route::Proxy {
                upstream_address,
                access,
                bearer_token_digest_file_path,
                identifies_tailnet_users,
                allowed_client_networks,
                allowed_paths,
                identity_header,
            } => {
                let client_networks_label = allowed_client_networks.as_ref().map_or_else(
                    || "any".to_string(),
                    |networks| {
                        networks
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" ")
                    },
                );
                let allowed_paths_label = allowed_paths
                    .as_ref()
                    .map_or_else(|| "any".to_string(), |paths| paths.join(" "));
                let identity_header_label =
                    identity_header.as_ref().map_or("none", HeaderName::as_str);
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
                    route.authenticated = bearer_token_digest_file_path.is_some(),
                    route.tailnet_identity = identifies_tailnet_users,
                    route.client_networks = client_networks_label,
                    route.allowed_paths = allowed_paths_label,
                    route.identity_header = identity_header_label,
                    "routing {{server.address}} to {{upstream.address}} ({{route.access}}, authenticated={{route.authenticated}}, tailnet_identity={{route.tailnet_identity}}, client_networks={{route.client_networks}}, allowed_paths={{route.allowed_paths}}, identity_header={{route.identity_header}})",
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

    fn load(self) -> Result<LoadedRoute, HostProxyError> {
        match self {
            Route::Proxy {
                upstream_address,
                access,
                bearer_token_digest_file_path,
                identifies_tailnet_users,
                allowed_client_networks,
                allowed_paths,
                identity_header,
            } => {
                let requires_identities = identity_header.is_some();
                let bearer_token_digests = bearer_token_digest_file_path
                    .map(|digest_file_path| {
                        BearerTokenDigests::load(&digest_file_path, requires_identities)
                    })
                    .transpose()?;
                Ok(LoadedRoute::Proxy {
                    upstream_address,
                    access,
                    bearer_token_digests,
                    identifies_tailnet_users,
                    allowed_client_networks,
                    allowed_paths,
                    identity_header,
                })
            }
            Route::Redirect { target_host } => Ok(LoadedRoute::Redirect { target_host }),
        }
    }
}

pub struct HostProxy {
    routes_by_hostname: HashMap<String, Route>,
    certificates: Vec<Certificate>,
    rate_limit_per_second: Option<u32>,
    metrics_address: Option<String>,
    tailnet_identity_hostnames: HashSet<String>,
    client_networks_by_hostname: HashMap<String, Vec<ClientNetwork>>,
    allowed_paths_by_hostname: HashMap<String, Vec<String>>,
    identity_headers_by_hostname: HashMap<String, HeaderName>,
    tailscaled_socket_path: String,
    https_addresses: Vec<String>,
    http_addresses: Vec<String>,
}

impl HostProxy {
    #[must_use]
    pub fn new() -> Self {
        HostProxy {
            routes_by_hostname: HashMap::new(),
            certificates: Vec::new(),
            rate_limit_per_second: None,
            metrics_address: None,
            tailnet_identity_hostnames: HashSet::new(),
            client_networks_by_hostname: HashMap::new(),
            allowed_paths_by_hostname: HashMap::new(),
            identity_headers_by_hostname: HashMap::new(),
            tailscaled_socket_path: DEFAULT_TAILSCALED_SOCKET_PATH.to_string(),
            https_addresses: DEFAULT_HTTPS_ADDRESSES.map(str::to_string).to_vec(),
            http_addresses: DEFAULT_HTTP_ADDRESSES.map(str::to_string).to_vec(),
        }
    }

    /// Serve Prometheus metrics over HTTP on this address. Bind it to
    /// loopback or a private interface; the endpoint carries no
    /// authentication of its own.
    #[must_use]
    pub fn metrics_address(mut self, metrics_address: impl Into<String>) -> Self {
        self.metrics_address = Some(metrics_address.into());
        self
    }

    /// Reject clients exceeding this many requests per second, per client IP
    /// address, with a 429 before any routing or authentication work happens.
    #[must_use]
    pub fn rate_limit_per_second(mut self, max_requests_per_second: u32) -> Self {
        self.rate_limit_per_second = Some(max_requests_per_second);
        self
    }

    #[must_use]
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
                bearer_token_digest_file_path: None,
                identifies_tailnet_users: false,
                allowed_client_networks: None,
                allowed_paths: None,
                identity_header: None,
            },
        );
        self
    }

    /// Route requests only when they carry `Authorization: Bearer <token>` with
    /// a token whose SHA-256 digest is listed in `token_digest_file_path`, one
    /// 64-character hexadecimal digest per line. Unauthenticated
    /// requests receive a 401 and never reach the upstream, so this suits
    /// machine-to-machine endpoints that must be publicly reachable. The file is
    /// read when [`HostProxy::run`] starts and reloaded on SIGHUP, so tokens
    /// rotate without restarting the proxy.
    #[must_use]
    pub fn authenticated_route(
        mut self,
        hostname: impl Into<String>,
        upstream_address: impl Into<String>,
        access: Access,
        token_digest_file_path: impl Into<String>,
    ) -> Self {
        self.routes_by_hostname.insert(
            hostname.into().to_ascii_lowercase(),
            Route::Proxy {
                upstream_address: upstream_address.into(),
                access,
                bearer_token_digest_file_path: Some(token_digest_file_path.into()),
                identifies_tailnet_users: false,
                allowed_client_networks: None,
                allowed_paths: None,
                identity_header: None,
            },
        );
        self
    }

    /// Permanently redirect (301) requests for `hostname` to
    /// `https://{target_host}{path_and_query}`. The target is fixed
    /// configuration and is never taken from the request, so this cannot
    /// become an open redirect.
    #[must_use]
    pub fn redirect(mut self, hostname: impl Into<String>, target_host: impl Into<String>) -> Self {
        self.routes_by_hostname.insert(
            hostname.into().to_ascii_lowercase(),
            Route::Redirect {
                target_host: target_host.into(),
            },
        );
        self
    }

    #[must_use]
    pub fn identify_tailnet_users(mut self, hostname: impl Into<String>) -> Self {
        self.tailnet_identity_hostnames
            .insert(hostname.into().to_ascii_lowercase());
        self
    }

    /// Accept requests for `hostname` only from clients inside one of
    /// `networks`, answering 403 to everyone else before authentication or
    /// proxying. Suits a public route that only a known service, such as a
    /// provider's published outbound ranges, should ever call.
    #[must_use]
    pub fn allow_clients_from(
        mut self,
        hostname: impl Into<String>,
        networks: Vec<ClientNetwork>,
    ) -> Self {
        self.client_networks_by_hostname
            .insert(hostname.into().to_ascii_lowercase(), networks);
        self
    }

    /// Accept requests for `hostname` only when their path is exactly one of
    /// `paths`, answering 403 to every other path before authentication or
    /// proxying.
    ///
    /// The query string is not part of the comparison. Paths are compared as
    /// sent, so an encoded or dot-segment variant of an allowed path is
    /// refused rather than normalised. This suits an ingest route whose token
    /// should reach only the write endpoints of a store that also serves reads.
    #[must_use]
    pub fn allow_paths(mut self, hostname: impl Into<String>, paths: Vec<String>) -> Self {
        self.allowed_paths_by_hostname
            .insert(hostname.into().to_ascii_lowercase(), paths);
        self
    }

    /// Pass the identity of the presented bearer token upstream in `header`.
    ///
    /// The route must be an [`HostProxy::authenticated_route`], and every
    /// line of its digest file must name a [`TokenIdentity`]. Any value the
    /// client sent in `header` is removed, so the upstream can trust it, for
    /// example as the `X-Scope-OrgID` tenant of Loki or Mimir.
    #[must_use]
    pub fn pass_token_identity(mut self, hostname: impl Into<String>, header: HeaderName) -> Self {
        self.identity_headers_by_hostname
            .insert(hostname.into().to_ascii_lowercase(), header);
        self
    }

    #[must_use]
    pub fn https_addresses(mut self, addresses: Vec<String>) -> Self {
        self.https_addresses = addresses;
        self
    }

    #[must_use]
    pub fn http_addresses(mut self, addresses: Vec<String>) -> Self {
        self.http_addresses = addresses;
        self
    }

    #[must_use]
    pub fn tailscaled_socket_path(mut self, socket_path: impl Into<String>) -> Self {
        self.tailscaled_socket_path = socket_path.into();
        self
    }

    #[must_use]
    pub fn certificate(mut self, certificate: Certificate) -> Self {
        self.certificates.push(certificate);
        self
    }

    pub fn run(mut self) -> Result<Infallible, HostProxyError> {
        if self.routes_by_hostname.is_empty() {
            return Err(HostProxyError::new("no routes configured"));
        }
        self.apply_tailnet_identity();
        self.apply_client_networks()?;
        self.apply_allowed_paths()?;
        self.apply_identity_headers()?;

        let mut loaded_routes_by_hostname = HashMap::new();
        let mut reloadable_digests = Vec::new();
        for (hostname, route) in self.routes_by_hostname {
            route.log_configured(&hostname);
            let loaded_route = route.load()?;
            if let LoadedRoute::Proxy {
                bearer_token_digests: Some(bearer_token_digests),
                ..
            } = &loaded_route
            {
                reloadable_digests.push(bearer_token_digests.clone());
            }
            loaded_routes_by_hostname.insert(hostname, loaded_route);
        }

        let first_certificate = self
            .certificates
            .first()
            .ok_or_else(|| HostProxyError::new("no certificates configured"))?;

        let mut contexts_by_hostname = HashMap::new();
        for certificate in &self.certificates {
            let loaded = certificate.load()?;
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

        let mut server = Server::new(Some(Opt::parse_args())).map_err(|error| {
            HostProxyError::new(format!("failed to create the pingora server: {error}"))
        })?;
        server.bootstrap();

        let mut router_service = http_proxy_service(
            &server.configuration,
            HostRouter {
                routes_by_hostname: loaded_routes_by_hostname,
                rate_limit: self.rate_limit_per_second.map(RateLimit::new),
                request_metrics: RequestMetrics::register()?,
                tailnet_whois: TailnetWhois::new(self.tailscaled_socket_path),
            },
        );
        router_service.threads = Some(available_worker_thread_count());

        for address in &self.https_addresses {
            router_service.add_tls_with_settings(
                address,
                socket_options_for(address),
                build_tls_settings(first_certificate, &resolver)?,
            );
        }

        let mut redirect_service = http_proxy_service(&server.configuration, RedirectToHttps);
        for address in &self.http_addresses {
            match socket_options_for(address) {
                Some(options) => redirect_service.add_tcp_with_settings(address, options),
                None => redirect_service.add_tcp(address),
            }
        }

        server.add_service(router_service);
        server.add_service(redirect_service);

        if let Some(metrics_address) = &self.metrics_address {
            let mut metrics_service = pingora_prometheus::prometheus_http_service();
            metrics_service.add_tcp(metrics_address);
            server.add_service(metrics_service);
            event!(
                name: "proxy.metrics.configured",
                Level::INFO,
                server.address = metrics_address,
                "serving Prometheus metrics on {{server.address}}",
            );
        }

        server.add_service(background_service(
            "bearer token reload",
            TokenReloadService { reloadable_digests },
        ));

        server.run_forever()
    }
}

impl HostProxy {
    fn apply_tailnet_identity(&mut self) {
        for hostname in &self.tailnet_identity_hostnames {
            match self.routes_by_hostname.get_mut(hostname) {
                Some(Route::Proxy {
                    identifies_tailnet_users,
                    ..
                }) => *identifies_tailnet_users = true,
                Some(Route::Redirect { .. }) | None => event!(
                    name: "proxy.tailnet.identity_ignored",
                    Level::WARN,
                    server.address = hostname,
                    "ignoring tailnet identity for {{server.address}}, which is not a proxied route",
                ),
            }
        }
    }
}

impl HostProxy {
    fn apply_client_networks(&mut self) -> Result<(), HostProxyError> {
        for (hostname, networks) in self.client_networks_by_hostname.drain() {
            match self.routes_by_hostname.get_mut(&hostname) {
                Some(Route::Proxy {
                    allowed_client_networks,
                    ..
                }) => *allowed_client_networks = Some(networks),
                Some(Route::Redirect { .. }) | None => {
                    return Err(HostProxyError::new(format!(
                        "client networks are set for {hostname}, which is not a proxied route"
                    )));
                }
            }
        }
        Ok(())
    }

    fn apply_allowed_paths(&mut self) -> Result<(), HostProxyError> {
        for (hostname, paths) in self.allowed_paths_by_hostname.drain() {
            if paths.is_empty() {
                return Err(HostProxyError::new(format!(
                    "allowed paths for {hostname} list no paths"
                )));
            }
            if let Some(relative_path) = paths.iter().find(|path| !path.starts_with('/')) {
                return Err(HostProxyError::new(format!(
                    "allowed path {relative_path:?} for {hostname} does not start with '/'"
                )));
            }
            let Some(Route::Proxy { allowed_paths, .. }) =
                self.routes_by_hostname.get_mut(&hostname)
            else {
                return Err(HostProxyError::new(format!(
                    "allowed paths are set for {hostname}, which is not a proxied route"
                )));
            };
            *allowed_paths = Some(paths);
        }
        Ok(())
    }

    fn apply_identity_headers(&mut self) -> Result<(), HostProxyError> {
        for (hostname, header) in self.identity_headers_by_hostname.drain() {
            let Some(Route::Proxy {
                bearer_token_digest_file_path: Some(_),
                identity_header,
                ..
            }) = self.routes_by_hostname.get_mut(&hostname)
            else {
                return Err(HostProxyError::new(format!(
                    "an identity header is set for {hostname}, which is not an authenticated \
                     proxied route"
                )));
            };
            *identity_header = Some(header);
        }
        Ok(())
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
) -> Result<TlsSettings, HostProxyError> {
    let mut tls_settings = TlsSettings::intermediate(
        &first_certificate.certificate_path,
        &first_certificate.private_key_path,
    )
    .map_err(|error| HostProxyError::new(format!("failed to create TLS settings: {error}")))?;

    let sni_resolver = Arc::clone(resolver);
    tls_settings.set_servername_callback(move |ssl: &mut SslRef, _| {
        if let Some(server_name) = ssl.servername(NameType::HOST_NAME) {
            if let Some(context) = sni_resolver.resolve(server_name) {
                if let Err(error) = ssl.set_ssl_context(context) {
                    event!(
                        name: "proxy.tls.context_swap_failed",
                        Level::ERROR,
                        error.message = error.to_string(),
                        "failed to set the SNI-resolved SSL context: {{error.message}}",
                    );
                }
            }
        }
        Ok(())
    });

    tls_settings.enable_h2();
    Ok(tls_settings)
}

struct HostRouter {
    routes_by_hostname: HashMap<String, LoadedRoute>,
    rate_limit: Option<RateLimit>,
    request_metrics: RequestMetrics,
    tailnet_whois: TailnetWhois,
}

#[derive(Default)]
pub struct RequestContext {
    routed_hostname: Option<String>,
    upstream_address: Option<String>,
    tailnet_identity: Option<TailnetIdentity>,
    identity_header: Option<HeaderName>,
    token_identity: Option<TokenIdentity>,
}

struct RedirectToHttps;

fn available_worker_thread_count() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
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

async fn write_too_many_requests(session: &mut Session) -> Result<()> {
    let mut response_header = ResponseHeader::build(429, None)?;
    response_header.insert_header("Retry-After", "1")?;
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
        .map_or("/", PathAndQuery::as_str)
}

fn client_socket_address(session: &Session) -> Option<std::net::SocketAddr> {
    session.client_addr().and_then(SocketAddr::as_inet).copied()
}

fn admits_client(
    hostname: &str,
    access: Access,
    allowed_client_networks: Option<&[ClientNetwork]>,
    client_address: Option<IpAddr>,
) -> bool {
    let client_address_label = client_address
        .map(|address| address.to_string())
        .unwrap_or_default();
    if access == Access::Private && !client_address.is_some_and(is_private_client) {
        event!(
            name: "proxy.route.forbidden",
            Level::WARN,
            server.address = hostname,
            client.address = client_address_label,
            "denied public access to private route {{server.address}} from {{client.address}}",
        );
        return false;
    }
    let outside_allowed_networks = allowed_client_networks.is_some_and(|networks| {
        !client_address
            .is_some_and(|address| networks.iter().any(|network| network.contains(address)))
    });
    if outside_allowed_networks {
        event!(
            name: "proxy.route.client_network_forbidden",
            Level::WARN,
            server.address = hostname,
            client.address = client_address_label,
            "denied {{client.address}} outside the allowed networks of {{server.address}}",
        );
        return false;
    }
    true
}

fn admits_path(hostname: &str, allowed_paths: Option<&[String]>, requested_path: &str) -> bool {
    let is_allowed =
        allowed_paths.is_none_or(|paths| paths.iter().any(|path| path == requested_path));
    if !is_allowed {
        event!(
            name: "proxy.route.path_forbidden",
            Level::WARN,
            server.address = hostname,
            url.path = requested_path,
            "denied {{server.address}}{{url.path}}, which is not an allowed path",
        );
    }
    is_allowed
}

fn client_ip_address(session: &Session) -> Option<IpAddr> {
    client_socket_address(session).map(|socket_address| socket_address.ip())
}

fn insert_identity_header(upstream_request: &mut RequestHeader, name: &'static str, value: &str) {
    if value.is_empty() {
        return;
    }
    if let Err(error) = upstream_request.insert_header(name, value) {
        event!(
            name: "proxy.tailnet.header_rejected",
            Level::WARN,
            http.header.name = name,
            error.message = error.to_string(),
            "left out the {{http.header.name}} header: {{error.message}}",
        );
    }
}

fn presented_bearer_token(session: &Session) -> Option<&str> {
    session
        .req_header()
        .headers
        .get("authorization")
        .and_then(|header_value| header_value.to_str().ok())
        .and_then(|header_value| header_value.strip_prefix("Bearer "))
        .map(str::trim)
}

fn pass_token_identity(
    upstream_request: &mut RequestHeader,
    identity_header: &HeaderName,
    token_identity: Option<&TokenIdentity>,
) -> Result<()> {
    upstream_request.remove_header(identity_header);
    let Some(token_identity) = token_identity else {
        return Ok(());
    };
    upstream_request.insert_header(identity_header, token_identity.as_str())
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
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::default()
    }

    async fn request_filter(&self, session: &mut Session, context: &mut Self::CTX) -> Result<bool> {
        if let (Some(rate_limit), Some(client_address)) =
            (&self.rate_limit, client_ip_address(session))
        {
            if rate_limit.exceeded_by(client_address) {
                self.request_metrics.rate_limited_total.inc();
                event!(
                    name: "proxy.request.rate_limited",
                    Level::WARN,
                    client.address = client_address.to_string(),
                    "rate limited {{client.address}}, responding 429",
                );
                write_too_many_requests(session).await?;
                return Ok(true);
            }
        }

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

        context.routed_hostname = Some(hostname.clone());

        let (
            upstream_address,
            access,
            bearer_token_digests,
            identifies_tailnet_users,
            allowed_client_networks,
            allowed_paths,
            identity_header,
        ) = match route {
            LoadedRoute::Redirect { target_host } => {
                let redirect_location =
                    format!("https://{target_host}{}", requested_path_and_query(session));
                write_permanent_redirect(session, redirect_location).await?;
                return Ok(true);
            }
            LoadedRoute::Proxy {
                upstream_address,
                access,
                bearer_token_digests,
                identifies_tailnet_users,
                allowed_client_networks,
                allowed_paths,
                identity_header,
            } => (
                upstream_address,
                *access,
                bearer_token_digests.as_ref(),
                *identifies_tailnet_users,
                allowed_client_networks.as_deref(),
                allowed_paths.as_deref(),
                identity_header.as_ref(),
            ),
        };

        let is_admitted =
            admits_client(
                &hostname,
                access,
                allowed_client_networks,
                client_ip_address(session),
            ) && admits_path(&hostname, allowed_paths, session.req_header().uri.path());
        if !is_admitted {
            session.respond_error(403).await?;
            return Ok(true);
        }

        if let Some(accepted_digests) = bearer_token_digests {
            let authenticated_token = presented_bearer_token(session)
                .and_then(|token| accepted_digests.authenticate(token));

            let Some(authenticated_token) = authenticated_token else {
                event!(
                    name: "proxy.route.unauthenticated",
                    Level::WARN,
                    server.address = hostname,
                    url.path = session.req_header().uri.path(),
                    "rejected unauthenticated request for {{server.address}}{{url.path}}",
                );
                write_unauthorized(session).await?;
                return Ok(true);
            };
            context.token_identity = authenticated_token.identity;
        }
        context.identity_header = identity_header.cloned();

        if identifies_tailnet_users {
            if let Some(client) = client_socket_address(session) {
                context.tailnet_identity = self.tailnet_whois.identify(client).await;
            }
        }

        context.upstream_address = Some(upstream_address.clone());
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        context: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let upstream_address = context.upstream_address.clone().ok_or_else(|| {
            Error::explain(
                InternalError,
                "upstream requested for a session that request_filter did not route",
            )
        })?;

        let mut peer = HttpPeer::new(upstream_address, false, String::new());
        peer.options.connection_timeout = Some(UPSTREAM_CONNECTION_TIMEOUT);
        peer.options.read_timeout = Some(UPSTREAM_READ_TIMEOUT);
        peer.options.write_timeout = Some(UPSTREAM_WRITE_TIMEOUT);
        peer.options.idle_timeout = Some(UPSTREAM_IDLE_TIMEOUT);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        context: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(client_address) = client_ip_address(session) {
            upstream_request.insert_header("X-Forwarded-For", client_address.to_string())?;
        }
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        upstream_request.remove_header(tailnet::USER_LOGIN_HEADER);
        upstream_request.remove_header(tailnet::USER_NAME_HEADER);
        if let Some(identity) = &context.tailnet_identity {
            insert_identity_header(
                upstream_request,
                tailnet::USER_LOGIN_HEADER,
                &identity.login_name,
            );
            insert_identity_header(
                upstream_request,
                tailnet::USER_NAME_HEADER,
                &identity.display_name,
            );
        }
        if let Some(identity_header) = &context.identity_header {
            pass_token_identity(
                upstream_request,
                identity_header,
                context.token_identity.as_ref(),
            )?;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, context: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        let status_code = session
            .response_written()
            .map_or(0, |response_header| response_header.status.as_u16());
        let hostname = context
            .routed_hostname
            .as_deref()
            .unwrap_or(UNROUTED_HOSTNAME_LABEL);

        self.request_metrics
            .requests_total
            .with_label_values(&[hostname, &status_code.to_string()])
            .inc();

        event!(
            name: "proxy.request.completed",
            Level::INFO,
            http.request.method = session.req_header().method.as_str(),
            server.address = hostname,
            url.path = session.req_header().uri.path(),
            http.response.status_code = status_code,
            client.address = client_ip_address(session)
                .map(|address| address.to_string())
                .unwrap_or_default(),
            error.message = error.map(ToString::to_string).unwrap_or_default(),
            "{{http.request.method}} {{server.address}}{{url.path}} responded {{http.response.status_code}}",
        );
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

        let redirect_location = format!("https://{hostname}{}", requested_path_and_query(session));
        write_permanent_redirect(session, redirect_location).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _context: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Error::e_explain(InternalError, "the redirect service never proxies upstream")
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::{Arc, RwLock};

    use super::{
        admits_client, admits_path, constant_time_equals, is_private_client, parse_accepted_token,
        parse_hexadecimal_digest, sha256, AcceptedToken, Access, BearerTokenDigests, ClientNetwork,
        HeaderName, HostProxy, Route, TokenIdentity,
    };

    fn parsed(address: &str) -> IpAddr {
        address.parse().expect("invalid test address")
    }

    fn anthropic_networks() -> Vec<ClientNetwork> {
        ["160.79.104.0/21", "153.61.208.0/20"]
            .iter()
            .map(|network| network.parse().unwrap())
            .collect()
    }

    #[test]
    fn a_route_with_networks_admits_only_clients_inside_them() {
        let networks = anthropic_networks();

        assert!(admits_client(
            "mcp.example.org",
            Access::Public,
            Some(&networks),
            Some(parsed("160.79.105.20"))
        ));
        assert!(!admits_client(
            "mcp.example.org",
            Access::Public,
            Some(&networks),
            Some(parsed("203.0.113.7"))
        ));
        assert!(!admits_client(
            "mcp.example.org",
            Access::Public,
            Some(&networks),
            None
        ));
    }

    #[test]
    fn a_route_without_networks_keeps_its_access_rule() {
        assert!(admits_client(
            "app.example.org",
            Access::Public,
            None,
            Some(parsed("203.0.113.7"))
        ));
        assert!(!admits_client(
            "admin.example.org",
            Access::Private,
            None,
            Some(parsed("203.0.113.7"))
        ));
        assert!(admits_client(
            "admin.example.org",
            Access::Private,
            None,
            Some(parsed("100.64.0.17"))
        ));
    }

    #[test]
    fn private_access_and_networks_must_both_pass() {
        let tailnet_only: Vec<ClientNetwork> = vec!["100.64.0.17/32".parse().unwrap()];

        assert!(admits_client(
            "admin.example.org",
            Access::Private,
            Some(&tailnet_only),
            Some(parsed("100.64.0.17"))
        ));
        assert!(!admits_client(
            "admin.example.org",
            Access::Private,
            Some(&tailnet_only),
            Some(parsed("100.64.0.22"))
        ));
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

    fn hexadecimal_digest(token: &str) -> String {
        sha256(token.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<String>>()
            .concat()
    }

    fn digest_file_contents(tokens: &[&str]) -> String {
        tokens
            .iter()
            .map(|token| hexadecimal_digest(token) + "\n")
            .collect::<Vec<String>>()
            .concat()
    }

    fn accepts(accepted: &BearerTokenDigests, token: &str) -> bool {
        accepted.authenticate(token).is_some()
    }

    fn digests_of(tokens: &[&str]) -> BearerTokenDigests {
        BearerTokenDigests {
            digest_file_path: Arc::from("test-digests"),
            requires_identities: false,
            accepted_tokens: Arc::new(RwLock::new(
                tokens
                    .iter()
                    .map(|token| AcceptedToken {
                        digest: sha256(token.as_bytes()),
                        identity: None,
                    })
                    .collect(),
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
    fn accepts_any_token_whose_digest_is_configured() {
        let accepted = digests_of(&["first-token", "second-token"]);
        assert!(accepts(&accepted, "first-token"));
        assert!(accepts(&accepted, "second-token"));
    }

    #[test]
    fn rejects_unknown_and_partial_tokens() {
        let accepted = digests_of(&["first-token"]);
        assert!(!accepts(&accepted, "wrong-token"));
        assert!(!accepts(&accepted, "first"));
        assert!(!accepts(&accepted, "first-token-extra"));
        assert!(!accepts(&accepted, ""));
    }

    #[test]
    fn rejects_the_digest_presented_as_a_token() {
        let accepted = digests_of(&["first-token"]);
        assert!(!accepts(&accepted, &hexadecimal_digest("first-token")));
    }

    #[test]
    fn parses_only_64_character_hexadecimal_digests() {
        let digest = hexadecimal_digest("first-token");
        assert_eq!(
            parse_hexadecimal_digest(&digest),
            Some(sha256(b"first-token"))
        );
        assert_eq!(
            parse_hexadecimal_digest(&digest.to_ascii_uppercase()),
            Some(sha256(b"first-token"))
        );
        let digest_without_first_character: String = digest.chars().skip(1).collect();
        assert_eq!(
            parse_hexadecimal_digest(&digest_without_first_character),
            None
        );
        assert_eq!(parse_hexadecimal_digest(&format!("{digest}0")), None);
        assert_eq!(
            parse_hexadecimal_digest(&format!("+{digest_without_first_character}")),
            None
        );
        assert_eq!(
            parse_hexadecimal_digest(&format!("g{digest_without_first_character}")),
            None
        );
        assert_eq!(parse_hexadecimal_digest("first-token"), None);
    }

    fn temporary_digest_file(contents: &str, label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("host-proxy-{}-{label}", std::process::id()));
        std::fs::write(&path, contents).expect("failed to write temporary digest file");
        path
    }

    #[test]
    fn load_rejects_a_file_holding_a_plain_token() {
        let path = temporary_digest_file("first-token\n", "load-plain-token");
        assert!(BearerTokenDigests::load(path.to_str().unwrap(), false).is_err());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn reload_swaps_the_accepted_token_set() {
        let path = temporary_digest_file(&digest_file_contents(&["first-token"]), "reload-swap");
        let accepted = BearerTokenDigests::load(path.to_str().unwrap(), false).unwrap();
        assert!(accepts(&accepted, "first-token"));

        std::fs::write(&path, digest_file_contents(&["second-token"])).unwrap();
        accepted.reload();

        assert!(accepts(&accepted, "second-token"));
        assert!(!accepts(&accepted, "first-token"));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn reload_keeps_existing_digests_when_the_new_file_is_empty() {
        let path = temporary_digest_file(&digest_file_contents(&["only-token"]), "reload-empty");
        let accepted = BearerTokenDigests::load(path.to_str().unwrap(), false).unwrap();

        std::fs::write(&path, "\n   \n").unwrap();
        accepted.reload();

        assert!(accepts(&accepted, "only-token"));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn reload_keeps_existing_digests_when_the_new_file_holds_a_plain_token() {
        let path =
            temporary_digest_file(&digest_file_contents(&["only-token"]), "reload-plain-token");
        let accepted = BearerTokenDigests::load(path.to_str().unwrap(), false).unwrap();

        std::fs::write(&path, "second-token\n").unwrap();
        accepted.reload();

        assert!(accepts(&accepted, "only-token"));
        assert!(!accepts(&accepted, "second-token"));

        std::fs::remove_file(&path).unwrap();
    }

    fn identifies_tailnet_users(proxy: &HostProxy, hostname: &str) -> bool {
        matches!(
            proxy.routes_by_hostname.get(hostname),
            Some(Route::Proxy {
                identifies_tailnet_users: true,
                ..
            })
        )
    }

    #[test]
    fn tailnet_identity_is_off_unless_a_route_asks_for_it() {
        let mut proxy = HostProxy::new()
            .route("app.example.org", "127.0.0.1:3000", Access::Private)
            .route("other.example.org", "127.0.0.1:4000", Access::Private)
            .identify_tailnet_users("App.Example.org");
        proxy.apply_tailnet_identity();

        assert!(identifies_tailnet_users(&proxy, "app.example.org"));
        assert!(!identifies_tailnet_users(&proxy, "other.example.org"));
    }

    #[test]
    fn tailnet_identity_on_a_redirect_or_an_unknown_host_is_ignored() {
        let mut redirecting = HostProxy::new()
            .redirect("www.example.org", "example.org")
            .identify_tailnet_users("www.example.org");
        let mut unknown = HostProxy::new()
            .route("app.example.org", "127.0.0.1:3000", Access::Private)
            .identify_tailnet_users("typo.example.org");

        redirecting.apply_tailnet_identity();
        unknown.apply_tailnet_identity();

        assert!(matches!(
            redirecting.routes_by_hostname.get("www.example.org"),
            Some(Route::Redirect { .. })
        ));
        assert!(!identifies_tailnet_users(&unknown, "app.example.org"));
        assert!(!unknown.routes_by_hostname.contains_key("typo.example.org"));
    }
    fn identified_digest_file_contents(tokens: &[(&str, &str)]) -> String {
        tokens
            .iter()
            .map(|(token, identity)| format!("{} {identity}\n", hexadecimal_digest(token)))
            .collect::<Vec<String>>()
            .concat()
    }

    #[test]
    fn a_digest_line_may_name_the_identity_of_its_token() {
        let digest = hexadecimal_digest("first-token");

        assert_eq!(
            parse_accepted_token(&format!("{digest} fbrmarble.pan")),
            Some(AcceptedToken {
                digest: sha256(b"first-token"),
                identity: TokenIdentity::parse("fbrmarble.pan"),
            })
        );
        assert_eq!(
            parse_accepted_token(&digest),
            Some(AcceptedToken {
                digest: sha256(b"first-token"),
                identity: None,
            })
        );
    }

    #[test]
    fn a_digest_line_with_an_unsafe_identity_or_extra_fields_is_rejected() {
        let digest = hexadecimal_digest("first-token");

        assert_eq!(parse_accepted_token(&format!("{digest} pan,atlas")), None);
        assert_eq!(parse_accepted_token(&format!("{digest} pan atlas")), None);
        assert_eq!(
            parse_accepted_token(&format!("{digest} {}", "a".repeat(151))),
            None
        );
    }

    #[test]
    fn authenticating_returns_the_identity_of_the_matching_token() {
        let path = temporary_digest_file(
            &identified_digest_file_contents(&[
                ("pan-token", "fbrmarble.pan"),
                ("atlas-token", "chichek.atlas"),
            ]),
            "identities",
        );
        let accepted = BearerTokenDigests::load(path.to_str().unwrap(), true).unwrap();

        let identity_of = |token: &str| {
            accepted
                .authenticate(token)
                .and_then(|authenticated| authenticated.identity)
        };
        assert_eq!(
            identity_of("pan-token"),
            TokenIdentity::parse("fbrmarble.pan")
        );
        assert_eq!(
            identity_of("atlas-token"),
            TokenIdentity::parse("chichek.atlas")
        );
        assert!(accepted.authenticate("unknown-token").is_none());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_route_passing_identities_refuses_a_digest_without_one() {
        let mut contents = identified_digest_file_contents(&[("pan-token", "fbrmarble.pan")]);
        contents.push_str(&digest_file_contents(&["anonymous-token"]));
        let path = temporary_digest_file(&contents, "missing-identity");

        assert!(BearerTokenDigests::load(path.to_str().unwrap(), true).is_err());
        BearerTokenDigests::load(path.to_str().unwrap(), false).unwrap();

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_route_with_allowed_paths_admits_only_those_exact_paths() {
        let allowed = vec!["/loki/api/v1/push".to_string(), "/api/v1/push".to_string()];

        assert!(admits_path(
            "logs.example.org",
            Some(&allowed),
            "/loki/api/v1/push"
        ));
        assert!(admits_path(
            "logs.example.org",
            Some(&allowed),
            "/api/v1/push"
        ));
        assert!(!admits_path(
            "logs.example.org",
            Some(&allowed),
            "/loki/api/v1/query"
        ));
        assert!(!admits_path(
            "logs.example.org",
            Some(&allowed),
            "/loki/api/v1/push/"
        ));
        assert!(!admits_path(
            "logs.example.org",
            Some(&allowed),
            "/loki/api/v1/push/../query_range"
        ));
        assert!(!admits_path(
            "logs.example.org",
            Some(&allowed),
            "/loki/api/v1/%70ush"
        ));
        assert!(admits_path("logs.example.org", None, "/anything"));
    }

    #[test]
    fn allowed_paths_must_be_absolute_and_on_a_proxied_route() {
        let mut relative = HostProxy::new()
            .route("logs.example.org", "127.0.0.1:3100", Access::Public)
            .allow_paths("logs.example.org", vec!["loki/api/v1/push".to_string()]);
        let mut redirecting = HostProxy::new()
            .redirect("www.example.org", "example.org")
            .allow_paths("www.example.org", vec!["/".to_string()]);
        let mut empty = HostProxy::new()
            .route("logs.example.org", "127.0.0.1:3100", Access::Public)
            .allow_paths("logs.example.org", Vec::new());

        assert!(relative.apply_allowed_paths().is_err());
        assert!(redirecting.apply_allowed_paths().is_err());
        assert!(empty.apply_allowed_paths().is_err());
    }

    #[test]
    fn an_identity_header_needs_an_authenticated_route() {
        let tenant_header = HeaderName::from_static("x-scope-orgid");
        let mut unauthenticated = HostProxy::new()
            .route("logs.example.org", "127.0.0.1:3100", Access::Public)
            .pass_token_identity("logs.example.org", tenant_header.clone());
        let mut authenticated = HostProxy::new()
            .authenticated_route(
                "logs.example.org",
                "127.0.0.1:3100",
                Access::Public,
                "digests",
            )
            .pass_token_identity("Logs.Example.org", tenant_header.clone());

        assert!(unauthenticated.apply_identity_headers().is_err());
        authenticated.apply_identity_headers().unwrap();
        assert!(matches!(
            authenticated.routes_by_hostname.get("logs.example.org"),
            Some(Route::Proxy {
                identity_header: Some(header),
                ..
            }) if *header == tenant_header
        ));
    }
}
