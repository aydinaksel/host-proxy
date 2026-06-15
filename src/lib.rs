use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::tls::nid::Nid;
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::{
    AlpnError, NameType, SslContext, SslMethod, SslRef, select_next_proto,
};
use pingora::tls::x509::X509;
use pingora::{Error, ErrorType};
use tracing::{Level, event};

const NEGOTIATED_ALPN_PROTOCOLS: &[u8] = b"\x02h2\x08http/1.1";

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

pub struct HostProxy {
    upstream_addresses_by_hostname: HashMap<String, String>,
    certificates: Vec<Certificate>,
}

impl HostProxy {
    pub fn new() -> Self {
        HostProxy {
            upstream_addresses_by_hostname: HashMap::new(),
            certificates: Vec::new(),
        }
    }

    pub fn route(
        mut self,
        hostname: impl Into<String>,
        upstream_address: impl Into<String>,
    ) -> Self {
        self.upstream_addresses_by_hostname
            .insert(hostname.into().to_ascii_lowercase(), upstream_address.into());
        self
    }

    pub fn certificate(mut self, certificate: Certificate) -> Self {
        self.certificates.push(certificate);
        self
    }

    pub fn run(self) -> ! {
        if self.upstream_addresses_by_hostname.is_empty() {
            panic!("no routes configured");
        }
        if self.certificates.is_empty() {
            panic!("no certificates configured");
        }

        for (hostname, upstream_address) in &self.upstream_addresses_by_hostname {
            event!(
                name: "proxy.route.configured",
                Level::INFO,
                server.address = hostname,
                upstream.address = upstream_address,
                "routing {{server.address}} to {{upstream.address}}",
            );
        }

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
                upstream_addresses_by_hostname: self.upstream_addresses_by_hostname,
            },
        );
        router_service.threads = Some(available_worker_thread_count());

        let mut tls_settings = pingora::listeners::tls::TlsSettings::intermediate(
            &first_certificate.certificate_path,
            &first_certificate.private_key_path,
        )
        .expect("failed to create TLS settings");

        let sni_resolver = Arc::clone(&resolver);
        tls_settings.set_servername_callback(move |ssl: &mut SslRef, _| {
            if let Some(server_name) = ssl.servername(NameType::HOST_NAME) {
                if let Some(context) = sni_resolver.resolve(server_name) {
                    ssl.set_ssl_context(context).ok();
                }
            }
            Ok(())
        });

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

fn available_worker_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
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
