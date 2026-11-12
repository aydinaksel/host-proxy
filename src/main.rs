use std::convert::Infallible;
use std::env;
use std::process::ExitCode;

use host_proxy::{Access, Certificate, ClientNetwork, HeaderName, HostProxy, HostProxyError};
use tracing::{event, Level};

const ROUTES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_ROUTES";
const CERTIFICATES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_CERTIFICATES";
const RATE_LIMIT_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_RATE_LIMIT_PER_SECOND";
const METRICS_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_METRICS_ADDRESS";
const TAILSCALED_SOCKET_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_TAILSCALED_SOCKET";
const HTTPS_ADDRESSES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_HTTPS_ADDRESSES";
const HTTP_ADDRESSES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_HTTP_ADDRESSES";
const TAILNET_IDENTITY_TAG: &str = "tailnet-identity";
const CLIENT_NETWORKS_TAG_PREFIX: &str = "networks=";
const ALLOWED_PATHS_TAG_PREFIX: &str = "paths=";
const IDENTITY_HEADER_TAG_PREFIX: &str = "identity-header=";
const LIST_SEPARATOR: char = '+';

fn required_environment_variable(name: &str) -> Result<String, HostProxyError> {
    env::var(name).map_err(|error| {
        HostProxyError::new(format!("environment variable {name} is required: {error}"))
    })
}

fn optional_environment_variable(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn address_list(name: &str) -> Option<Vec<String>> {
    optional_environment_variable(name).map(|addresses| {
        addresses
            .split(',')
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .map(str::to_string)
            .collect()
    })
}

fn parse_client_networks(networks: &str) -> Result<Vec<ClientNetwork>, HostProxyError> {
    let parsed: Vec<ClientNetwork> = networks
        .split(LIST_SEPARATOR)
        .map(|network| {
            network
                .parse()
                .map_err(|error| HostProxyError::new(format!("{error}")))
        })
        .collect::<Result<_, _>>()?;
    if parsed.is_empty() {
        return Err(HostProxyError::new("the networks tag lists no networks"));
    }
    Ok(parsed)
}

fn parse_allowed_paths(paths: &str) -> Vec<String> {
    paths
        .split(LIST_SEPARATOR)
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_identity_header(header: &str) -> Result<HeaderName, HostProxyError> {
    HeaderName::from_bytes(header.trim().as_bytes()).map_err(|error| {
        HostProxyError::new(format!("invalid identity header {header:?}: {error}"))
    })
}

fn add_route_entry(proxy: HostProxy, route_entry: &str) -> Result<HostProxy, HostProxyError> {
    let Some((hostname, target)) = route_entry.split_once('=') else {
        return Err(HostProxyError::new(format!(
            "invalid route entry {route_entry:?} in {ROUTES_ENVIRONMENT_VARIABLE}, \
             expected hostname=address, hostname=address!private, \
             hostname=address!bearer-sha256=/path/to/digests, hostname=address!tailnet-identity, \
             hostname=address!networks=192.0.2.0/24+198.51.100.0/24, \
             hostname=address!paths=/write+/push, hostname=address!identity-header=X-Scope-OrgID, \
             or hostname=>redirecthost"
        )));
    };

    let proxy = if let Some(redirect_host) = target.strip_prefix('>') {
        proxy.redirect(hostname.trim(), redirect_host.trim())
    } else {
        let mut tags = target.split('!');
        let upstream_address = tags.next().unwrap_or(target).trim();

        let mut access = Access::Public;
        let mut token_digest_file_path = None;
        let mut identifies_tailnet_users = false;
        let mut allowed_client_networks = None;
        let mut allowed_paths = None;
        let mut identity_header = None;

        for tag in tags {
            let tag = tag.trim();
            if let Some(path) = tag.strip_prefix("bearer-sha256=") {
                token_digest_file_path = Some(path.trim().to_string());
            } else if tag == TAILNET_IDENTITY_TAG {
                identifies_tailnet_users = true;
            } else if let Some(networks) = tag.strip_prefix(CLIENT_NETWORKS_TAG_PREFIX) {
                allowed_client_networks = Some(parse_client_networks(networks)?);
            } else if let Some(paths) = tag.strip_prefix(ALLOWED_PATHS_TAG_PREFIX) {
                allowed_paths = Some(parse_allowed_paths(paths));
            } else if let Some(header) = tag.strip_prefix(IDENTITY_HEADER_TAG_PREFIX) {
                identity_header = Some(parse_identity_header(header)?);
            } else {
                access = match tag {
                    "private" => Access::Private,
                    "public" => Access::Public,
                    other => {
                        return Err(HostProxyError::new(format!(
                            "unknown route tag {other:?}, expected 'private', 'public', \
                             'tailnet-identity', 'networks=...', 'paths=...', 'identity-header=...', \
                             or 'bearer-sha256=/path/to/digests'"
                        )));
                    }
                };
            }
        }

        let routed = match token_digest_file_path {
            Some(path) => {
                proxy.authenticated_route(hostname.trim(), upstream_address, access, path)
            }
            None => proxy.route(hostname.trim(), upstream_address, access),
        };
        let identified = if identifies_tailnet_users {
            routed.identify_tailnet_users(hostname.trim())
        } else {
            routed
        };
        let restricted_to_networks = match allowed_client_networks {
            Some(networks) => identified.allow_clients_from(hostname.trim(), networks),
            None => identified,
        };
        let restricted_to_paths = match allowed_paths {
            Some(paths) => restricted_to_networks.allow_paths(hostname.trim(), paths),
            None => restricted_to_networks,
        };
        match identity_header {
            Some(header) => restricted_to_paths.pass_token_identity(hostname.trim(), header),
            None => restricted_to_paths,
        }
    };
    Ok(proxy)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt::init();

    match configure_and_run() {
        Ok(never) => match never {},
        Err(error) => {
            event!(
                name: "proxy.startup.failed",
                Level::ERROR,
                error.message = error.to_string(),
                "proxy failed to start: {{error.message}}",
            );
            ExitCode::FAILURE
        }
    }
}

fn configure_and_run() -> Result<Infallible, HostProxyError> {
    let route_specification = required_environment_variable(ROUTES_ENVIRONMENT_VARIABLE)?;
    let certificates_specification =
        required_environment_variable(CERTIFICATES_ENVIRONMENT_VARIABLE)?;

    let mut proxy = HostProxy::new();

    if let Some(rate_limit) = optional_environment_variable(RATE_LIMIT_ENVIRONMENT_VARIABLE) {
        let max_requests_per_second = rate_limit.parse().map_err(|error| {
            HostProxyError::new(format!(
                "invalid value {rate_limit:?} in {RATE_LIMIT_ENVIRONMENT_VARIABLE}, \
                 expected a positive integer: {error}"
            ))
        })?;
        proxy = proxy.rate_limit_per_second(max_requests_per_second);
    }

    if let Some(metrics_address) = optional_environment_variable(METRICS_ENVIRONMENT_VARIABLE) {
        proxy = proxy.metrics_address(metrics_address);
    }

    if let Some(socket_path) = optional_environment_variable(TAILSCALED_SOCKET_ENVIRONMENT_VARIABLE)
    {
        proxy = proxy.tailscaled_socket_path(socket_path);
    }

    if let Some(addresses) = address_list(HTTPS_ADDRESSES_ENVIRONMENT_VARIABLE) {
        proxy = proxy.https_addresses(addresses);
    }

    if let Some(addresses) = address_list(HTTP_ADDRESSES_ENVIRONMENT_VARIABLE) {
        proxy = proxy.http_addresses(addresses);
    }

    for route_entry in route_specification
        .split(',')
        .filter(|route_entry| !route_entry.is_empty())
    {
        proxy = add_route_entry(proxy, route_entry)?;
    }

    for certificate_entry in certificates_specification
        .split(',')
        .filter(|entry| !entry.is_empty())
    {
        let Some((certificate_path, private_key_path)) = certificate_entry.split_once(':') else {
            return Err(HostProxyError::new(format!(
                "invalid certificate entry {certificate_entry:?} in \
                 {CERTIFICATES_ENVIRONMENT_VARIABLE}, expected the form \
                 certificate_path:private_key_path"
            )));
        };
        proxy = proxy.certificate(Certificate::new(
            certificate_path.trim().to_string(),
            private_key_path.trim().to_string(),
        ));
    }

    proxy.run()
}
