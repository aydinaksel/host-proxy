use std::convert::Infallible;
use std::env;
use std::process::ExitCode;

use host_proxy::{Access, Certificate, HostProxy, HostProxyError};
use tracing::{event, Level};

const ROUTES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_ROUTES";
const CERTIFICATES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_CERTIFICATES";
const RATE_LIMIT_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_RATE_LIMIT_PER_SECOND";
const METRICS_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_METRICS_ADDRESS";

fn required_environment_variable(name: &str) -> Result<String, HostProxyError> {
    env::var(name).map_err(|error| {
        HostProxyError::new(format!("environment variable {name} is required: {error}"))
    })
}

fn optional_environment_variable(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
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

    for route_entry in route_specification
        .split(',')
        .filter(|route_entry| !route_entry.is_empty())
    {
        let Some((hostname, target)) = route_entry.split_once('=') else {
            return Err(HostProxyError::new(format!(
                "invalid route entry {route_entry:?} in {ROUTES_ENVIRONMENT_VARIABLE}, \
                 expected hostname=address, hostname=address!private, \
                 hostname=address!bearer=/path/to/tokens, or hostname=>redirecthost"
            )));
        };

        proxy = if let Some(redirect_host) = target.strip_prefix('>') {
            proxy.redirect(hostname.trim(), redirect_host.trim())
        } else {
            let mut tags = target.split('!');
            let upstream_address = tags.next().unwrap_or(target).trim();

            let mut access = Access::Public;
            let mut token_file_path = None;

            for tag in tags {
                let tag = tag.trim();
                if let Some(path) = tag.strip_prefix("bearer=") {
                    token_file_path = Some(path.trim().to_string());
                } else {
                    access = match tag {
                        "private" => Access::Private,
                        "public" => Access::Public,
                        other => {
                            return Err(HostProxyError::new(format!(
                                "unknown route tag {other:?}, expected 'private', 'public', \
                                 or 'bearer=/path/to/tokens'"
                            )));
                        }
                    };
                }
            }

            match token_file_path {
                Some(path) => {
                    proxy.authenticated_route(hostname.trim(), upstream_address, access, path)
                }
                None => proxy.route(hostname.trim(), upstream_address, access),
            }
        };
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
