use std::env;

use host_proxy::HostProxy;

const ROUTES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_ROUTES";
const CERTIFICATE_FILE_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_CERTIFICATE_FILE";
const PRIVATE_KEY_FILE_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_PRIVATE_KEY_FILE";

fn required_environment_variable(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("environment variable {name} is required"))
}

fn main() {
    tracing_subscriber::fmt::init();

    let route_specification = required_environment_variable(ROUTES_ENVIRONMENT_VARIABLE);

    let mut proxy = HostProxy::new();
    for route_entry in route_specification
        .split(',')
        .filter(|route_entry| !route_entry.is_empty())
    {
        let Some((hostname, upstream_address)) = route_entry.split_once('=') else {
            panic!(
                "invalid route entry {route_entry:?} in {ROUTES_ENVIRONMENT_VARIABLE}, \
                 expected the form hostname=address"
            );
        };
        proxy = proxy.route(hostname.trim(), upstream_address.trim());
    }

    proxy
        .certificate(
            required_environment_variable(CERTIFICATE_FILE_ENVIRONMENT_VARIABLE),
            required_environment_variable(PRIVATE_KEY_FILE_ENVIRONMENT_VARIABLE),
        )
        .run();
}
