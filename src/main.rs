use std::env;

use host_proxy::{Access, Certificate, HostProxy};

const ROUTES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_ROUTES";
const CERTIFICATES_ENVIRONMENT_VARIABLE: &str = "HOST_PROXY_CERTIFICATES";

fn required_environment_variable(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("environment variable {name} is required"))
}

fn main() {
    tracing_subscriber::fmt::init();

    let route_specification = required_environment_variable(ROUTES_ENVIRONMENT_VARIABLE);
    let certificates_specification = required_environment_variable(CERTIFICATES_ENVIRONMENT_VARIABLE);

    let mut proxy = HostProxy::new();

    for route_entry in route_specification
        .split(',')
        .filter(|route_entry| !route_entry.is_empty())
    {
        let Some((hostname, target)) = route_entry.split_once('=') else {
            panic!(
                "invalid route entry {route_entry:?} in {ROUTES_ENVIRONMENT_VARIABLE}, \
                 expected hostname=address, hostname=address!private, \
                 hostname=address!bearer=/path/to/tokens, or hostname=>redirecthost"
            );
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
                        other => panic!(
                            "unknown route tag {other:?}, expected 'private', 'public', \
                             or 'bearer=/path/to/tokens'"
                        ),
                    };
                }
            }

            match token_file_path {
                Some(path) => {
                    proxy.authenticated_route(hostname.trim(), upstream_address, access, &path)
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
            panic!(
                "invalid certificate entry {certificate_entry:?} in {CERTIFICATES_ENVIRONMENT_VARIABLE}, \
                 expected the form certificate_path:private_key_path"
            );
        };
        proxy = proxy.certificate(Certificate::new(
            certificate_path.trim().to_string(),
            private_key_path.trim().to_string(),
        ));
    }

    proxy.run();
}
