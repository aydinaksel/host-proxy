use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{event, Level};

pub const DEFAULT_TAILSCALED_SOCKET_PATH: &str = "/run/tailscale/tailscaled.sock";
pub(crate) const USER_LOGIN_HEADER: &str = "x-tailnet-user-login";
pub(crate) const USER_NAME_HEADER: &str = "x-tailnet-user-name";

const LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);
const CACHE_LIFETIME: Duration = Duration::from_mins(1);
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const WHOIS_HTTP_VERSION_WITHOUT_CHUNKED_BODIES: &str = "HTTP/1.0";
const LOCAL_API_HOST: &str = "local-tailscaled.sock";
const SUCCESS_STATUS_CODE: &str = "200";
const TAILSCALE_IPV6_PREFIX: [u16; 3] = [0xfd7a, 0x115c, 0xa1e0];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TailnetIdentity {
    pub(crate) login_name: String,
    pub(crate) display_name: String,
}

#[derive(Deserialize)]
struct WhoisResponse {
    #[serde(rename = "UserProfile")]
    user_profile: UserProfile,
}

#[derive(Deserialize)]
struct UserProfile {
    #[serde(rename = "LoginName")]
    login_name: String,
    #[serde(rename = "DisplayName", default)]
    display_name: String,
}

struct CachedIdentity {
    looked_up_at: Instant,
    identity: TailnetIdentity,
}

pub(crate) struct TailnetWhois {
    socket_path: String,
    identities_by_address: Mutex<HashMap<IpAddr, CachedIdentity>>,
}

fn is_tailnet_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ipv4) => {
            let [first_octet, second_octet, _, _] = ipv4.octets();
            first_octet == 100 && (second_octet & 0xC0) == 64
        }
        IpAddr::V6(ipv6) => match ipv6.to_ipv4_mapped() {
            Some(mapped_ipv4) => is_tailnet_address(IpAddr::V4(mapped_ipv4)),
            None => ipv6.segments().starts_with(&TAILSCALE_IPV6_PREFIX),
        },
    }
}

fn parse_whois_response(response: &[u8]) -> Result<TailnetIdentity, String> {
    let text = std::str::from_utf8(response)
        .map_err(|error| format!("tailscaled answered with invalid UTF-8: {error}"))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "tailscaled answered without a header terminator".to_string())?;
    let status_code = head
        .lines()
        .next()
        .and_then(|status_line| status_line.split_whitespace().nth(1))
        .ok_or_else(|| "tailscaled answered without a status line".to_string())?;
    if status_code != SUCCESS_STATUS_CODE {
        return Err(format!(
            "tailscaled answered {status_code}: {}",
            body.trim()
        ));
    }
    let whois: WhoisResponse = serde_json::from_str(body)
        .map_err(|error| format!("tailscaled answered with unexpected JSON: {error}"))?;
    Ok(TailnetIdentity {
        login_name: whois.user_profile.login_name,
        display_name: whois.user_profile.display_name,
    })
}

impl TailnetWhois {
    pub(crate) fn new(socket_path: String) -> Self {
        TailnetWhois {
            socket_path,
            identities_by_address: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn identify(&self, client: SocketAddr) -> Option<TailnetIdentity> {
        if !is_tailnet_address(client.ip()) {
            return None;
        }
        if let Some(identity) = self.cached(client.ip()) {
            return Some(identity);
        }
        let lookup_result = tokio::time::timeout(LOOKUP_TIMEOUT, self.look_up(client)).await;
        let identity = match lookup_result {
            Ok(Ok(identity)) => identity,
            Ok(Err(error)) => {
                event!(
                    name: "proxy.tailnet.lookup_failed",
                    Level::WARN,
                    client.address = client.to_string(),
                    error.message = error,
                    "could not identify tailnet client {{client.address}}: {{error.message}}",
                );
                return None;
            }
            Err(elapsed) => {
                event!(
                    name: "proxy.tailnet.lookup_timed_out",
                    Level::WARN,
                    client.address = client.to_string(),
                    error.message = elapsed.to_string(),
                    "tailscaled did not identify {{client.address}} in time: {{error.message}}",
                );
                return None;
            }
        };
        self.remember(client.ip(), identity.clone());
        Some(identity)
    }

    fn cached(&self, address: IpAddr) -> Option<TailnetIdentity> {
        let identities = self
            .identities_by_address
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        identities
            .get(&address)
            .filter(|cached| cached.looked_up_at.elapsed() < CACHE_LIFETIME)
            .map(|cached| cached.identity.clone())
    }

    fn remember(&self, address: IpAddr, identity: TailnetIdentity) {
        let mut identities = self
            .identities_by_address
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        identities.insert(
            address,
            CachedIdentity {
                looked_up_at: Instant::now(),
                identity,
            },
        );
    }

    async fn look_up(&self, client: SocketAddr) -> Result<TailnetIdentity, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|error| format!("failed to connect to {}: {error}", self.socket_path))?;
        let request = format!(
            "GET /localapi/v0/whois?addr={client} {WHOIS_HTTP_VERSION_WITHOUT_CHUNKED_BODIES}\r\nHost: {LOCAL_API_HOST}\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("failed to send the whois request: {error}"))?;
        let mut response = Vec::new();
        (&mut stream)
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut response)
            .await
            .map_err(|error| format!("failed to read the whois response: {error}"))?;
        parse_whois_response(&response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{is_tailnet_address, parse_whois_response, TailnetIdentity};

    fn parsed(address: &str) -> IpAddr {
        address.parse().expect("invalid test address")
    }

    #[test]
    fn tailnet_addresses_are_the_cgnat_range_and_the_tailscale_ipv6_prefix() {
        assert!(is_tailnet_address(parsed("100.64.0.5")));
        assert!(is_tailnet_address(parsed("100.127.255.254")));
        assert!(is_tailnet_address(parsed("fd7a:115c:a1e0::5")));
        assert!(is_tailnet_address(parsed("::ffff:100.64.0.5")));
        assert!(!is_tailnet_address(parsed("10.0.0.2")));
        assert!(!is_tailnet_address(parsed("fd00::1")));
        assert!(!is_tailnet_address(parsed("8.8.8.8")));
    }

    #[test]
    fn a_successful_whois_names_the_user() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n\
            {\"Node\":{\"ID\":7},\"UserProfile\":{\"ID\":3,\"LoginName\":\"aydin@\",\"DisplayName\":\"Aydin Aksel\"}}";
        assert_eq!(
            parse_whois_response(response),
            Ok(TailnetIdentity {
                login_name: "aydin@".to_string(),
                display_name: "Aydin Aksel".to_string(),
            })
        );
    }

    #[test]
    fn a_missing_display_name_leaves_it_empty() {
        let response =
            b"HTTP/1.0 200 OK\r\n\r\n{\"UserProfile\":{\"LoginName\":\"stephanieaksel@\"}}";
        assert_eq!(
            parse_whois_response(response).map(|identity| identity.display_name),
            Ok(String::new())
        );
    }

    #[test]
    fn an_unknown_address_is_an_error() {
        let response = b"HTTP/1.0 404 Not Found\r\n\r\nno match for IP:port\n";
        let error = parse_whois_response(response).unwrap_err();
        assert!(error.contains("404"), "unexpected error: {error}");
    }
}
