use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

const IPV4_ADDRESS_BITS: u8 = 32;
const IPV6_ADDRESS_BITS: u8 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientNetwork {
    network_address: IpAddr,
    prefix_length_bits: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidClientNetwork {
    text: String,
    reason: String,
}

impl fmt::Display for InvalidClientNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid client network {:?} ({}), expected an address and prefix length such as 192.0.2.0/24",
            self.text, self.reason
        )
    }
}

impl FromStr for ClientNetwork {
    type Err = InvalidClientNetwork;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: String| InvalidClientNetwork {
            text: text.to_string(),
            reason,
        };
        let (address_text, prefix_text) = text
            .trim()
            .split_once('/')
            .ok_or_else(|| invalid("no prefix length".to_string()))?;
        let network_address: IpAddr = address_text
            .parse()
            .map_err(|error| invalid(format!("address: {error}")))?;
        let prefix_length_bits: u8 = prefix_text
            .parse()
            .map_err(|error| invalid(format!("prefix length: {error}")))?;
        if prefix_length_bits > address_bits(network_address) {
            return Err(invalid(format!(
                "a prefix of {prefix_length_bits} bits is longer than the address"
            )));
        }
        Ok(ClientNetwork {
            network_address,
            prefix_length_bits,
        })
    }
}

impl fmt::Display for ClientNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}",
            self.network_address, self.prefix_length_bits
        )
    }
}

impl ClientNetwork {
    #[must_use]
    pub fn contains(&self, client_address: IpAddr) -> bool {
        match (self.network_address, comparable_address(client_address)) {
            (IpAddr::V4(network), IpAddr::V4(client)) => {
                let mask = network_mask_v4(self.prefix_length_bits);
                u32::from(network) & mask == u32::from(client) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(client)) => {
                let mask = network_mask_v6(self.prefix_length_bits);
                u128::from(network) & mask == u128::from(client) & mask
            }
            _ => false,
        }
    }
}

fn address_bits(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => IPV4_ADDRESS_BITS,
        IpAddr::V6(_) => IPV6_ADDRESS_BITS,
    }
}

fn comparable_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn network_mask_v4(prefix_length_bits: u8) -> u32 {
    let host_bits = u32::from(IPV4_ADDRESS_BITS.saturating_sub(prefix_length_bits));
    u32::MAX.checked_shl(host_bits).unwrap_or(0)
}

fn network_mask_v6(prefix_length_bits: u8) -> u128 {
    let host_bits = u32::from(IPV6_ADDRESS_BITS.saturating_sub(prefix_length_bits));
    u128::MAX.checked_shl(host_bits).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::ClientNetwork;

    fn network(text: &str) -> ClientNetwork {
        text.parse().unwrap()
    }

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_address_inside_the_network_is_contained() {
        let anthropic = network("160.79.104.0/21");

        assert!(anthropic.contains(address("160.79.104.1")));
        assert!(anthropic.contains(address("160.79.111.254")));
    }

    #[test]
    fn an_address_just_outside_the_network_is_not() {
        let anthropic = network("160.79.104.0/21");

        assert!(!anthropic.contains(address("160.79.112.0")));
        assert!(!anthropic.contains(address("160.79.103.255")));
    }

    #[test]
    fn an_ipv4_client_seen_as_an_ipv6_mapped_address_still_matches() {
        assert!(network("153.61.208.0/20").contains(address("::ffff:153.61.223.9")));
    }

    #[test]
    fn ipv6_networks_match_ipv6_clients_only() {
        let documentation = network("2001:db8::/32");

        assert!(documentation.contains(address("2001:db8:1::1")));
        assert!(!documentation.contains(address("2001:db9::1")));
        assert!(!documentation.contains(address("192.0.2.1")));
    }

    #[test]
    fn a_zero_length_prefix_contains_every_address_of_its_family() {
        assert!(network("0.0.0.0/0").contains(address("203.0.113.7")));
        assert!(!network("0.0.0.0/0").contains(address("2001:db8::1")));
    }

    #[test]
    fn malformed_networks_are_rejected() {
        for text in [
            "160.79.104.0",
            "160.79.104.0/33",
            "not-an-address/8",
            "10.0.0.0/x",
        ] {
            assert!(
                text.parse::<ClientNetwork>().is_err(),
                "{text} should be rejected"
            );
        }
    }

    #[test]
    fn a_network_displays_as_it_was_written() {
        assert_eq!(network("160.79.104.0/21").to_string(), "160.79.104.0/21");
    }
}
