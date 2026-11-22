//! A standalone UniFi Teleport client that only routes what you ask it to.
//!
//! It signs in with a UI account ([`sso`]), finds the consoles and their LAN
//! subnets ([`cloud`]), asks a console for access ([`signaling`]), punches
//! through NAT ([`ice`]) and runs WireGuard over the punched path ([`tunnel`]).
//!
//! The protocol knowledge comes from darki73/telepy-cli (MIT), whose docs
//! describe it step by step.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

pub mod aws;
pub mod cloud;
pub mod connect;
mod http;
pub mod ice;
pub mod model;
pub mod platform;
pub mod signaling;
pub mod sso;
pub mod tunnel;

pub use model::{
    AccessGrant, AwsCredentials, Candidate, ClientOffer, CloudConfig, ConnectResult, Console, IceServer, Result,
    Session,
};

/// Extra destinations sent through Teleport, one per line. The console's own
/// LANs are routed without being listed.
pub const ROUTES_FILE: &str = "routes.conf";
/// What a new `routes.conf` starts with.
pub const ROUTES_HEADER: &str =
    "# Extra destinations routed through Teleport, one per line:\n# a network, an address or a host name.\n";
/// Holds the name of the console the daemon should be connected to.
pub const CONNECT_FILE: &str = "connect";

pub fn config_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/teleport-split")
}

/// A network, normalized to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Net> {
        let addr = match addr {
            IpAddr::V4(a) if prefix <= 32 => {
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                Ipv4Addr::from_bits(a.to_bits() & mask).into()
            }
            IpAddr::V6(a) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                Ipv6Addr::from_bits(a.to_bits() & mask).into()
            }
            _ => return None,
        };
        Some(Net { addr, prefix })
    }

    pub fn host(addr: IpAddr) -> Net {
        Net {
            addr,
            prefix: if addr.is_ipv4() { 32 } else { 128 },
        }
    }
}

impl FromStr for Net {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Net, ()> {
        match s.split_once('/') {
            Some((addr, prefix)) => {
                // u8::from_str accepts a leading '+', which route(8) would not.
                if !prefix.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(());
                }
                Net::new(addr.parse().map_err(drop)?, prefix.parse().map_err(drop)?).ok_or(())
            }
            None => Ok(Net::host(s.parse().map_err(drop)?)),
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Net(Net),
    Host(String),
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Entry::Net(net) if net.prefix == if net.addr.is_ipv4() { 32 } else { 128 } => net.addr.fmt(f),
            Entry::Net(net) => net.fmt(f),
            Entry::Host(host) => host.fmt(f),
        }
    }
}

impl FromStr for Entry {
    type Err = ();
    /// The trust boundary: the root daemon passes these to route(8) and the resolver.
    fn from_str(s: &str) -> std::result::Result<Entry, ()> {
        if let Ok(net) = s.parse::<Net>() {
            // A /0 would replace the default route, the opposite of a split tunnel.
            return if net.prefix == 0 { Err(()) } else { Ok(Entry::Net(net)) };
        }
        let label = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        };
        // Requiring a letter keeps malformed addresses ("1.2.3") from being resolved as names.
        if s.len() <= 253 && s.split('.').all(label) && s.bytes().any(|b| b.is_ascii_alphabetic()) {
            Ok(Entry::Host(s.to_ascii_lowercase()))
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Config {
    pub entries: Vec<Entry>,
    /// 1-based numbers of the lines that are not valid entries.
    pub bad_lines: Vec<usize>,
}

pub fn parse_config(text: &str) -> Config {
    let mut config = Config::default();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match line.parse() {
            Ok(entry) => config.entries.push(entry),
            Err(()) => config.bad_lines.push(number + 1),
        }
    }
    config
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum State {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    /// The last attempt failed; the daemon will try again.
    Failed,
}

/// What the daemon is doing. Written as `key=value` lines so that any frontend
/// can read it without a parser dependency.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Status {
    pub state: State,
    pub console: String,
    pub iface: String,
    /// Destinations routed through Teleport.
    pub routes: Vec<String>,
    /// Destinations left alone because they overlap a local network or could not be routed.
    pub skipped: Vec<String>,
    pub error: String,
}

impl Status {
    /// One line for a person.
    pub fn summary(&self) -> String {
        match self.state {
            State::Disconnected => "Not connected".into(),
            State::Connecting => format!("Connecting to {}…", self.console),
            State::Connected => format!("Connected to {}: {} routes", self.console, self.routes.len()),
            State::Failed => format!(
                "Could not connect to {}: {}",
                self.console,
                self.error.replace(['\n', '\r'], " ")
            ),
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = match self.state {
            State::Disconnected => "disconnected",
            State::Connecting => "connecting",
            State::Connected => "connected",
            State::Failed => "failed",
        };
        // One value per line: an error text must not be able to forge another key.
        let line = |v: &str| v.replace(['\n', '\r'], " ");
        writeln!(f, "state={state}")?;
        writeln!(f, "console={}", line(&self.console))?;
        writeln!(f, "interface={}", self.iface)?;
        writeln!(f, "error={}", line(&self.error))?;
        self.routes.iter().try_for_each(|r| writeln!(f, "route={r}"))?;
        self.skipped.iter().try_for_each(|r| writeln!(f, "skipped={r}"))
    }
}

impl FromStr for Status {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Status, ()> {
        let mut status = Status::default();
        for line in s.lines() {
            match line.split_once('=').ok_or(())? {
                ("state", "disconnected") => status.state = State::Disconnected,
                ("state", "connecting") => status.state = State::Connecting,
                ("state", "connected") => status.state = State::Connected,
                ("state", "failed") => status.state = State::Failed,
                ("console", v) => status.console = v.into(),
                ("interface", v) => status.iface = v.into(),
                ("error", v) => status.error = v.into(),
                ("route", v) => status.routes.push(v.into()),
                ("skipped", v) => status.skipped.push(v.into()),
                _ => {} // a newer daemon may write keys this build does not know
            }
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    #[test]
    fn nets_are_normalized_and_validated() {
        assert_eq!(net("192.168.1.77/24").to_string(), "192.168.1.0/24");
        assert_eq!(net("10.1.2.3").to_string(), "10.1.2.3/32");
        assert_eq!(net("fd00:1::5/64").to_string(), "fd00:1::/64");
        assert_eq!(net("0.0.0.0/0").to_string(), "0.0.0.0/0");
        for bad in ["10.0.0.0/33", "fd00::/129", "10.0.0.0/+8", "10.0.0.0/", "1.2.3/24", ""] {
            assert!(bad.parse::<Net>().is_err(), "{bad}");
        }
    }

    #[test]
    fn config_rejects_what_must_not_reach_route() {
        let config = parse_config(
            "# comment\n192.168.1.0/24  # lan\n\nNAS.Home.Example\n0.0.0.0/0\n-interface en0\n1.2.3\na;b\n10.0.0.5\n",
        );
        assert_eq!(
            config.entries,
            [
                Entry::Net(net("192.168.1.0/24")),
                Entry::Host("nas.home.example".into()),
                Entry::Net(net("10.0.0.5/32"))
            ]
        );
        assert_eq!(config.bad_lines, [5, 6, 7, 8]);
        assert_eq!(config.entries[2].to_string(), "10.0.0.5");
    }

    #[test]
    fn status_round_trips_and_stays_one_value_per_line() {
        let status = Status {
            state: State::Failed,
            console: "Home".into(),
            iface: "utun7".into(),
            routes: vec!["192.168.1.0/24".into()],
            skipped: vec!["10.0.0.0/8".into()],
            error: "timed out".into(),
        };
        assert_eq!(status.to_string().parse(), Ok(status));
        assert_eq!(
            "state=connected\nfuture=1\n".parse::<Status>().unwrap().state,
            State::Connected
        );

        let forged = Status {
            error: "x\nstate=connected".into(),
            ..Status::default()
        };
        assert_eq!(forged.to_string().parse::<Status>().unwrap().state, State::Disconnected);
    }
}
