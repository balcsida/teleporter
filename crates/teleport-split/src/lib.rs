//! Split tunneling for UniFi Teleport.
//!
//! WiFiman connects Teleport as a full tunnel: its `wg-quick` installs the
//! broad routes in [`BROAD`], which capture all traffic. [`reconcile`] removes
//! them and routes only the configured destinations through the tunnel.
//!
//! Everything OS-specific sits behind [`Os`]. Frontends share no code with the
//! daemon: they write the files in [`config_dir`] and read [`Status`].

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fmt, fs, io};

pub mod platform;

/// The routes `wg-quick` adds for `AllowedIPs = 0.0.0.0/0, ::/0`.
pub const BROAD: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

/// Destinations sent through Teleport, one per line.
pub const ROUTES_FILE: &str = "routes.conf";
/// While this file exists the daemon leaves Teleport as a full tunnel.
pub const DISABLED_FILE: &str = "disabled";

/// Used until the user has a `routes.conf`: the private ranges, so a home LAN
/// is reachable without any setup. More-specific local routes still win.
pub const DEFAULT_ROUTES: &str = "\
# Destinations routed through UniFi Teleport, one per line:
# a network (192.168.1.0/24), an address (192.168.1.10) or a host name.
# Everything else stays on your normal connection.
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
";

pub fn config_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/teleport-split")
}

/// The text of `routes.conf` in `dir`, or the defaults while it does not exist.
pub fn read_routes(dir: &Path) -> io::Result<String> {
    match fs::read_to_string(dir.join(ROUTES_FILE)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(DEFAULT_ROUTES.into()),
        other => other,
    }
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
    fn from_str(s: &str) -> Result<Net, ()> {
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
    fn from_str(s: &str) -> Result<Entry, ()> {
        if let Ok(net) = s.parse::<Net>() {
            // A /0 or a broad route would be the full tunnel again, and the
            // daemon would add and sweep it in turns; that is what `off` is for.
            return if net.prefix == 0 || broad().any(|b| b == net) {
                Err(())
            } else {
                Ok(Entry::Net(net))
            };
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
    /// Teleport is not connected.
    #[default]
    Disconnected,
    /// Only the configured routes use Teleport.
    Split,
    /// Teleport carries all traffic, as WiFiman set it up.
    Full,
}

/// What the daemon last did. Written as `key=value` lines so that any frontend
/// can read it without a parser dependency.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Status {
    pub state: State,
    pub iface: String,
    /// Destinations currently routed through Teleport.
    pub routes: Vec<String>,
    /// Destinations that could not be routed or resolved.
    pub failed: Vec<String>,
    pub bad_lines: Vec<usize>,
}

impl Status {
    /// One line for a person.
    pub fn summary(&self) -> String {
        let failed = match self.failed.len() {
            0 => String::new(),
            n => format!(", {n} failed"),
        };
        match self.state {
            State::Disconnected => "Teleport is not connected".into(),
            State::Full => format!("Full tunnel on {}{failed}", self.iface),
            State::Split => format!("Split tunnel on {}: {} routes{failed}", self.iface, self.routes.len()),
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = match self.state {
            State::Disconnected => "disconnected",
            State::Split => "split",
            State::Full => "full",
        };
        writeln!(f, "state={state}")?;
        writeln!(f, "interface={}", self.iface)?;
        self.routes.iter().try_for_each(|r| writeln!(f, "route={r}"))?;
        self.failed.iter().try_for_each(|r| writeln!(f, "failed={r}"))?;
        self.bad_lines.iter().try_for_each(|n| writeln!(f, "bad_line={n}"))
    }
}

impl FromStr for Status {
    type Err = ();
    fn from_str(s: &str) -> Result<Status, ()> {
        let mut status = Status::default();
        for line in s.lines() {
            match line.split_once('=').ok_or(())? {
                ("state", "disconnected") => status.state = State::Disconnected,
                ("state", "split") => status.state = State::Split,
                ("state", "full") => status.state = State::Full,
                ("interface", v) => status.iface = v.into(),
                ("route", v) => status.routes.push(v.into()),
                ("failed", v) => status.failed.push(v.into()),
                ("bad_line", v) => status.bad_lines.push(v.parse().map_err(drop)?),
                _ => {} // a newer daemon may write keys this build does not know
            }
        }
        Ok(status)
    }
}

/// The Teleport tunnel as the OS sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Tunnel {
    pub iface: String,
    /// Networks of the tunnel's own addresses. WiFiman talks to the gateway
    /// inside the tunnel, so these stay routed in split mode.
    pub nets: Vec<Net>,
}

/// The platform boundary. A backend only has to find WiFiman's tunnel and edit
/// the routing table; [`reconcile`] decides what to change.
pub trait Os {
    /// WiFiman's tunnel, if Teleport is connected. Must never return another
    /// VPN's interface: its broad routes would be removed.
    fn tunnel(&self) -> Option<Tunnel>;
    /// The interface the routing table sends `net` to.
    fn route_iface(&self, net: Net) -> Option<String>;
    fn add_route(&mut self, net: Net, iface: &str);
    fn delete_route(&mut self, net: Net, iface: &str);
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        (host, 0)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .unwrap_or_default()
    }
}

/// The routes this process added, and on which tunnel.
// shortcut: kept in memory only, so routes added before a daemon restart are
// not pruned until Teleport reconnects; persist it if that ever matters.
#[derive(Debug, Default)]
pub struct Applied {
    iface: String,
    nets: BTreeSet<Net>,
}

fn broad() -> impl Iterator<Item = Net> {
    BROAD.iter().map(|b| b.parse().expect("BROAD holds valid networks"))
}

/// Bring the routing table in line with `config`: split tunnel if `split`,
/// otherwise WiFiman's full tunnel. Safe to call repeatedly.
pub fn reconcile(os: &mut impl Os, config: &Config, split: bool, applied: &mut Applied) -> Status {
    let Some(tunnel) = os.tunnel() else {
        *applied = Applied::default();
        return Status {
            bad_lines: config.bad_lines.clone(),
            ..Status::default()
        };
    };
    let iface = tunnel.iface.as_str();
    if applied.iface != iface {
        // A new tunnel: the old interface took its routes with it.
        *applied = Applied {
            iface: iface.into(),
            nets: BTreeSet::new(),
        };
    }
    let mut status = Status {
        iface: iface.into(),
        bad_lines: config.bad_lines.clone(),
        ..Status::default()
    };

    if !split {
        for net in std::mem::take(&mut applied.nets) {
            os.delete_route(net, iface);
        }
        // shortcut: restores all of BROAD because WiFiman always allows ::/0;
        // remember what was swept if it ever connects IPv4-only.
        for net in broad() {
            if os.route_iface(net).as_deref() != Some(iface) {
                os.add_route(net, iface);
                if os.route_iface(net).as_deref() != Some(iface) {
                    status.failed.push(net.to_string());
                }
            }
        }
        status.state = State::Full;
        return status;
    }

    for net in broad() {
        if os.route_iface(net).as_deref() == Some(iface) {
            os.delete_route(net, iface);
            // Never claim a split tunnel while a broad route is still in place.
            if os.route_iface(net).as_deref() == Some(iface) {
                status.failed.push(net.to_string());
            }
        }
    }

    let mut desired: BTreeSet<Net> = tunnel.nets.iter().copied().collect();
    let mut unresolved = false;
    for entry in &config.entries {
        match entry {
            Entry::Net(net) => drop(desired.insert(*net)),
            Entry::Host(host) => {
                let addrs = os.resolve(host);
                if addrs.is_empty() {
                    unresolved = true;
                    status.failed.push(host.clone());
                }
                desired.extend(addrs.into_iter().map(Net::host));
            }
        }
    }

    for &net in &desired {
        if os.route_iface(net).as_deref() != Some(iface) {
            os.add_route(net, iface);
            // route(8) exits 0 even when it fails, so ask the table instead.
            if os.route_iface(net).as_deref() != Some(iface) {
                status.failed.push(net.to_string());
                continue;
            }
            applied.nets.insert(net);
        }
        status.routes.push(net.to_string());
    }

    // A name that failed to resolve keeps its old routes rather than flapping.
    if !unresolved {
        for net in applied.nets.difference(&desired).copied().collect::<Vec<_>>() {
            os.delete_route(net, iface);
            applied.nets.remove(&net);
        }
    }

    status.state = State::Split;
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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
            "# comment\n192.168.1.0/24  # lan\n\nNAS.Home.Example\n0.0.0.0/0\n-interface en0\n1.2.3\na;b\n10.0.0.5\n128.9.9.9/1\n",
        );
        assert_eq!(
            config.entries,
            [
                Entry::Net(net("192.168.1.0/24")),
                Entry::Host("nas.home.example".into()),
                Entry::Net(net("10.0.0.5/32"))
            ]
        );
        assert_eq!(config.bad_lines, [5, 6, 7, 8, 10]);
        assert_eq!(config.entries[2].to_string(), "10.0.0.5");
        assert!(parse_config(DEFAULT_ROUTES).bad_lines.is_empty());
        assert_eq!(parse_config(DEFAULT_ROUTES).entries.len(), 3);
    }

    #[test]
    fn status_round_trips() {
        let status = Status {
            state: State::Split,
            iface: "utun8".into(),
            routes: vec!["192.168.1.0/24".into()],
            failed: vec!["nas.home.example".into()],
            bad_lines: vec![3],
        };
        assert_eq!(status.to_string().parse(), Ok(status));
        assert_eq!("state=full\nfuture=1\n".parse::<Status>().unwrap().state, State::Full);
    }

    /// A routing table with exact-match lookups, plus a default route on en0.
    #[derive(Default)]
    struct Fake {
        tunnel: Option<Tunnel>,
        table: BTreeMap<Net, String>,
        dns: BTreeMap<&'static str, Vec<IpAddr>>,
        /// The table rejects every change, as it does without root.
        read_only: bool,
    }

    impl Fake {
        /// Teleport connected the way WiFiman leaves it.
        fn connected() -> Fake {
            let mut fake = Fake {
                tunnel: Some(Tunnel {
                    iface: "utun8".into(),
                    nets: vec![net("fd37::/64")],
                }),
                ..Fake::default()
            };
            fake.table.extend(broad().map(|b| (b, "utun8".to_string())));
            fake.table.insert(net("fd37::/64"), "utun8".into());
            fake
        }

        fn on_tunnel(&self) -> Vec<String> {
            self.table
                .iter()
                .filter(|(_, i)| *i == "utun8")
                .map(|(n, _)| n.to_string())
                .collect()
        }
    }

    impl Os for Fake {
        fn tunnel(&self) -> Option<Tunnel> {
            self.tunnel.clone()
        }
        fn route_iface(&self, net: Net) -> Option<String> {
            Some(self.table.get(&net).cloned().unwrap_or_else(|| "en0".into()))
        }
        fn add_route(&mut self, net: Net, iface: &str) {
            // Like the kernel, refuse to replace an existing route.
            if !self.read_only {
                self.table.entry(net).or_insert_with(|| iface.into());
            }
        }
        fn delete_route(&mut self, net: Net, iface: &str) {
            if !self.read_only && self.table.get(&net).is_some_and(|i| i == iface) {
                self.table.remove(&net);
            }
        }
        fn resolve(&self, host: &str) -> Vec<IpAddr> {
            self.dns.get(host).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn split_sweeps_broad_routes_and_adds_only_configured_ones() {
        let mut os = Fake::connected();
        os.dns.insert("nas.home.example", vec!["203.0.113.7".parse().unwrap()]);
        // The LAN the machine sits on overlaps a configured route.
        os.table.insert(net("192.168.50.0/24"), "en0".into());
        let config = parse_config("192.168.1.0/24\n192.168.50.0/24\nnas.home.example\n");
        let mut applied = Applied::default();

        let status = reconcile(&mut os, &config, true, &mut applied);

        assert_eq!(status.state, State::Split);
        assert_eq!(os.on_tunnel(), ["192.168.1.0/24", "203.0.113.7/32", "fd37::/64"]);
        assert_eq!(status.routes, ["192.168.1.0/24", "203.0.113.7/32", "fd37::/64"]);
        assert_eq!(status.failed, ["192.168.50.0/24"]);
        assert_eq!(os.table[&net("192.168.50.0/24")], "en0");

        // A second pass changes nothing.
        let table = os.table.clone();
        assert_eq!(reconcile(&mut os, &config, true, &mut applied).routes, status.routes);
        assert_eq!(os.table, table);
    }

    #[test]
    fn changes_the_table_rejects_are_reported() {
        let mut os = Fake {
            read_only: true,
            ..Fake::connected()
        };
        let status = reconcile(
            &mut os,
            &parse_config("192.168.1.0/24\n"),
            true,
            &mut Applied::default(),
        );
        assert_eq!(
            status.failed,
            ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "192.168.1.0/24"]
        );
        assert_eq!(status.routes, ["fd37::/64"]);
    }

    #[test]
    fn removed_entries_are_pruned_unless_a_name_fails_to_resolve() {
        let mut os = Fake::connected();
        os.dns.insert("nas.home.example", vec!["203.0.113.7".parse().unwrap()]);
        let mut applied = Applied::default();
        reconcile(
            &mut os,
            &parse_config("192.168.1.0/24\nnas.home.example\n"),
            true,
            &mut applied,
        );

        os.dns.clear();
        let status = reconcile(&mut os, &parse_config("nas.home.example\n"), true, &mut applied);
        assert_eq!(status.failed, ["nas.home.example"]);
        assert_eq!(os.on_tunnel(), ["192.168.1.0/24", "203.0.113.7/32", "fd37::/64"]);

        reconcile(&mut os, &parse_config(""), true, &mut applied);
        assert_eq!(os.on_tunnel(), ["fd37::/64"]);
    }

    #[test]
    fn off_restores_the_full_tunnel() {
        let mut os = Fake::connected();
        let before = os.table.clone();
        let config = parse_config("192.168.1.0/24\n");
        let mut applied = Applied::default();
        reconcile(&mut os, &config, true, &mut applied);
        assert_ne!(os.table, before);

        let status = reconcile(&mut os, &config, false, &mut applied);

        assert_eq!(status.state, State::Full);
        assert_eq!(os.table, before);
    }

    #[test]
    fn other_vpns_and_a_missing_tunnel_are_left_alone() {
        let mut os = Fake::default();
        os.table.extend(broad().map(|b| (b, "utun3".to_string())));
        let before = os.table.clone();
        let mut applied = Applied::default();

        // Not connected: nothing is touched.
        let status = reconcile(&mut os, &parse_config("192.168.1.0/24\n"), true, &mut applied);
        assert_eq!(status.state, State::Disconnected);
        assert_eq!(os.table, before);

        // Connected, but another VPN owns the broad routes: they stay.
        os.tunnel = Some(Tunnel {
            iface: "utun8".into(),
            nets: vec![],
        });
        reconcile(&mut os, &parse_config("192.168.1.0/24\n"), true, &mut applied);
        assert!(broad().all(|b| os.table[&b] == "utun3"));
        assert_eq!(os.on_tunnel(), ["192.168.1.0/24"]);

        // Nor can `off` take them over; it says so instead of claiming success.
        let status = reconcile(&mut os, &parse_config(""), false, &mut applied);
        assert_eq!(status.failed.len(), 4);
        assert!(broad().all(|b| os.table[&b] == "utun3"));
    }
}
