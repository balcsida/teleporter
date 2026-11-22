//! The whole connection, in the order the protocol needs it.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::path::Path;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;

use crate::tunnel::Tunnel;
use crate::{ClientOffer, Console, Entry, Net, Result, cloud, ice, platform, signaling, sso, tunnel};

/// The name the console shows for this client.
const CLIENT_NAME: &str = "teleport-split";
/// NAT traversal does not always succeed first time; the console hands out a new offer per try.
const ATTEMPTS: usize = 4;

pub struct Connection {
    pub tunnel: Tunnel,
    /// Destinations routed through the tunnel.
    pub routes: Vec<String>,
    /// Destinations left alone: they overlap a local network or could not be routed.
    pub skipped: Vec<String>,
}

fn sign_in(dir: &Path) -> Result<(crate::Session, crate::CloudConfig, crate::AwsCredentials)> {
    let mut session = sso::load_session(dir)?.ok_or("not signed in; run: teleport-split login")?;
    if sso::refresh(&mut session)? {
        sso::save_session(dir, &session)?;
    }
    let cloud = cloud::fetch_config()?;
    let creds = sso::aws_credentials(&session, &cloud)?;
    Ok((session, cloud, creds))
}

/// The consoles of the signed-in account.
pub fn consoles(dir: &Path) -> Result<Vec<Console>> {
    let (_, cloud, creds) = sign_in(dir)?;
    cloud::consoles(&cloud, &creds)
}

fn overlaps(a: Net, b: Net) -> bool {
    let prefix = a.prefix.min(b.prefix);
    a.addr.is_ipv4() == b.addr.is_ipv4() && Net::new(a.addr, prefix) == Net::new(b.addr, prefix)
}

/// RFC 1918 and the carrier-grade NAT range: what a LAN behind a console can be.
fn is_private(ip: Ipv4Addr) -> bool {
    ip.is_private() || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
}

/// Which destinations to route through the tunnel, and which to skip.
///
/// The console's `subnets` come from the cloud and `extra` may come from DNS,
/// so neither is trusted to be harmless: a route is only added if it cannot
/// take over the machine's own networking.
fn plan_routes(subnets: &[Net], extra: &[Net], local: &[Net], endpoint: IpAddr) -> (Vec<Net>, Vec<Net>) {
    let safe = |net: &Net, from_console: bool| {
        let IpAddr::V4(ip) = net.addr else {
            return false; // the tunnel only carries IPv4 beyond its own link
        };
        net.prefix >= 8
            && !(ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_unspecified() || ip.is_broadcast())
            // A console only ever has private LANs; anything else is the user's explicit choice.
            && (!from_console || is_private(ip))
            // Routing the LAN this machine sits on would cut it off from that LAN...
            && !local.iter().any(|l| overlaps(*net, *l))
            // ...and routing the tunnel's own transport into the tunnel would loop it.
            && !overlaps(*net, Net::host(endpoint))
    };
    let mut all: Vec<(Net, bool)> = subnets
        .iter()
        .map(|n| (*n, safe(n, true)))
        .chain(extra.iter().map(|n| (*n, safe(n, false))))
        .collect();
    // Listed twice, the user's own entry decides.
    all.sort_by_key(|(net, ok)| (*net, !*ok));
    all.dedup_by_key(|(net, _)| *net);
    let (routed, skipped): (Vec<_>, Vec<_>) = all.into_iter().partition(|(_, ok)| *ok);
    (
        routed.into_iter().map(|(n, _)| n).collect(),
        skipped.into_iter().map(|(n, _)| n).collect(),
    )
}

/// Connect to the console called `name` (or with that id) and route its LANs,
/// plus the `extra` entries, through the tunnel. Needs root.
pub fn connect(dir: &Path, name: &str, extra: &[Entry]) -> Result<Connection> {
    let (session, cloud, creds) = sign_in(dir)?;
    let consoles = cloud::consoles(&cloud, &creds)?;
    let console = consoles
        .iter()
        .find(|c| c.id == name || c.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            let names: Vec<&str> = consoles.iter().map(|c| c.name.as_str()).collect();
            format!("no console called {name:?}; this account has: {}", names.join(", "))
        })?;
    if !console.online {
        return Err(format!("{} is offline", console.name).into());
    }

    let mut last_error = None;
    for _ in 0..ATTEMPTS {
        let grant = signaling::access_request(&cloud, &creds, &console.id, &session.client_id, CLIENT_NAME)?;
        let ice_servers = cloud::ice_configuration(&cloud, &creds, &grant)?;
        // A fresh socket per attempt: the console probes the port it was told about.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let candidates = ice::gather(&socket, &ice_servers)?;
        let (private_key, wg_public_key) = tunnel::keypair();
        let mut secret = [0u8; 16];
        getrandom::fill(&mut secret)?;
        let stun_session_secret = BASE64_STANDARD.encode(secret);
        let offer = ClientOffer {
            wg_public_key,
            candidates,
            ice_servers,
            stun_session_secret,
        };
        // The console starts probing as soon as it has the offer, so nothing may sit between these two.
        let result = cloud::connect(&cloud, &creds, &grant, CLIENT_NAME, &offer)?;
        let endpoint = match ice::traverse(&socket, &result, &offer.stun_session_secret) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        let local = platform::local_nets();
        // The address the console assigns goes onto an interface, so it must not shadow anything real.
        let client_ip = result.client_ip.parse::<Ipv4Addr>().ok().filter(|ip| is_private(*ip));
        if !client_ip.is_some_and(|ip| !local.iter().any(|l| overlaps(Net::host(ip.into()), *l))) {
            return Err("the console assigned a tunnel address that is not usable here".into());
        }
        let tunnel = Tunnel::start(socket, endpoint, private_key, &offer.stun_session_secret, &result)?;

        let mut extra_nets = Vec::new();
        let mut skipped = Vec::new();
        for entry in extra {
            match entry {
                Entry::Net(net) => extra_nets.push(*net),
                // shortcut: names are resolved once per connection, re-resolve on a timer if they move.
                Entry::Host(host) => match (host.as_str(), 0).to_socket_addrs() {
                    Ok(addrs) => extra_nets.extend(addrs.map(|a| Net::host(a.ip()))),
                    Err(_) => skipped.push(host.clone()),
                },
            }
        }
        let (wanted, unsafe_nets) = plan_routes(&console.subnets, &extra_nets, &local, endpoint.ip());
        skipped.extend(unsafe_nets.iter().map(Net::to_string));
        let mut routes = Vec::new();
        for net in wanted {
            if platform::add_route(net, tunnel.iface()) {
                routes.push(net.to_string());
            } else {
                skipped.push(net.to_string());
            }
        }
        return Ok(Connection {
            tunnel,
            routes,
            skipped,
        });
    }
    Err(last_error.unwrap_or_else(|| "NAT traversal failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_harmless_routes_are_planned() {
        let nets = |s: &[&str]| s.iter().map(|n| n.parse().unwrap()).collect::<Vec<Net>>();
        let subnets = nets(&[
            "192.168.1.0/24",
            "192.168.50.0/24", // the LAN this machine is on
            "10.0.0.0/8",      // contains a local LAN
            "172.16.4.0/22",   // inside a local LAN
            "0.0.0.0/1",       // a hijack of half the internet
            "8.8.8.0/24",      // not a LAN
            "100.64.1.0/24",
        ]);
        let extra = nets(&[
            "8.8.4.0/24",
            "203.0.113.9/32",
            "127.0.0.1/32",
            "224.0.0.0/8",
            "198.51.100.0/24",
            "fd00::/64",
        ]);
        let local = nets(&["192.168.50.0/24", "10.9.0.0/16", "172.16.0.0/12"]);
        let endpoint = "198.51.100.7".parse().unwrap();

        let (routed, skipped) = plan_routes(&subnets, &extra, &local, endpoint);

        assert_eq!(
            routed,
            nets(&["8.8.4.0/24", "100.64.1.0/24", "192.168.1.0/24", "203.0.113.9/32"])
        );
        assert_eq!(skipped.len(), subnets.len() + extra.len() - routed.len());
    }
}
