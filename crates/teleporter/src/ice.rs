//! NAT traversal: gather candidates and run STUN connectivity checks on one UDP socket.
//!
//! Wire behaviour follows telepy's native ICE agent: checks are Binding requests whose
//! MESSAGE-INTEGRITY (RFC 5389 short-term credentials) is keyed by the session secret.
//! There is no TURN relay support, so a console reachable only through a relay fails here.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::{Candidate, ConnectResult, IceServer, Result};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC: u32 = 0x2112_A442;
const ATTR_MAPPED: u16 = 0x0001;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_INTEGRITY: u16 = 0x0008;
const HEADER: usize = 20;
const TXID_LEN: usize = 12;

const STUN_TIMEOUT: Duration = Duration::from_secs(2);
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const READ_SLICE: Duration = Duration::from_millis(250);
const DRAIN_PER_ROUND: usize = 32;

type TxId = [u8; TXID_LEN];

fn hmac_sha1(key: &[u8], data: &[u8]) -> Hmac<Sha1> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac
}

fn header(msg_type: u16, len: usize, txid: &TxId) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER);
    h.extend_from_slice(&msg_type.to_be_bytes());
    h.extend_from_slice(&(len as u16).to_be_bytes());
    h.extend_from_slice(&MAGIC.to_be_bytes());
    h.extend_from_slice(txid);
    h
}

fn new_txid() -> Result<TxId> {
    let mut t = [0u8; TXID_LEN];
    getrandom::fill(&mut t)?;
    Ok(t)
}

/// A plain Binding request, for reflexive discovery.
fn binding_request(txid: &TxId) -> Vec<u8> {
    header(BINDING_REQUEST, 0, txid)
}

/// Header + attrs + MESSAGE-INTEGRITY; the header length already counts the 24-byte attribute.
fn with_integrity(msg_type: u16, txid: &TxId, attrs: &[u8], key: &[u8]) -> Vec<u8> {
    let mut msg = header(msg_type, attrs.len() + 24, txid);
    msg.extend_from_slice(attrs);
    let digest = hmac_sha1(key, &msg).finalize().into_bytes();
    msg.extend_from_slice(&ATTR_INTEGRITY.to_be_bytes());
    msg.extend_from_slice(&20u16.to_be_bytes());
    msg.extend_from_slice(&digest);
    msg
}

fn xor_mapped_attr(addr: SocketAddrV4) -> Vec<u8> {
    let mut a = Vec::with_capacity(12);
    a.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
    a.extend_from_slice(&8u16.to_be_bytes());
    a.extend_from_slice(&[0, 1]);
    a.extend_from_slice(&(addr.port() ^ (MAGIC >> 16) as u16).to_be_bytes());
    a.extend_from_slice(&(addr.ip().to_bits() ^ MAGIC).to_be_bytes());
    a
}

/// The `(offset, type, value)` of each attribute; stops at the first truncated one.
fn attributes(msg: &[u8]) -> Vec<(usize, u16, &[u8])> {
    let mut out = Vec::new();
    if msg.len() < HEADER {
        return out;
    }
    let end = (HEADER + usize::from(u16::from_be_bytes([msg[2], msg[3]]))).min(msg.len());
    let mut i = HEADER;
    while i + 4 <= end {
        let kind = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let len = usize::from(u16::from_be_bytes([msg[i + 2], msg[i + 3]]));
        if i + 4 + len > end {
            break;
        }
        out.push((i, kind, &msg[i + 4..i + 4 + len]));
        i += 4 + len + (4 - len % 4) % 4;
    }
    out
}

/// The first XOR-MAPPED-ADDRESS (or legacy MAPPED-ADDRESS) IPv4 endpoint.
fn parse_mapped(msg: &[u8]) -> Option<SocketAddrV4> {
    let (_, kind, v) = attributes(msg)
        .into_iter()
        .find(|&(_, k, v)| (k == ATTR_XOR_MAPPED || k == ATTR_MAPPED) && v.len() >= 8 && v[1] == 1)?;
    let (mut port, mut ip) = (
        u16::from_be_bytes([v[2], v[3]]),
        u32::from_be_bytes([v[4], v[5], v[6], v[7]]),
    );
    if kind == ATTR_XOR_MAPPED {
        port ^= (MAGIC >> 16) as u16;
        ip ^= MAGIC;
    }
    Some(SocketAddrV4::new(Ipv4Addr::from_bits(ip), port))
}

/// The transaction id of a STUN message with the right magic cookie.
fn stun_txid(msg: &[u8]) -> Option<(u16, TxId)> {
    if msg.len() < HEADER || msg[4..8] != MAGIC.to_be_bytes() {
        return None;
    }
    Some((u16::from_be_bytes([msg[0], msg[1]]), msg[8..HEADER].try_into().ok()?))
}

/// Checks MESSAGE-INTEGRITY over the bytes before it, with the length field rewritten to end there.
fn verify_integrity(msg: &[u8], key: &[u8]) -> bool {
    let Some(&(at, _, mac)) = attributes(msg)
        .iter()
        .find(|&&(_, k, v)| k == ATTR_INTEGRITY && v.len() == 20)
    else {
        return false;
    };
    let mut covered = msg[..at].to_vec();
    covered[2..4].copy_from_slice(&((at - HEADER + 24) as u16).to_be_bytes());
    hmac_sha1(key, &covered).verify_slice(mac).is_ok()
}

/// The first `stun:host[:port]` server, resolved to IPv4.
fn stun_addrs(servers: &[IceServer]) -> impl Iterator<Item = SocketAddr> + '_ {
    servers.iter().flat_map(|s| &s.urls).filter_map(|url| {
        let hostport = url.strip_prefix("stun:")?.split('?').next()?;
        let target = if hostport.contains(':') {
            hostport.to_string()
        } else {
            format!("{hostport}:3478")
        };
        target.to_socket_addrs().ok()?.find(SocketAddr::is_ipv4)
    })
}

/// One Binding request to `server`; the reflexive address, or None if it did not answer in time.
fn stun_query(socket: &UdpSocket, server: SocketAddr) -> Option<SocketAddrV4> {
    let txid = new_txid().ok()?;
    socket.send_to(&binding_request(&txid), server).ok()?;
    let deadline = Instant::now() + STUN_TIMEOUT;
    let mut buf = [0u8; 2048];
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())?
            .max(Duration::from_millis(1));
        socket.set_read_timeout(Some(left)).ok()?;
        let (n, _) = socket.recv_from(&mut buf).ok()?;
        let reply = &buf[..n];
        if stun_txid(reply).is_some_and(|(_, t)| t == txid) {
            return parse_mapped(reply);
        }
    }
}

/// The address the default route uses; connecting a UDP socket sends nothing.
fn default_route_ipv4() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("8.8.8.8:80").ok()?;
    match probe.local_addr().ok()? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() && !a.ip().is_loopback() => Some(*a.ip()),
        _ => None,
    }
}

/// Local candidates for `socket`: the default-route host address and the STUN-reflexive one.
pub fn gather(socket: &UdpSocket, servers: &[IceServer]) -> Result<Vec<Candidate>> {
    let port = socket.local_addr()?.port();
    let mut out = Vec::new();
    if let Some(ip) = default_route_ipv4() {
        out.push(Candidate {
            kind: "iface".into(),
            addr: format!("{ip}:{port}"),
        });
    }
    let reflex = stun_addrs(servers).find_map(|server| stun_query(socket, server));
    socket.set_read_timeout(None)?;
    if let Some(addr) = reflex {
        out.push(Candidate {
            kind: "reflex".into(),
            addr: addr.to_string(),
        });
    }
    if out.is_empty() {
        return Err("no local candidates: no default route and no STUN answer".into());
    }
    Ok(out)
}

/// Runs connectivity checks until both directions work; returns the console's active source.
pub fn traverse(socket: &UdpSocket, result: &ConnectResult, stun_session_secret: &str) -> Result<SocketAddr> {
    let key = stun_session_secret.as_bytes();
    // Reflex candidates first; relay and IPv6 candidates are not usable here.
    let mut remotes: Vec<(bool, SocketAddrV4)> = result
        .remote_candidates
        .iter()
        .filter(|c| c.kind != "turn")
        .filter_map(|c| Some((c.kind != "reflex", c.addr.parse().ok()?)))
        .collect();
    remotes.sort_by_key(|&(not_reflex, _)| not_reflex);

    socket.set_read_timeout(Some(READ_SLICE))?;
    let outcome = run_checks(socket, &remotes, key);
    socket.set_read_timeout(None)?;
    outcome
}

fn run_checks(socket: &UdpSocket, remotes: &[(bool, SocketAddrV4)], key: &[u8]) -> Result<SocketAddr> {
    let deadline = Instant::now() + CHECK_TIMEOUT;
    let mut sent = HashSet::new();
    let mut confirmed = false;
    // Where the console's own checks come from, and whether it proved it knows the secret.
    let mut console_src: Option<(SocketAddr, bool)> = None;
    let mut answered = HashSet::new();
    let mut buf = [0u8; 2048];

    while Instant::now() < deadline {
        let targets = remotes
            .iter()
            .map(|&(_, a)| SocketAddr::V4(a))
            .chain(console_src.map(|(src, _)| src));
        for target in targets {
            let txid = new_txid()?;
            sent.insert(txid);
            let _ = socket.send_to(&with_integrity(BINDING_REQUEST, &txid, &[], key), target);
        }
        for _ in 0..DRAIN_PER_ROUND {
            let Ok((n, SocketAddr::V4(src))) = socket.recv_from(&mut buf) else {
                break;
            };
            let msg = &buf[..n];
            match stun_txid(msg) {
                Some((BINDING_REQUEST, txid)) => {
                    let reply = with_integrity(BINDING_SUCCESS, &txid, &xor_mapped_attr(src), key);
                    let _ = socket.send_to(&reply, src);
                    let authentic = verify_integrity(msg, key);
                    // An unsigned request never displaces a source that signed.
                    if authentic || !console_src.is_some_and(|(_, signed)| signed) {
                        console_src = Some((src.into(), authentic));
                    }
                }
                Some((BINDING_SUCCESS, txid)) if sent.contains(&txid) => {
                    confirmed = true;
                    answered.insert(SocketAddr::V4(src));
                }
                _ => {}
            }
        }
        // The reference nominates any source once a check of ours was answered. Here the source
        // must have signed its request, or have answered a request of ours itself, so a stray
        // packet cannot choose the endpoint.
        if let Some((src, signed)) = console_src
            && ((signed && confirmed) || answered.contains(&src))
        {
            return Ok(src);
        }
    }
    Err("no remote candidate answered connectivity checks".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const KEY: &[u8] = b"session-secret-ascii";

    fn ice_server(urls: Vec<String>) -> IceServer {
        IceServer {
            urls,
            username: String::new(),
            credential: String::new(),
        }
    }

    // RFC 5769 section 2.1 sample request, credentials from the same section.
    const RFC5769_PASSWORD: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";
    const RFC5769_TXID: TxId = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];
    const RFC5769_ATTRS: [u8; 56] = [
        0x80, 0x22, 0x00, 0x10, b'S', b'T', b'U', b'N', b' ', b't', b'e', b's', b't', b' ', b'c', b'l', b'i', b'e',
        b'n', b't', 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1,
        0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, b'e', b'v', b't', b'j', b':', b'h', b'6', b'v', b'Y', b' ',
        b' ', b' ',
    ];
    const RFC5769_MI: [u8; 20] = [
        0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5,
        0x71, 0xa2,
    ];
    const RFC5769_FINGERPRINT: [u8; 8] = [0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf];

    /// The full sample request: attributes, MESSAGE-INTEGRITY, then FINGERPRINT.
    fn rfc5769_request() -> Vec<u8> {
        let mut msg = header(BINDING_REQUEST, 0x58, &RFC5769_TXID);
        msg.extend_from_slice(&RFC5769_ATTRS);
        msg.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
        msg.extend_from_slice(&RFC5769_MI);
        msg.extend_from_slice(&RFC5769_FINGERPRINT);
        msg
    }

    #[test]
    fn rfc5769_integrity_vector() {
        let msg = rfc5769_request();
        assert_eq!(msg.len(), HEADER + 0x58);
        assert!(verify_integrity(&msg, RFC5769_PASSWORD));
        assert!(!verify_integrity(&msg, KEY));

        let built = with_integrity(BINDING_REQUEST, &RFC5769_TXID, &RFC5769_ATTRS, RFC5769_PASSWORD);
        assert_eq!(built[HEADER + RFC5769_ATTRS.len() + 4..], RFC5769_MI);
        assert!(verify_integrity(&built, RFC5769_PASSWORD));
    }

    #[test]
    fn integrity_covers_every_byte() {
        let txid = [7u8; TXID_LEN];
        let msg = with_integrity(
            BINDING_SUCCESS,
            &txid,
            &xor_mapped_attr("203.0.113.7:4242".parse().unwrap()),
            KEY,
        );
        assert!(verify_integrity(&msg, KEY));
        assert!(!verify_integrity(&msg, b"other"));
        // Bytes 2..4 (the length) are rewritten before hashing, as RFC 5389 requires.
        for i in (0..2).chain(4..msg.len()) {
            let mut bad = msg.clone();
            bad[i] ^= 1;
            assert!(!verify_integrity(&bad, KEY), "flip at {i}");
        }
        assert!(!verify_integrity(&binding_request(&txid), KEY));
    }

    #[test]
    fn xor_mapped_roundtrip_and_is_obfuscated() {
        let addr: SocketAddrV4 = "198.51.100.23:51820".parse().unwrap();
        let attr = xor_mapped_attr(addr);
        assert_eq!(u16::from_be_bytes([attr[6], attr[7]]), 51820 ^ 0x2112);
        let mut msg = header(BINDING_SUCCESS, attr.len(), &[0; TXID_LEN]);
        msg.extend_from_slice(&attr);
        assert_eq!(parse_mapped(&msg), Some(addr));
    }

    #[test]
    fn parses_legacy_mapped_address_after_padded_attribute() {
        let mut attrs = vec![0x80, 0x22, 0x00, 0x02, 0xaa, 0xbb, 0, 0];
        attrs.extend_from_slice(&[0x00, 0x01, 0x00, 0x08, 0, 1, 0x0d, 0x96, 192, 0, 2, 55]);
        let mut msg = header(BINDING_SUCCESS, attrs.len(), &[0; TXID_LEN]);
        msg.extend_from_slice(&attrs);
        assert_eq!(parse_mapped(&msg), Some("192.0.2.55:3478".parse().unwrap()));
    }

    #[test]
    fn malformed_packets_are_ignored() {
        assert_eq!(parse_mapped(&[]), None);
        assert_eq!(parse_mapped(&[0, 1, 0, 0]), None);
        assert_eq!(parse_mapped(&binding_request(&[0; TXID_LEN])), None);
        // Attribute length points past the end of the message, and past the declared length.
        let mut msg = header(BINDING_SUCCESS, 12, &[0; TXID_LEN]);
        msg.extend_from_slice(&[0x00, 0x20, 0xff, 0xff, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_mapped(&msg), None);
        assert!(!verify_integrity(&msg, KEY));
        // Declared length longer than the datagram.
        let mut short = header(BINDING_SUCCESS, 400, &[0; TXID_LEN]);
        short.extend_from_slice(&[0x00, 0x08, 0x00, 0x14, 1, 2, 3]);
        assert!(!verify_integrity(&short, KEY));
        // Every truncation of a valid message must be handled without panicking.
        let ok = with_integrity(BINDING_REQUEST, &[1; TXID_LEN], &[], KEY);
        for n in 0..ok.len() {
            assert!(!verify_integrity(&ok[..n], KEY));
            let _ = stun_txid(&ok[..n]);
        }
        // Wrong magic cookie.
        let mut bad = ok.clone();
        bad[4] ^= 1;
        assert_eq!(stun_txid(&bad), None);
    }

    #[test]
    fn plain_binding_request_is_header_only() {
        let txid = [3u8; TXID_LEN];
        let msg = binding_request(&txid);
        assert_eq!(msg.len(), HEADER);
        assert_eq!(stun_txid(&msg), Some((BINDING_REQUEST, txid)));
        assert_ne!(new_txid().unwrap(), new_txid().unwrap());
    }

    #[test]
    fn stun_urls_default_port_and_skip_other_schemes() {
        let servers = [
            ice_server(vec![
                "turn:127.0.0.9:3478".into(),
                "stun:127.0.0.1?transport=udp".into(),
            ]),
            ice_server(vec!["stun:127.0.0.2:19302".into()]),
        ];
        let got: Vec<String> = stun_addrs(&servers).map(|a| a.to_string()).collect();
        assert_eq!(got, ["127.0.0.1:3478", "127.0.0.2:19302"]);
    }

    #[test]
    fn gather_learns_reflex_from_stun_server() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let (_, txid) = stun_txid(&buf[..n]).unwrap();
            let SocketAddr::V4(from) = from else {
                panic!("ipv4 only")
            };
            let attr = xor_mapped_attr(from);
            let mut reply = header(BINDING_SUCCESS, attr.len(), &txid);
            reply.extend_from_slice(&attr);
            server.send_to(&reply, from).unwrap();
        });
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let servers = [ice_server(vec![format!("stun:{server_addr}")])];
        let got = gather(&socket, &servers).unwrap();
        handle.join().unwrap();
        let reflex = got.iter().find(|c| c.kind == "reflex").unwrap();
        assert_eq!(reflex.addr, socket.local_addr().unwrap().to_string());
        assert_eq!(socket.read_timeout().unwrap(), None);
    }

    /// A console: answers authenticated checks and sends its own at the client.
    fn run_console(console: UdpSocket, client: SocketAddr, key: &'static [u8], stop: Arc<AtomicBool>) {
        console.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let mut buf = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            let own = with_integrity(BINDING_REQUEST, &new_txid().unwrap(), &[], key);
            console.send_to(&own, client).unwrap();
            while let Ok((n, SocketAddr::V4(src))) = console.recv_from(&mut buf) {
                if let Some((BINDING_REQUEST, txid)) = stun_txid(&buf[..n])
                    && verify_integrity(&buf[..n], key)
                {
                    let reply = with_integrity(BINDING_SUCCESS, &txid, &xor_mapped_attr(src), key);
                    console.send_to(&reply, src).unwrap();
                }
            }
        }
    }

    #[test]
    fn traverse_nominates_the_console_over_loopback() {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let console = UdpSocket::bind("127.0.0.1:0").unwrap();
        let console_addr = console.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let client_addr = client.local_addr().unwrap();
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || run_console(console, client_addr, b"s3cret", stop))
        };
        // The unusable candidates must be skipped, not fail the checks.
        let candidate = |kind: &str, addr: &str| Candidate {
            kind: kind.into(),
            addr: addr.into(),
        };
        let result = ConnectResult {
            remote_candidates: vec![
                candidate("turn", "127.0.0.1:9"),
                candidate("iface", "[::1]:9"),
                candidate("reflex", &console_addr.to_string()),
            ],
            ..Default::default()
        };
        let nominated = traverse(&client, &result, "s3cret");
        stop.store(true, Ordering::Relaxed);
        thread.join().unwrap();
        assert_eq!(nominated.unwrap(), console_addr);
        assert_eq!(client.read_timeout().unwrap(), None);
    }

    #[test]
    fn traverse_accepts_an_unsigned_console_that_answers_our_checks() {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let console = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (client_addr, console_addr) = (client.local_addr().unwrap(), console.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                console.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::Relaxed) {
                    console
                        .send_to(&header(BINDING_REQUEST, 0, &new_txid().unwrap()), client_addr)
                        .unwrap();
                    while let Ok((n, src)) = console.recv_from(&mut buf) {
                        if let Some((BINDING_REQUEST, txid)) = stun_txid(&buf[..n]) {
                            console.send_to(&header(BINDING_SUCCESS, 0, &txid), src).unwrap();
                        }
                    }
                }
            })
        };
        let result = ConnectResult {
            remote_candidates: vec![Candidate {
                kind: "reflex".into(),
                addr: console_addr.to_string(),
            }],
            ..Default::default()
        };
        let nominated = traverse(&client, &result, "s3cret");
        stop.store(true, Ordering::Relaxed);
        thread.join().unwrap();
        assert_eq!(nominated.unwrap(), console_addr);
    }

    #[test]
    fn traverse_ignores_a_peer_with_the_wrong_secret() {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let console = UdpSocket::bind("127.0.0.1:0").unwrap();
        let console_addr = console.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let client_addr = client.local_addr().unwrap();
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || run_console(console, client_addr, b"wrong", stop))
        };
        let result = ConnectResult {
            remote_candidates: vec![Candidate {
                kind: "reflex".into(),
                addr: console_addr.to_string(),
            }],
            ..Default::default()
        };
        // Nothing authentic ever arrives, so this takes the full check timeout.
        let nominated = traverse(&client, &result, "s3cret");
        stop.store(true, Ordering::Relaxed);
        thread.join().unwrap();
        assert!(nominated.is_err());
    }
}
