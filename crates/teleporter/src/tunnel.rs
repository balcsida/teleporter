//! WireGuard over the socket ICE punched, pumped to a TUN device, plus the in-tunnel
//! `udp_echo` heartbeat that keeps the console's lease open.
//!
//! The protocol knowledge comes from telepy (docs/wireguard.md, docs/keepalive.md): the client is
//! always the initiator, the punched socket is the WireGuard endpoint, and the echo is an
//! authenticated JSON request sent to `udp_echo_addr:udp_echo_port` inside the tunnel every 1.5 s.
//! telepy hand-builds the IPv6/UDP packet; here the OS does it with an ordinary UDP socket bound to
//! the tunnel address, which the on-link prefix of that address routes through the TUN device.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::prelude::*;
use boringtun::noise::{Tunn, TunnResult, errors::WireGuardError};
use boringtun::x25519::{PublicKey, StaticSecret};
use sha2::{Digest, Sha256};
use tun_rs::{DeviceBuilder, InterruptEvent};

use crate::{ConnectResult, Net, Result, platform};

const MTU: u16 = 1380;
const KEEPALIVE_SECS: u16 = 5;
const READY_TIMEOUT: Duration = Duration::from_secs(20);
/// With a 5 s keepalive from each side, this long without anything authenticated means the path is gone.
const SILENCE: Duration = Duration::from_secs(20);
const ECHO_INTERVAL: Duration = Duration::from_millis(1500);
/// Every blocking read wakes at least this often to look at the stop flag.
const TICK: Duration = Duration::from_millis(100);
const BUF: usize = 2048;
/// A tunnel overlay is never wider than this; it keeps a bad `tunnel_mask` from claiming a huge on-link prefix.
const MIN_TUNNEL_PREFIX: u8 = 64;

/// A new WireGuard keypair: (private key bytes, public key in base64 as CONNECT wants it).
pub fn keypair() -> ([u8; 32], String) {
    let mut private = [0u8; 32];
    getrandom::fill(&mut private).expect("the OS has no randomness");
    let public = PublicKey::from(&StaticSecret::from(private));
    (private, BASE64_STANDARD.encode(public.as_bytes()))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// `base64(sha256(secret string))`: the exact CONNECT string is hashed, not its decoded bytes.
fn secret_hash(stun_session_secret: &str) -> String {
    BASE64_STANDARD.encode(Sha256::digest(stun_session_secret.as_bytes()))
}

fn echo_request(hash: &str, req_id: u64) -> Vec<u8> {
    format!(r#"{{"session_secret_hash":"{hash}","req_id":"{req_id}","timeout":3000}}"#).into_bytes()
}

/// The `req_id` of an echo reply (a string, or a number as the Go client also accepts).
fn parse_pong(datagram: &[u8]) -> Option<String> {
    match serde_json::from_slice::<serde_json::Value>(datagram)
        .ok()?
        .get("req_id")?
    {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

struct Echo {
    /// Bound to the tunnel address and connected to the echo endpoint.
    socket: UdpSocket,
    hash: String,
}

/// Everything the threads share. The `Tunn` lock is never held across I/O that can block.
struct Core {
    tunn: Mutex<Tunn>,
    socket: UdpSocket,
    /// Always the punched endpoint, whoever authenticated packets come from (telepy does the same).
    endpoint: SocketAddr,
    stop: AtomicBool,
    dead: AtomicBool,
    /// When something authenticated last arrived.
    last_rx: Mutex<Instant>,
    silence: Duration,
    pongs: AtomicU64,
}

impl Core {
    fn send(&self, datagram: &[u8]) {
        let _ = self.socket.send_to(datagram, self.endpoint);
    }

    /// One datagram from the network. Decrypted inner packets go to `to_tun`. Garbage is dropped.
    fn receive(&self, from: IpAddr, datagram: &[u8], to_tun: &dyn Fn(&[u8])) {
        let mut out = [0u8; BUF];
        let mut input = datagram;
        loop {
            // boringtun: after WriteToNetwork, call again with an empty datagram until Done.
            let result = lock(&self.tunn).decapsulate(Some(from), input, &mut out);
            if !input.is_empty() && !matches!(result, TunnResult::Err(_)) {
                *lock(&self.last_rx) = Instant::now();
            }
            match result {
                TunnResult::WriteToNetwork(p) => {
                    self.send(p);
                    input = &[];
                }
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    to_tun(p);
                    return;
                }
                TunnResult::Done | TunnResult::Err(_) => return,
            }
        }
    }

    /// One inner packet from the OS. Anything above the MTU can only be a bug or an attack: drop it.
    fn send_inner(&self, packet: &[u8]) {
        if packet.is_empty() || packet.len() > usize::from(MTU) {
            return;
        }
        let mut out = [0u8; BUF];
        let result = lock(&self.tunn).encapsulate(packet, &mut out);
        if let TunnResult::WriteToNetwork(p) = result {
            self.send(p);
        }
    }

    fn tick(&self) {
        let mut out = [0u8; BUF];
        let result = lock(&self.tunn).update_timers(&mut out);
        match result {
            TunnResult::WriteToNetwork(p) => self.send(p),
            TunnResult::Err(WireGuardError::ConnectionExpired) => self.dead.store(true, Relaxed),
            _ => {}
        }
    }

    fn alive(&self) -> bool {
        !self.dead.load(Relaxed) && lock(&self.last_rx).elapsed() < self.silence
    }
}

/// Handshake as initiator over `socket`; no device exists yet, so a failure leaves nothing behind.
fn bring_up(
    socket: UdpSocket,
    endpoint: SocketAddr,
    private_key: [u8; 32],
    server_public: [u8; 32],
    ready: Duration,
    silence: Duration,
) -> Result<Arc<Core>> {
    socket.set_read_timeout(Some(TICK))?;
    let mut index = [0u8; 4];
    getrandom::fill(&mut index)?;
    let tunn = Tunn::new(
        StaticSecret::from(private_key),
        PublicKey::from(server_public),
        None,
        Some(KEEPALIVE_SECS),
        u32::from_le_bytes(index) >> 8, // boringtun shifts it left by 8 itself
        None,
    );
    let core = Arc::new(Core {
        tunn: Mutex::new(tunn),
        socket,
        endpoint,
        stop: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        last_rx: Mutex::new(Instant::now()),
        silence,
        pongs: AtomicU64::new(0),
    });

    let deadline = Instant::now() + ready;
    let mut out = [0u8; BUF];
    let first = lock(&core.tunn).format_handshake_initiation(&mut out, false);
    if let TunnResult::WriteToNetwork(p) = first {
        core.send(p);
    }
    let mut buf = [0u8; BUF];
    while lock(&core.tunn).time_since_last_handshake().is_none() {
        if Instant::now() >= deadline || core.dead.load(Relaxed) {
            return Err("WireGuard handshake did not complete".into());
        }
        if let Ok((n, from)) = core.socket.recv_from(&mut buf) {
            core.receive(from.ip(), &buf[..n], &|_| {});
        }
        core.tick(); // retransmits the initiation every 5 s
    }
    *lock(&core.last_rx) = Instant::now();
    Ok(core)
}

/// The three threads. The device side is two plain closures, so tests can use channels.
struct Pump {
    core: Arc<Core>,
    threads: Vec<JoinHandle<()>>,
}

impl Pump {
    /// `read_tun` must return an `Interrupted`/`TimedOut` error now and then, or when `stop` is set
    /// and the caller wakes it; any other error marks the tunnel dead.
    fn spawn(
        core: Arc<Core>,
        mut read_tun: impl FnMut(&mut [u8]) -> io::Result<usize> + Send + 'static,
        write_tun: impl Fn(&[u8]) + Send + 'static,
        echo: Option<Echo>,
    ) -> Pump {
        let mut threads = Vec::new();

        let c = core.clone();
        threads.push(thread::spawn(move || {
            let mut buf = [0u8; BUF];
            while !c.stop.load(Relaxed) {
                match c.socket.recv_from(&mut buf) {
                    Ok((n, from)) => c.receive(from.ip(), &buf[..n], &write_tun),
                    Err(e) if transient(&e) => {}
                    Err(_) => thread::sleep(TICK), // e.g. a Windows ICMP reset; do not spin
                }
            }
        }));

        let c = core.clone();
        threads.push(thread::spawn(move || {
            let mut buf = [0u8; BUF];
            while !c.stop.load(Relaxed) {
                match read_tun(&mut buf) {
                    Ok(n) => c.send_inner(&buf[..n]),
                    Err(e) if transient(&e) => {}
                    Err(_) => {
                        c.dead.store(true, Relaxed);
                        return;
                    }
                }
            }
        }));

        let c = core.clone();
        threads.push(thread::spawn(move || {
            let mut next_echo = Instant::now();
            let mut req_id = 0u64;
            let mut buf = [0u8; BUF];
            while !c.stop.load(Relaxed) {
                c.tick();
                let Some(echo) = &echo else {
                    thread::sleep(TICK);
                    continue;
                };
                if Instant::now() >= next_echo {
                    let _ = echo.socket.send(&echo_request(&echo.hash, req_id));
                    req_id += 1;
                    next_echo = Instant::now() + ECHO_INTERVAL;
                }
                // The read timeout doubles as this loop's tick.
                if let Ok(n) = echo.socket.recv(&mut buf)
                    && parse_pong(&buf[..n]).is_some()
                {
                    c.pongs.fetch_add(1, Relaxed);
                }
            }
        }));

        Pump { core, threads }
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.core.stop.store(true, Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// The client's tunnel IPv6 address, the echo endpoint and the prefix length, when the console gave an echo.
type EchoPlan = (Ipv6Addr, Ipv6Addr, u8);

fn echo_plan(result: &ConnectResult) -> Result<Option<EchoPlan>> {
    if result.udp_echo_addr.is_empty() || result.udp_echo_port == 0 || result.tunnel_addr.is_empty() {
        return Ok(None);
    }
    let me: Ipv6Addr = result
        .tunnel_addr
        .parse()
        .map_err(|_| "tunnel_addr is not an IPv6 address")?;
    let peer: Ipv6Addr = result
        .udp_echo_addr
        .parse()
        .map_err(|_| "udp_echo_addr is not an IPv6 address")?;
    // The address goes onto an interface: only a unique-local one cannot shadow a real network.
    if me.octets()[0] & 0xfe != 0xfc {
        return Err("tunnel_addr is not a unique-local address".into());
    }
    let prefix = result.tunnel_mask;
    if !(MIN_TUNNEL_PREFIX..=128).contains(&prefix) {
        return Err(format!("tunnel_mask /{prefix} is not usable").into());
    }
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    if me.to_bits() & mask != peer.to_bits() & mask {
        return Err("the udp_echo address is not on the tunnel's on-link prefix".into());
    }
    Ok(Some((me, peer, prefix)))
}

/// A running WireGuard tunnel pumped to a TUN device.
pub struct Tunnel {
    pump: Pump,
    iface: String,
    event: Arc<InterruptEvent>,
}

impl Tunnel {
    /// Bring WireGuard up over `socket` (the socket ICE punched, peer at `endpoint`),
    /// wait for the first handshake (reference timeout), then create and address the
    /// TUN device from `result` and start pumping. Needs root for the device.
    ///
    /// `stun_session_secret` is the string sent in CONNECT; the echo is authenticated with its hash.
    ///
    /// The device gets `client_ip`/32 (point-to-point to itself, as telepy's macOS `ifconfig ip ip`)
    /// and, when the console provides an echo, `tunnel_addr`/`tunnel_mask`; the OS's connected
    /// route for that prefix is the only route this adds. The caller routes everything else.
    pub fn start(
        socket: UdpSocket,
        endpoint: SocketAddr,
        private_key: [u8; 32],
        stun_session_secret: &str,
        result: &ConnectResult,
    ) -> Result<Tunnel> {
        let server_public: [u8; 32] = BASE64_STANDARD
            .decode(&result.server_wg_public_key)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or("the console's WireGuard public key is not 32 bytes of base64")?;
        let client_ip: Ipv4Addr = result
            .client_ip
            .parse()
            .map_err(|_| "client_ip is not an IPv4 address")?;
        let plan = echo_plan(result)?;

        let core = bring_up(socket, endpoint, private_key, server_public, READY_TIMEOUT, SILENCE)?;

        // The device and everything below is not exercised without root; keep it literal.
        let mut builder = DeviceBuilder::new().mtu(MTU).ipv4(client_ip, 32u8, None);
        if let Some((me, _, prefix)) = plan {
            builder = builder.ipv6(me, prefix);
        }
        #[cfg(target_os = "macos")]
        let builder = builder.with(|o| {
            o.associate_route(false); // routes are the caller's
        });
        let dev = Arc::new(builder.build_sync()?);
        let iface = dev.name()?;
        if let Some(net) = plan.and_then(|(me, _, prefix)| Net::new(me.into(), prefix)) {
            // The echo needs the tunnel's link routed; macOS does not promise that for a utun address.
            platform::add_route(net, &iface);
        }
        let echo = match plan {
            Some((me, peer, _)) => {
                // A new IPv6 address can be tentative for a moment, and binding to it fails until it is not.
                let mut bound = UdpSocket::bind((me, 0));
                for _ in 0..30 {
                    if bound.is_ok() {
                        break;
                    }
                    thread::sleep(TICK);
                    bound = UdpSocket::bind((me, 0));
                }
                let socket = bound?;
                socket.connect((peer, result.udp_echo_port))?;
                socket.set_read_timeout(Some(TICK))?;
                Some(Echo {
                    socket,
                    hash: secret_hash(stun_session_secret),
                })
            }
            None => None,
        };

        let event = Arc::new(InterruptEvent::new()?);
        let (reader, writer, wake) = (dev.clone(), dev, event.clone());
        let pump = Pump::spawn(
            core,
            move |buf| reader.recv_intr(buf, &wake),
            move |packet| {
                let _ = writer.send(packet);
            },
            echo,
        );
        Ok(Tunnel { pump, iface, event })
    }

    /// The OS name of the TUN interface, e.g. "utun7". The caller adds routes to it.
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// False once the tunnel is dead (the session expired, or nothing authenticated arrived for
    /// too long). The caller then drops it and reconnects.
    pub fn alive(&self) -> bool {
        self.pump.core.alive()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Wakes the device read; the fields drop afterwards: the pump joins its threads, which
        // release the device.
        let _ = self.event.trigger();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 192, 168, 1, 1];
        p.extend_from_slice(payload);
        let len = (p.len() as u16).to_be_bytes();
        p[2..4].copy_from_slice(&len);
        p
    }

    /// A responder-side peer standing in for the console, on its own UDP socket.
    fn spawn_console(
        socket: UdpSocket,
        key: [u8; 32],
        client_public: [u8; 32],
        stop: Arc<AtomicBool>,
        got: mpsc::Sender<Vec<u8>>,
        to_send: mpsc::Receiver<Vec<u8>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            socket.set_read_timeout(Some(TICK)).unwrap();
            let mut tunn = Tunn::new(
                StaticSecret::from(key),
                PublicKey::from(client_public),
                None,
                Some(1),
                7,
                None,
            );
            let (mut peer, mut buf, mut out) = (None, [0u8; BUF], [0u8; BUF]);
            while !stop.load(Relaxed) {
                if let Some(p) = peer {
                    while let Ok(packet) = to_send.try_recv() {
                        if let TunnResult::WriteToNetwork(d) = tunn.encapsulate(&packet, &mut out) {
                            socket.send_to(d, p).unwrap();
                        }
                    }
                    if let TunnResult::WriteToNetwork(d) = tunn.update_timers(&mut out) {
                        socket.send_to(d, p).unwrap();
                    }
                }
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                peer = Some(from);
                let mut input = &buf[..n];
                loop {
                    match tunn.decapsulate(Some(from.ip()), input, &mut out) {
                        TunnResult::WriteToNetwork(d) => {
                            socket.send_to(d, from).unwrap();
                            input = &[];
                        }
                        TunnResult::WriteToTunnelV4(d, _) => {
                            got.send(d.to_vec()).unwrap();
                            break;
                        }
                        _ => break,
                    }
                }
            }
        })
    }

    #[test]
    fn loopback_handshake_data_echo_and_silence() {
        let (client_key, client_public_b64) = keypair();
        let client_public: [u8; 32] = BASE64_STANDARD.decode(client_public_b64).unwrap().try_into().unwrap();
        let (console_key, console_public_b64) = keypair();
        let console_public: [u8; 32] = BASE64_STANDARD.decode(console_public_b64).unwrap().try_into().unwrap();

        let console_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let console_addr = console_socket.local_addr().unwrap();
        let (stop_console, (got_tx, got_rx), (send_tx, send_rx)) =
            (Arc::new(AtomicBool::new(false)), mpsc::channel(), mpsc::channel());
        let console = spawn_console(
            console_socket,
            console_key,
            client_public,
            stop_console.clone(),
            got_tx,
            send_rx,
        );

        // A fake echo service on loopback: replies to requests carrying the right token.
        let echo_server = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo_server.set_read_timeout(Some(TICK)).unwrap();
        let echo_addr = echo_server.local_addr().unwrap();
        let stop_echo_flag = Arc::new(AtomicBool::new(false));
        let echo_thread = {
            let stop = stop_echo_flag.clone();
            thread::spawn(move || {
                let mut buf = [0u8; BUF];
                while !stop.load(Relaxed) {
                    let Ok((n, from)) = echo_server.recv_from(&mut buf) else {
                        continue;
                    };
                    let req: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
                    assert_eq!(req["session_secret_hash"], secret_hash("the-secret"));
                    let reply = format!(r#"{{"req_id":"{}"}}"#, req["req_id"].as_str().unwrap());
                    echo_server.send_to(reply.as_bytes(), from).unwrap();
                }
            })
        };
        let echo_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo_socket.connect(echo_addr).unwrap();
        echo_socket.set_read_timeout(Some(TICK)).unwrap();

        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let core = bring_up(
            client_socket,
            console_addr,
            client_key,
            console_public,
            Duration::from_secs(5),
            Duration::from_millis(2500),
        )
        .unwrap();

        let (tun_in_tx, tun_in_rx) = mpsc::channel::<Vec<u8>>();
        let (tun_out_tx, tun_out_rx) = mpsc::channel::<Vec<u8>>();
        let pump = Pump::spawn(
            core,
            move |buf| match tun_in_rx.recv_timeout(TICK) {
                Ok(p) => {
                    buf[..p.len()].copy_from_slice(&p);
                    Ok(p.len())
                }
                Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
                Err(_) => Err(io::ErrorKind::BrokenPipe.into()),
            },
            move |p| tun_out_tx.send(p.to_vec()).unwrap(),
            Some(Echo {
                socket: echo_socket,
                hash: secret_hash("the-secret"),
            }),
        );
        assert!(pump.core.alive());

        // Garbage and oversize input from the network and the OS must not matter.
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(&[4, 0, 0, 0, 1], pump.core.socket.local_addr().unwrap())
            .unwrap();
        tun_in_tx.send(vec![0x45; usize::from(MTU) + 1]).unwrap();

        let up = ipv4_packet(b"client to console");
        tun_in_tx.send(up.clone()).unwrap();
        assert_eq!(got_rx.recv_timeout(Duration::from_secs(5)).unwrap(), up);

        let down = ipv4_packet(b"console to client");
        send_tx.send(down.clone()).unwrap();
        assert_eq!(tun_out_rx.recv_timeout(Duration::from_secs(5)).unwrap(), down);

        let t = Instant::now();
        while pump.core.pongs.load(Relaxed) == 0 {
            assert!(t.elapsed() < Duration::from_secs(5), "no echo reply");
            thread::sleep(TICK);
        }
        assert!(pump.core.alive());

        stop_console.store(true, Relaxed);
        console.join().unwrap();
        let t = Instant::now();
        while pump.core.alive() {
            assert!(t.elapsed() < Duration::from_secs(6), "still alive after silence");
            thread::sleep(TICK);
        }

        // Dropping must stop every thread promptly even though the device read is a channel wait.
        let t = Instant::now();
        drop(pump);
        assert!(t.elapsed() < Duration::from_secs(2));
        stop_echo_flag.store(true, Relaxed);
        echo_thread.join().unwrap();
    }

    #[test]
    fn handshake_times_out_when_nobody_answers() {
        let nobody = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (key, _) = keypair();
        let (_, other_public) = keypair();
        let other_public: [u8; 32] = BASE64_STANDARD.decode(other_public).unwrap().try_into().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let result = bring_up(
            socket,
            nobody.local_addr().unwrap(),
            key,
            other_public,
            Duration::from_millis(500),
            SILENCE,
        );
        assert!(result.is_err());
    }

    #[test]
    fn echo_request_matches_the_reference_bytes() {
        // sha256("abc"), base64.
        assert_eq!(secret_hash("abc"), "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
        assert_eq!(
            echo_request("HASH", 42),
            br#"{"session_secret_hash":"HASH","req_id":"42","timeout":3000}"#
        );
    }

    #[test]
    fn echo_reply_is_decoded_leniently() {
        assert_eq!(parse_pong(br#"{"req_id":"42"}"#).as_deref(), Some("42"));
        assert_eq!(parse_pong(br#"{"req_id":42,"x":1}"#).as_deref(), Some("42"));
        for bad in [
            &b""[..],
            b"not json",
            br#"{"req_id":null}"#,
            br#"{"id":"1"}"#,
            br#"["req_id"]"#,
        ] {
            assert_eq!(parse_pong(bad), None);
        }
    }

    #[test]
    fn keypair_is_fresh_and_consistent() {
        let (a, a_public) = keypair();
        let (b, _) = keypair();
        assert_ne!(a, b);
        let derived = PublicKey::from(&StaticSecret::from(a));
        assert_eq!(a_public, BASE64_STANDARD.encode(derived.as_bytes()));
    }

    #[test]
    fn echo_plan_needs_an_on_link_ipv6_echo() {
        let result = |tunnel: &str, echo: &str, mask: u8| ConnectResult {
            tunnel_addr: tunnel.into(),
            udp_echo_addr: echo.into(),
            udp_echo_port: 34378,
            tunnel_mask: mask,
            ..Default::default()
        };
        let plan = echo_plan(&result("fd37::2", "fd37::1", 120)).unwrap().unwrap();
        assert_eq!(plan, ("fd37::2".parse().unwrap(), "fd37::1".parse().unwrap(), 120));
        assert_eq!(echo_plan(&ConnectResult::default()).unwrap(), None);
        for bad in [
            result("fd37::2", "fd38::1", 120),
            result("fd37::2", "fd37::1", 0),
            result("fd37::2", "fd37::1", 8),
            result("10.0.0.2", "fd37::1", 120),
            result("fd37::2", "nope", 120),
            result("2001:db8::2", "2001:db8::1", 120),
        ] {
            assert!(echo_plan(&bad).is_err());
        }
    }
}
