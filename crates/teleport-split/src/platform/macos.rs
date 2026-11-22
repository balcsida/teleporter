//! macOS: WiFiman runs a bundled `wg-quick`, so its tunnel is a `utun`
//! registered under /var/run/wireguard, and routes are edited with route(8)
//! exactly as `wg-quick` does.

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use crate::{Net, Os, Tunnel};

pub const STATUS_FILE: &str = "/var/run/teleport-split.status";

const ROUTE: &str = "/sbin/route";
const WG_RUN: &str = "/var/run/wireguard";
const LABEL: &str = "com.teleport-split-tunnel.daemon";
const PLIST: &str = "/Library/LaunchDaemons/com.teleport-split-tunnel.daemon.plist";
const BIN_DIR: &str = "/Library/PrivilegedHelperTools";
const BIN: &str = "/Library/PrivilegedHelperTools/teleport-split";
const LOG: &str = "/var/log/teleport-split.log";

pub struct System;

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).stdin(Stdio::null()).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn family(net: Net) -> &'static str {
    if net.addr.is_ipv4() { "-inet" } else { "-inet6" }
}

impl Os for System {
    fn tunnel(&self) -> Option<Tunnel> {
        let iface = wifiman_iface(Path::new(WG_RUN))?;
        // Also proves the interface exists: a crashed wireguard-go leaves its files behind.
        let ifconfig = run("/sbin/ifconfig", &[&iface])?;
        Some(Tunnel {
            nets: parse_ifconfig(&ifconfig),
            iface,
        })
    }

    fn route_iface(&self, net: Net) -> Option<String> {
        // With a mask, `route get` only finds that exact route (or the default),
        // so a host is looked up by address: "127.0.0.1/32" misses lo0.
        let target = if net == Net::host(net.addr) {
            net.addr.to_string()
        } else {
            net.to_string()
        };
        let out = run(ROUTE, &["-n", "get", family(net), &target])?;
        out.lines()
            .find_map(|l| l.trim().strip_prefix("interface: ").map(str::to_string))
    }

    fn add_route(&mut self, net: Net, iface: &str) {
        run(
            ROUTE,
            &["-q", "-n", "add", family(net), &net.to_string(), "-interface", iface],
        );
    }

    fn delete_route(&mut self, net: Net, iface: &str) {
        run(
            ROUTE,
            &["-q", "-n", "delete", family(net), &net.to_string(), "-interface", iface],
        );
    }
}

/// The `utun` behind WiFiman's tunnel. wireguard-go records it in
/// `<name>.name`, and WiFiman names its tunnels `wgwfm` plus eight hex digits,
/// which is what keeps other WireGuard tunnels out of reach.
fn wifiman_iface(dir: &Path) -> Option<String> {
    fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let file = entry.file_name().into_string().ok()?;
        let id = file.strip_suffix(".name")?.strip_prefix("wgwfm")?;
        if id.len() != 8 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let iface = fs::read_to_string(entry.path()).ok()?.trim().to_string();
        let unit = iface.strip_prefix("utun")?;
        let valid = !unit.is_empty() && unit.bytes().all(|b| b.is_ascii_digit());
        (valid && dir.join(format!("{iface}.sock")).exists()).then_some(iface)
    })
}

/// The networks of an interface's addresses, from ifconfig(8) output.
fn parse_ifconfig(text: &str) -> Vec<Net> {
    text.lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let after = |key: &str| {
                words
                    .iter()
                    .position(|w| *w == key)
                    .and_then(|i| words.get(i + 1))
                    .copied()
            };
            match *words.first()? {
                "inet" => {
                    let addr: Ipv4Addr = words.get(1)?.parse().ok()?;
                    let mask = u32::from_str_radix(after("netmask")?.strip_prefix("0x")?, 16).ok()?;
                    // A /32 is only the tunnel's own address, which is already routed.
                    (mask != u32::MAX).then(|| Net::new(addr.into(), mask.leading_ones() as u8))?
                }
                "inet6" => {
                    // Link-local addresses carry a %scope and are never routed.
                    let addr: IpAddr = words.get(1)?.parse().ok()?;
                    let prefix: u8 = after("prefixlen")?.parse().ok()?;
                    // The gateway end of a /128 is still in the same /64.
                    Net::new(addr, prefix.min(64))
                }
                _ => None,
            }
        })
        .collect()
}

/// Whether a `route -n monitor` line reports a change. Lookups (RTM_GET) are
/// reported too, including the daemon's own, and so are requests the kernel
/// rejected; waking on a rejected add would retry it forever.
fn is_change(line: &str) -> bool {
    const KINDS: [&str; 6] = [
        "RTM_ADD",
        "RTM_DELETE",
        "RTM_CHANGE",
        "RTM_NEWADDR",
        "RTM_DELADDR",
        "RTM_IFINFO",
    ];
    let failed = line.contains(", errno ") && !line.contains(", errno 0,");
    !failed && KINDS.iter().any(|kind| line.starts_with(kind))
}

/// Send on `tx` whenever the routing table or an interface changes.
pub fn watch_routes(tx: Sender<()>) {
    thread::spawn(move || {
        let Ok(mut child) = Command::new(ROUTE)
            .args(["-n", "monitor"])
            .stdout(Stdio::piped())
            .spawn()
        else {
            return;
        };
        let lines = BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
        for line in lines.map_while(Result::ok) {
            if is_change(&line) && tx.send(()).is_err() {
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    });
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn plist(config_dir: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{BIN}</string>
        <string>daemon</string>
        <string>--config</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>{LOG}</string>
</dict>
</plist>
"#,
        xml_escape(config_dir)
    )
}

fn bootout() {
    run("/bin/launchctl", &["bootout", &format!("system/{LABEL}")]);
}

/// Install this executable as a root LaunchDaemon that reads `config_dir`.
pub fn install(config_dir: &Path) -> io::Result<()> {
    let config_dir = config_dir
        .to_str()
        .filter(|_| config_dir.is_absolute())
        .ok_or_else(|| io::Error::other("the config directory must be an absolute UTF-8 path"))?;
    let exe = std::env::current_exe()?;
    bootout();
    if exe != Path::new(BIN) {
        fs::create_dir_all(BIN_DIR)?;
        // Replace, never overwrite: macOS kills a signed binary that was rewritten in place.
        match fs::remove_file(BIN) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        fs::copy(&exe, BIN)?;
        fs::set_permissions(BIN, fs::Permissions::from_mode(0o755))?;
    }
    fs::write(PLIST, plist(config_dir))?;
    // bootout returns before the old job is gone, and bootstrap fails until it is.
    for _ in 0..20 {
        if run("/bin/launchctl", &["bootstrap", "system", PLIST]).is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(io::Error::other(format!("launchctl could not start {LABEL}")))
}

/// Stop the daemon and remove everything `install` created.
pub fn uninstall() -> io::Result<()> {
    bootout();
    for file in [PLIST, BIN, STATUS_FILE] {
        match fs::remove_file(file) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_wifiman_tunnels_are_recognized() {
        let dir = std::env::temp_dir().join(format!("teleport-split-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let put = |name: &str, body: &str| fs::write(dir.join(name), body).unwrap();

        // Another WireGuard tunnel, and a WiFiman name file whose socket is gone.
        put("wg0.name", "utun3\n");
        put("utun3.sock", "");
        put("wgwfm0000aaaa.name", "utun5\n");
        assert_eq!(wifiman_iface(&dir), None);

        put("wgwfm12ab34cd.name", "utun8\n");
        put("utun8.sock", "");
        assert_eq!(wifiman_iface(&dir).as_deref(), Some("utun8"));

        // Contents that are not an interface name never reach route(8).
        put("wgwfm12ab34cd.name", "utun8 -interface en0\n");
        assert_eq!(wifiman_iface(&dir), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ifconfig_yields_the_tunnel_networks() {
        let text = "\
utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
\tinet 192.0.2.6 --> 192.0.2.6 netmask 0xffffff00
\tinet 198.51.100.9 --> 198.51.100.9 netmask 0xffffffff
\tinet6 fe80::1234:5678:9abc:def0%utun8 prefixlen 64 scopeid 0x1c
\tinet6 fd37:1:2:3:4:5:6:2 prefixlen 64
\tinet6 fd99::2 prefixlen 128
";
        let nets: Vec<String> = parse_ifconfig(text).iter().map(Net::to_string).collect();
        assert_eq!(nets, ["192.0.2.0/24", "fd37:1:2:3::/64", "fd99::/64"]);
    }

    #[test]
    fn route_lookups_do_not_count_as_changes() {
        assert!(is_change(
            "RTM_ADD: Add Route: len 140, pid: 0, seq 0, errno 0, flags:<UP,DONE,STATIC>"
        ));
        assert!(is_change(
            "RTM_IFINFO: iface status change: len 112, if# 28, flags:<UP,RUNNING>"
        ));
        assert!(!is_change(
            "RTM_ADD: Add Route: len 140, pid: 9, seq 1, errno 17, flags:<UP,STATIC>"
        ));
        assert!(!is_change("RTM_GET: Report Metrics: len 164, pid: 1, seq 1"));
        assert!(!is_change("got message of size 164 on Sun Nov 22 14:15:45 2026"));
    }

    #[test]
    fn route_lookup_reads_the_real_table() {
        assert_eq!(System.route_iface("127.0.0.1".parse().unwrap()).as_deref(), Some("lo0"));
        assert_eq!(System.route_iface("::1".parse().unwrap()).as_deref(), Some("lo0"));
        assert_eq!(
            System.route_iface("127.0.0.0/8".parse().unwrap()).as_deref(),
            Some("lo0")
        );
    }

    #[test]
    fn plist_escapes_the_config_path() {
        let plist = plist("/Users/a&b/<x>");
        assert!(plist.contains("<string>/Users/a&amp;b/&lt;x&gt;</string>"));
    }
}
