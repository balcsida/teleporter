//! macOS: routes are edited with route(8), the way `wg-quick` does it, and the
//! daemon is a LaunchDaemon.

use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::Net;

pub const STATUS_FILE: &str = "/var/run/teleport-split.status";

const ROUTE: &str = "/sbin/route";
const LABEL: &str = "com.teleport-split-tunnel.daemon";
const PLIST: &str = "/Library/LaunchDaemons/com.teleport-split-tunnel.daemon.plist";
const BIN_DIR: &str = "/Library/PrivilegedHelperTools";
const BIN: &str = "/Library/PrivilegedHelperTools/teleport-split";
const LOG: &str = "/var/log/teleport-split.log";

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).stdin(Stdio::null()).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn family(net: Net) -> &'static str {
    if net.addr.is_ipv4() { "-inet" } else { "-inet6" }
}

/// Route `net` through `iface`. Returns whether the routing table now does.
pub fn add_route(net: Net, iface: &str) -> bool {
    run(
        ROUTE,
        &["-q", "-n", "add", family(net), &net.to_string(), "-interface", iface],
    );
    // route(8) exits 0 even when it fails, so ask the table. With a mask,
    // `route get` only finds that exact route, so a host is looked up by address.
    let target = if net == Net::host(net.addr) {
        net.addr.to_string()
    } else {
        net.to_string()
    };
    run(ROUTE, &["-n", "get", family(net), &target])
        .is_some_and(|out| out.lines().any(|l| l.trim().strip_prefix("interface: ") == Some(iface)))
}

/// The IPv4 networks this machine is directly attached to.
pub fn local_nets() -> Vec<Net> {
    run("/sbin/ifconfig", &["-a"])
        .map(|out| parse_local_nets(&out))
        .unwrap_or_default()
}

fn parse_local_nets(ifconfig: &str) -> Vec<Net> {
    ifconfig
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            // Only broadcast interfaces are LANs; tunnels show "-->" instead.
            if words.first() != Some(&"inet") || !words.contains(&"broadcast") {
                return None;
            }
            let addr: Ipv4Addr = words.get(1)?.parse().ok()?;
            let mask = words
                .iter()
                .position(|w| *w == "netmask")
                .and_then(|i| words.get(i + 1))?;
            let mask = u32::from_str_radix(mask.strip_prefix("0x")?, 16).ok()?;
            Net::new(addr.into(), mask.leading_ones() as u8)
        })
        .collect()
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
    fn local_nets_are_the_broadcast_interfaces() {
        let text = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xf
\tinet 192.168.50.23 netmask 0xffffff00 broadcast 192.168.50.255
utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 192.0.2.6 --> 192.0.2.6 netmask 0xffffffff
";
        let nets: Vec<String> = parse_local_nets(text).iter().map(Net::to_string).collect();
        assert_eq!(nets, ["192.168.50.0/24"]);
        assert!(!local_nets().iter().any(|n| n.prefix == 0));
    }

    #[test]
    fn plist_escapes_the_config_path() {
        let plist = plist("/Users/a&b/<x>");
        assert!(plist.contains("<string>/Users/a&amp;b/&lt;x&gt;</string>"));
    }
}
