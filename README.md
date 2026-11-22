# UniFi Teleport Split Tunnel

UniFi Teleport in WiFiman Desktop is a full tunnel: once you connect, all of
your traffic goes through your UniFi gateway. This utility turns it into a
split tunnel. Only the destinations you list use Teleport, everything else
stays on your normal connection.

It does not reimplement Teleport. WiFiman still signs in, connects and keeps
the tunnel alive. This tool only fixes the routing table afterwards.

> This is an independent utility and is not affiliated with Ubiquiti. It
> changes routes as root and may interrupt network access if misconfigured.

Status: macOS only for now, and new. The route logic is covered by tests, but
the route changes have not been verified against a live Teleport session yet.

## How it works

WiFiman runs a bundled `wg-quick` with `AllowedIPs = 0.0.0.0/0, ::/0`, which
adds four broad routes on the tunnel interface: `0.0.0.0/1`, `128.0.0.0/1`,
`::/1` and `8000::/1`. A small root helper watches the routing table and, as
soon as the Teleport tunnel appears:

1. removes those four routes from the tunnel interface,
2. adds a route through the tunnel for each destination in `routes.conf`,
3. keeps the tunnel's own subnets routed, because WiFiman talks to the gateway
   inside the tunnel.

Only WiFiman's tunnel is touched. It is recognized by the interface name
WiFiman gives it (`wgwfm` plus eight hex digits), so other WireGuard tunnels
and other VPNs keep their routes.

## Install

Requires WiFiman Desktop and a Rust toolchain.

```bash
git clone https://github.com/balcsida/unifi-teleport-split-tunnel.git
cd unifi-teleport-split-tunnel

# CLI only
cargo install --path crates/teleport-split
sudo "$(which teleport-split)" install

# or the menu bar app, with the CLI inside it
./scripts/bundle-macos.sh
open "target/Teleport Split Tunnel.app"   # then: Install Helper…
```

`install` copies the binary to `/Library/PrivilegedHelperTools/teleport-split`
and registers the LaunchDaemon `com.teleport-split-tunnel.daemon`. Connect
Teleport in WiFiman as usual afterwards.

## Usage

```bash
teleport-split status              # what the helper is doing
teleport-split list                # destinations routed through Teleport
teleport-split add 192.168.1.0/24  # a network, an address or a host name
teleport-split add nas.example.com
teleport-split remove 10.0.0.0/8
teleport-split off                 # back to WiFiman's full tunnel
teleport-split on                  # split tunnel again
sudo teleport-split uninstall
```

Until you change it, the list is the three private ranges (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`), so your home LAN is reachable without any
setup. Routes that are more specific, like the LAN you are sitting on, still
win over these.

Host names are resolved to addresses every minute. That works for a NAS, not
for a site behind a large CDN.

The menu bar app shows the same status and has the same switch. "Edit Routes…"
opens `routes.conf` in your text editor.

## Files

| File | Purpose |
| --- | --- |
| `~/.config/teleport-split/routes.conf` | Destinations routed through Teleport, one per line, `#` comments |
| `~/.config/teleport-split/disabled` | While this file exists, the helper keeps the full tunnel |
| `/var/run/teleport-split.status` | What the helper last did, as `key=value` lines |
| `/var/log/teleport-split.log` | Helper log, one line per change |

The helper picks up changes to the first two within a few seconds. There is no
other interface between the helper and its frontends.

The helper runs as root and reads `routes.conf` from the home directory of the
user who installed it. Each line must be a network, an address or a host name.
Anything else is ignored and never reaches `route`.

## Not handled

- DNS. As far as I can tell from its bundled `wg-quick`, WiFiman does not
  change DNS on macOS, and neither does this tool. Names that only your home
  DNS knows need `/etc/resolver` or an address.
- Remote subnets are not discovered from your UniFi account. You list them.
- The app is ad-hoc signed. There is no notarized download yet.

## Layout

```
crates/teleport-split/        library and CLI, no dependencies
  src/lib.rs                  config, status file, route reconciliation
  src/platform/macos.rs       tunnel detection, route(8), launchd
crates/menubar/               macOS menu bar app (tao, tray-icon)
scripts/bundle-macos.sh       builds the .app
```

### Windows

Everything OS-specific is behind the `Os` trait and the `platform` module, so a
Windows backend is one new file, `platform/windows.rs`: find WiFiman's
WireGuard adapter, edit routes, install a Windows service. A WinUI 3 frontend
then does what the menu bar app does: read the status file and write
`routes.conf` and `disabled`.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

`cargo run -p teleport-split -- daemon --config ~/.config/teleport-split` runs
the helper in the foreground (as root).

## Related projects

- [darki73/telepy-cli](https://github.com/darki73/telepy-cli) is a standalone
  Teleport client in Python with a split tunnel mode. It reimplements the
  protocol and signs in with your UI account instead of using WiFiman.
- [sinnet3000/teleport-client](https://github.com/sinnet3000/teleport-client)
  is an experimental Go client that exposes the tunnel as a SOCKS5 proxy.
- [zscaler-split-tunnel](https://github.com/balcsida/zscaler-split-tunnel) does
  the same job for Zscaler and is where the approach comes from.
