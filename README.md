# Teleporter

A standalone UniFi Teleport client that routes only your console's networks
through the tunnel. Everything else stays on your normal connection.

WiFiman's Teleport is a full tunnel: once you connect, all of your traffic goes
through your UniFi gateway. This client speaks the same protocol, signs in
with your own UI account, and adds routes only for the LANs behind the console
you connect to. It does not need WiFiman.

> This is an independent, unofficial interoperability project. It is not
> affiliated with or endorsed by Ubiquiti, and using it may be against
> Ubiquiti's terms. Use it only with consoles you own or administer. It changes
> routes as root and comes with no warranty.

Status: macOS only for now, and new. It has connected to one console (a Dream
Router 7) from one network so far.

## Install

With [Homebrew](https://brew.sh), the menu bar app and the `teleporter` CLI:

```bash
brew install --cask balcsida/tap/teleporter
open -a Teleporter
```

The app is ad-hoc signed, not notarized, so the cask clears its quarantine
flag; otherwise Gatekeeper would block the CLI on its first run. Each release
carries a [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations):
`gh attestation verify Teleporter-<version>.zip --repo balcsida/teleporter`.

From source, with a Rust toolchain:

```bash
git clone https://github.com/balcsida/teleporter.git
cd teleporter

# CLI only
cargo install --path crates/teleporter

# or the menu bar app, with the CLI inside it
./scripts/bundle-macos.sh
open "target/Teleporter.app"
```

## Usage

```bash
teleporter login                 # UI account, password, then a code or a push approval
teleporter ls                    # your consoles and the networks behind them
sudo teleporter up "My Console"  # connect in the foreground, Ctrl-C disconnects
```

### Signing in with a passkey

A passkey only works in a real browser. Two ways to use one:

- **Menu bar app, "Sign In with Browser…".** This opens Ubiquiti's own sign-in
  in your default browser, the same one WiFiman Desktop uses. That sign-in ends
  in a `wifiman-desktop-dl://` link, which belongs to WiFiman. The app takes
  the link over only after you choose this menu item, gives it back to WiFiman
  as soon as the link has arrived (or after five minutes), and passes on any
  link it did not ask for. The link cannot be pointed anywhere else: the only
  thing a client sends is a public key.
- **CLI, `teleporter login --cookie`.** Sign in at <https://account.ui.com>
  in your browser, copy the value of the `UBIC_AUTH` cookie from the developer
  tools (Application or Storage, then Cookies), and paste it at the prompt.

To stay connected without a terminal, install the helper once. It is a root
LaunchDaemon that keeps the tunnel up and reconnects when it drops:

```bash
sudo "$(which teleporter)" install
teleporter connect "My Console"
teleporter status
teleporter disconnect
sudo teleporter uninstall
```

The menu bar app does the same: it lists your consoles, and clicking one
connects or disconnects. It shows who is signed in, with "Sign Out" below the
consoles. While nobody is signed in it offers "Sign In with Browser…"
(described above) and "Sign In in Terminal…", which runs `login` in a terminal.

### What gets routed

The console's LAN subnets come from your UI account, so there is nothing to
configure. A subnet that overlaps the network you are sitting on is skipped,
otherwise you would lose your local LAN. `teleporter status` lists what was
routed and what was skipped.

To send more through Teleport, for example a public address that should see
your home IP:

```bash
teleporter add 203.0.113.0/24 nas.example.com
teleporter list
teleporter remove nas.example.com
```

Host names are resolved once per connection. DNS is not changed, so names that
only your home DNS knows need an address or `/etc/resolver`.

## How it works

1. **Sign in.** `login` talks to `sso.ui.com` and keeps the session cookie (or,
   after a browser sign-in, its tokens) in
   `~/.config/teleporter/session.json` (mode 0600). The password is not
   stored. Short-lived AWS credentials are minted from the session when needed.
2. **Directory.** The cloud lists your consoles with their LAN subnets.
3. **Signaling.** An access request reaches the console over AWS IoT (MQTT),
   then the client and the console swap WireGuard keys and NAT candidates
   through the cloud.
4. **NAT traversal.** Authenticated STUN checks find a direct UDP path.
5. **Tunnel.** WireGuard ([boringtun](https://github.com/cloudflare/boringtun))
   runs over that path on a `utun` device, and a small in-tunnel heartbeat
   keeps the console's lease alive.
6. **Routes.** Only the selected subnets are routed to the `utun`.

The protocol knowledge comes from
[darki73/telepy-cli](https://github.com/darki73/telepy-cli) (MIT), whose docs
describe each step, cross-checked against
[sinnet3000/teleport-client](https://github.com/sinnet3000/teleport-client).

## Files

| File | Purpose |
| --- | --- |
| `~/.config/teleporter/session.json` | The signed-in session |
| `~/.config/teleporter/connect` | Name of the console the helper should be connected to |
| `~/.config/teleporter/routes.conf` | Extra destinations, one per line, `#` comments |
| `/var/run/teleporter.status` | What the helper is doing, as `key=value` lines |
| `/var/log/teleporter.log` | Helper log, one line per change |

The helper runs as root, because creating a `utun` and editing routes needs it,
and reads the first three files from the home directory of the user who
installed it. These files are the whole interface between the helper and its
frontends.

## Not handled

- Relayed (TURN) connections. If no direct path can be punched, connecting fails.
- IPv6 destinations, and DNS.
- A full-tunnel mode. Use WiFiman for that.
- The app is ad-hoc signed. There is no notarized download yet.

## Layout

```
crates/teleporter/            library and CLI
  src/sso.rs                  UI account sign-in, session file
  src/aws.rs                  SigV4 signing
  src/cloud.rs                console directory, ICE config and CONNECT calls
  src/signaling.rs            access request over AWS IoT MQTT
  src/ice.rs                  STUN candidates and connectivity checks
  src/tunnel.rs               WireGuard, the TUN device, the heartbeat
  src/connect.rs              the steps above in order, and the route plan
  src/platform/macos.rs       route(8), launchd
crates/menubar/               macOS menu bar app (tao, tray-icon)
scripts/bundle-macos.sh       builds the .app
```

### Windows

The protocol and tunnel code is portable (`tun-rs` and `boringtun` both run on
Windows). What is missing is `platform/windows.rs`: routes and a Windows
service. A WinUI 3 frontend then does what the menu bar app does: list the
consoles, write `connect` and `routes.conf`, read the status file.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

To release, raise `version` under `[workspace.package]` in `Cargo.toml` and
merge to `main`. Once CI passes it tags the commit, the release workflow
builds a universal `Teleporter-<version>.zip`, publishes it, and the Homebrew
tap picks it up.
