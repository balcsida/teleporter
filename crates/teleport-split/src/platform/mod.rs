//! One module per operating system, each exporting the same names:
//!
//! - `STATUS_FILE`: where the daemon writes [`Status`](crate::Status)
//! - `add_route(net, iface)`: route a network through the tunnel interface
//! - `local_nets()`: the LANs this machine is attached to
//! - `install(config_dir)` / `uninstall()`: register the daemon with the OS
//!
//! A Windows backend goes in `windows.rs` and needs nothing outside this
//! directory; the tunnel itself (`tun-rs`, `boringtun`) is already portable.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(target_os = "macos"))]
compile_error!("teleport-split only has a macOS backend so far; see src/platform/mod.rs");
