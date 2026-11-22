//! One module per operating system, each exporting the same names:
//!
//! - `System`: the [`Os`](crate::Os) implementation
//! - `STATUS_FILE`: where the daemon writes [`Status`](crate::Status)
//! - `watch_routes(tx)`: sends on `tx` whenever the routing table changes
//! - `install(config_dir)` / `uninstall()`: register the daemon with the OS
//!
//! A Windows backend (WiFiman's WireGuard service, `route.exe`, a Windows
//! service) goes in `windows.rs` and needs nothing outside this directory.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(target_os = "macos"))]
compile_error!("teleport-split only has a macOS backend so far; see src/platform/mod.rs");
