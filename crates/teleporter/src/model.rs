//! The values the protocol steps hand to each other.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Net;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The signed-in UI account, as kept in `session.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub user: String,
    /// The SSO cookies; `UBIC_AUTH` is the long-lived trusted session.
    pub cookies: BTreeMap<String, String>,
    /// A UUID that identifies this installation to the console.
    pub client_id: String,
    /// Set instead of the cookies after a browser sign-in.
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    /// When the access token stops working, in seconds since the epoch.
    #[serde(default)]
    pub expires_at: u64,
}

/// Short-lived AWS credentials minted from a [`Session`].
#[derive(Debug, Clone, PartialEq)]
pub struct AwsCredentials {
    pub identity_id: String,
    pub access_key_id: String,
    pub secret_key: String,
    pub session_token: String,
    /// Milliseconds since the epoch; 0 when unknown.
    pub expiration_ms: u64,
}

/// Where Ubiquiti's cloud lives, from `cloudAccessConfig.json`.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudConfig {
    pub region: String,
    pub iot_region: String,
    pub mqtt_host: String,
    pub api_gateway_ui: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Console {
    /// `<hex>:<number>`; also the connection id used in signaling.
    pub id: String,
    pub name: String,
    pub online: bool,
    /// The LANs behind the console, without its Teleport transfer network.
    pub subnets: Vec<Net>,
    /// The site's WAN address, to recognize the site this machine sits behind.
    pub public_ip: String,
}

/// A console's permission to connect, from its `access-request` endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessGrant {
    pub secret: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    /// `iface`, `reflex` or `turn`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `ip:port`.
    pub addr: String,
}

/// What the client offers in CONNECT.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientOffer {
    /// Base64, as WireGuard prints it.
    pub wg_public_key: String,
    pub candidates: Vec<Candidate>,
    pub ice_servers: Vec<IceServer>,
    /// Base64 of 16 random bytes; authenticates the STUN checks.
    pub stun_session_secret: String,
}

/// The console's answer to CONNECT.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnectResult {
    pub server_wg_public_key: String,
    /// This client's address inside the tunnel.
    pub client_ip: String,
    pub dns_addrs: Vec<String>,
    pub remote_candidates: Vec<Candidate>,
    pub is_master: bool,
    pub udp_echo_addr: String,
    pub udp_echo_port: u16,
    pub tunnel_addr: String,
    pub tunnel_mask: u8,
}
