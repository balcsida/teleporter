//! One blocking HTTPS call that hands back 4xx/5xx instead of failing, with the OS trust store.

use std::sync::OnceLock;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

use crate::Result;

pub(crate) struct Reply {
    pub status: u16,
    /// The `Set-Cookie` header values.
    pub set_cookies: Vec<String>,
    pub body: String,
}

/// The first 200 characters, as the reference does, so error messages stay short.
pub(crate) fn clip(s: &str) -> String {
    s.chars().take(200).collect()
}

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .https_only(true)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .user_agent("teleport-split/0.1")
            // A TLS-inspecting proxy's CA is only in the system keychain.
            .tls_config(
                TlsConfig::builder()
                    .provider(TlsProvider::NativeTls)
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into()
    })
}

pub(crate) fn request(method: &str, url: &str, headers: &[(String, String)], body: Option<&[u8]>) -> Result<Reply> {
    let mut builder = ureq::http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let mut response = match body {
        Some(body) => agent().run(builder.body(body.to_vec())?)?,
        None => agent().run(builder.body(())?)?,
    };
    let set_cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect();
    let status = response.status().as_u16();
    let body = String::from_utf8_lossy(&response.body_mut().read_to_vec()?).into_owned();
    Ok(Reply {
        status,
        set_cookies,
        body,
    })
}
