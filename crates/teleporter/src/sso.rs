//! Signing in to a UI account at sso.ui.com, keeping the session, and trading it for AWS credentials.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use rsa::pkcs8::EncodePublicKey;
use serde_json::{Value, json};
use sha1::Sha1;

use crate::http::{Reply, clip, request};
use crate::{AwsCredentials, CloudConfig, Result, Session};

const LOGIN_URL: &str = "https://sso.ui.com/api/sso/v1/login";
const SELF_URL: &str = "https://sso.ui.com/api/sso/v1/user/self";
const PUSH_POLL_URL: &str = "https://sso.ui.com/api/sso/v1/user/self/mfa/push/poll-login";
const PUSH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const PUSH_POLL_TIMEOUT: Duration = Duration::from_secs(120);
const SESSION_FILE: &str = "session.json";
/// WiFiman Desktop's browser sign-in: Ubiquiti's server runs the OAuth exchange and hands the
/// tokens back in a `wifiman-desktop-dl://` link, encrypted to the key passed here.
const BROWSER_LOGIN_URL: &str = "https://sp-dir.uwn.com/auth/sso/desktop";
const REFRESH_URL: &str = "https://sp-dir.uwn.com/auth/sso/desktop/refresh";

/// The second factor the user chose.
pub enum Mfa {
    /// The six-digit code from an authenticator app.
    Totp(String),
    /// Approval in the UI mobile app; the password POST already sent the notification.
    Push,
}

/// A random UUID v4 in lowercase.
pub(crate) fn uuid_v4() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b)?;
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Keeps each `name=value` a `Set-Cookie` sets; an empty value deletes the cookie.
fn absorb(jar: &mut BTreeMap<String, String>, set_cookies: &[String]) {
    for cookie in set_cookies {
        let Some((name, value)) = cookie.split(';').next().unwrap_or("").split_once('=') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() {
            continue;
        }
        if value.is_empty() {
            jar.remove(name);
        } else {
            jar.insert(name.to_string(), value.to_string());
        }
    }
}

fn cookie_header(jar: &BTreeMap<String, String>) -> String {
    jar.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn json_headers(jar: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if !jar.is_empty() {
        headers.push(("cookie".to_string(), cookie_header(jar)));
    }
    headers
}

/// How a session proves itself: the access token of a browser sign-in, or the SSO cookies.
fn auth_headers(session: &Session) -> Vec<(String, String)> {
    if session.access_token.is_empty() {
        return json_headers(&session.cookies);
    }
    vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("authorization".to_string(), format!("Bearer {}", session.access_token)),
    ]
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

/// A browser sign-in in progress: the key the tokens will come back encrypted to.
pub struct BrowserLogin {
    key: rsa::PrivateKey,
}

impl BrowserLogin {
    /// Starts a sign-in; the returned URL is to be opened in the user's browser.
    pub fn start() -> Result<(BrowserLogin, String)> {
        // 1024 bits is what WiFiman asks its daemon for; the key lives for one sign-in.
        let key = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024)?;
        let public = BASE64_STANDARD.encode(key.to_public_key().to_public_key_der()?.as_bytes());
        let url = format!("{BROWSER_LOGIN_URL}?key={}", percent_encode(&public));
        Ok((BrowserLogin { key }, url))
    }

    /// Finishes the sign-in with the `wifiman-desktop-dl://` link the browser was sent to.
    pub fn finish(&self, link: &str, previous: Option<Session>) -> Result<Session> {
        let (access_token, refresh_token, expires_in) = self.tokens(link)?;
        let session = Session {
            access_token,
            refresh_token,
            expires_at: now() + expires_in,
            ..Session::default()
        };
        complete(session, previous)
    }

    /// The link's path is base64 of RSA-OAEP(SHA-1) over the access token, the refresh token
    /// and the lifetime in seconds, separated by tabs.
    fn tokens(&self, link: &str) -> Result<(String, String, u64)> {
        let path = link
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map_or("", |(_, path)| path);
        let path = path.split_once("sso.ui.link/").map_or(path, |(_, tokens)| tokens);
        let sealed = BASE64_STANDARD
            .decode(percent_decode(path))
            .map_err(|_| "the sign-in link carries no tokens")?;
        let plain = self
            .key
            .oaep_decrypt::<Sha1>(&sealed)
            .map_err(|_| "the sign-in link is not for this sign-in")?;
        let plain = String::from_utf8(plain).map_err(|_| "the sign-in link holds no text")?;
        match plain.split_whitespace().collect::<Vec<_>>()[..] {
            [access, refresh, expires_in] if !access.is_empty() => {
                Ok((access.to_string(), refresh.to_string(), expires_in.parse().unwrap_or(0)))
            }
            _ => Err("the sign-in link holds something other than tokens".into()),
        }
    }
}

/// Trades the refresh token of a browser sign-in for a new access token, if this one is used up.
pub fn refresh(session: &mut Session) -> Result<bool> {
    // Cookie sessions do not expire this way; the margin covers one connection attempt.
    if session.refresh_token.is_empty() || now() + 120 < session.expires_at {
        return Ok(false);
    }
    let headers = [("content-type".to_string(), "text/plain".to_string())];
    let reply = request("POST", REFRESH_URL, &headers, Some(session.refresh_token.as_bytes()))?;
    if reply.status != 200 {
        return Err(format!("the sign-in has expired - sign in again (HTTP {})", reply.status).into());
    }
    let j: Value = serde_json::from_str(&reply.body).map_err(|_| "token refresh: body is not JSON")?;
    let text = |a: &str, b: &str| {
        j.get(a)
            .or_else(|| j.get(b))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    session.access_token = text("accessToken", "access_token").ok_or("token refresh: no access token")?;
    if let Some(token) = text("refreshToken", "refresh_token") {
        session.refresh_token = token;
    }
    let expires_in = j
        .get("expiresIn")
        .or_else(|| j.get("expires_in"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    session.expires_at = now() + expires_in;
    Ok(true)
}

fn post_login(jar: &mut BTreeMap<String, String>, body: &Value) -> Result<Reply> {
    let reply = request("POST", LOGIN_URL, &json_headers(jar), Some(body.to_string().as_bytes()))?;
    absorb(jar, &reply.set_cookies);
    Ok(reply)
}

fn poll_push(jar: &mut BTreeMap<String, String>) -> Result<()> {
    let deadline = Instant::now() + PUSH_POLL_TIMEOUT;
    while Instant::now() < deadline {
        let reply = request("GET", PUSH_POLL_URL, &json_headers(jar), None)?;
        absorb(jar, &reply.set_cookies);
        if jar.contains_key("UBIC_AUTH") || (reply.status == 200 && reply.body.contains("username")) {
            return Ok(());
        }
        std::thread::sleep(PUSH_POLL_INTERVAL);
    }
    Err("push approval timed out - tap 'Yes, that's me' in the UI app".into())
}

/// Signs in, asking for a second factor (once) only if the account has one.
pub fn login(user: &str, password: &str, ask_mfa: &mut dyn FnMut() -> Result<Mfa>) -> Result<Session> {
    let mut jar = BTreeMap::new();
    let reply = post_login(&mut jar, &json!({"user": user, "password": password}))?;
    if reply.status != 200 {
        // A wrong password is a 403 without the cookie; only the MFA challenge is a 499 with it.
        let challenged =
            reply.status == 499 || jar.contains_key("UBIC_2FA") || reply.body.to_lowercase().contains("2fa");
        if !challenged {
            return Err(format!("login failed: HTTP {} {}", reply.status, clip(&reply.body)).into());
        }
        match ask_mfa()? {
            Mfa::Totp(token) => {
                let reply = post_login(&mut jar, &json!({"user": user, "password": password, "token": token}))?;
                if reply.status != 200 {
                    return Err(format!("MFA login failed: HTTP {} {}", reply.status, clip(&reply.body)).into());
                }
            }
            Mfa::Push => poll_push(&mut jar)?,
        }
    }
    if !jar.contains_key("UBIC_AUTH") {
        return Err("login succeeded but no UBIC_AUTH cookie was set".into());
    }
    Ok(Session {
        user: user.to_string(),
        cookies: jar,
        client_id: uuid_v4()?.to_uppercase(),
        ..Session::default()
    })
}

/// Turns the cookies of a browser login into a session, after checking that the
/// SSO accepts them. A `previous` session keeps its client id, so the console
/// sees the same client as before.
pub fn session_from_cookies(cookies: BTreeMap<String, String>, previous: Option<Session>) -> Result<Session> {
    complete(
        Session {
            cookies,
            ..Session::default()
        },
        previous,
    )
}

/// Checks the session against the SSO and fills in who it belongs to.
fn complete(mut session: Session, previous: Option<Session>) -> Result<Session> {
    let reply = request("GET", SELF_URL, &auth_headers(&session), None)?;
    if reply.status != 200 {
        return Err(format!("the SSO did not accept the login: HTTP {}", reply.status).into());
    }
    let me: Value = serde_json::from_str(&reply.body).unwrap_or_default();
    session.user = ["email", "username"]
        .iter()
        .find_map(|k| me.get(k)?.as_str())
        .unwrap_or_default()
        .to_string();
    session.client_id = match previous {
        Some(previous) if !previous.client_id.is_empty() => previous.client_id,
        _ => uuid_v4()?.to_uppercase(),
    };
    Ok(session)
}

pub fn load_session(dir: &Path) -> Result<Option<Session>> {
    let text = match std::fs::read_to_string(dir.join(SESSION_FILE)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let session: Session = serde_json::from_str(&text)?;
    Ok(Some(session).filter(|s| !s.cookies.is_empty() || !s.access_token.is_empty()))
}

pub fn save_session(dir: &Path, session: &Session) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join(SESSION_FILE))?;
    // `mode` only applies to a new file; an older, looser one is tightened before any write.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(serde_json::to_string(session)?.as_bytes())?;
    Ok(())
}

pub fn clear_session(dir: &Path) -> Result<()> {
    match std::fs::remove_file(dir.join(SESSION_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn parse_credentials(j: &Value) -> Result<AwsCredentials> {
    let field = |name: &str| -> Result<String> {
        match j.get(name).and_then(Value::as_str) {
            Some(s) => Ok(s.to_string()),
            None => Err(format!("unexpected create-credentials body (missing {name})").into()),
        }
    };
    Ok(AwsCredentials {
        identity_id: field("identityId")?,
        access_key_id: field("accessKeyId")?,
        secret_key: field("secretKey")?,
        session_token: field("sessionToken")?,
        expiration_ms: j.get("expiration").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// Trades the session's cookies for short-lived AWS credentials.
pub fn aws_credentials(session: &Session, cloud: &CloudConfig) -> Result<AwsCredentials> {
    let url = format!("{}/create-credentials", cloud.api_gateway_ui.trim_end_matches('/'));
    let reply = request("POST", &url, &auth_headers(session), Some(b"{}"))?;
    match reply.status {
        200 => {
            parse_credentials(&serde_json::from_str(&reply.body).map_err(|_| "create-credentials: body is not JSON")?)
        }
        401 | 403 => Err("SSO session expired - sign in again".into()),
        status => Err(format!("create-credentials -> HTTP {status}: {}", clip(&reply.body)).into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn sample() -> Session {
        Session {
            user: "alice@example.com".into(),
            cookies: BTreeMap::from([("UBIC_AUTH".into(), "abc123".into()), ("csrf".into(), "tok".into())]),
            client_id: "11111111-2222-4333-8444-555555555555".into(),
            ..Session::default()
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("teleporter-{name}-{}", uuid_v4().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn uuid_is_a_v4() {
        let id = uuid_v4().unwrap();
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
        assert!(parts[2].starts_with('4') && "89ab".contains(&parts[3][..1]));
        assert_ne!(id, uuid_v4().unwrap());
    }

    #[test]
    fn set_cookie_keeps_name_and_value_only() {
        let mut jar = BTreeMap::new();
        absorb(
            &mut jar,
            &[
                "UBIC_2FA=xyz; Path=/; Domain=.ui.com; HttpOnly".into(),
                "UBIC_AUTH=a=b==; Max-Age=31536000".into(),
                "junk".into(),
                "gone=1".into(),
            ],
        );
        absorb(&mut jar, &["gone=; Max-Age=0".into()]);
        assert_eq!(
            jar,
            BTreeMap::from([("UBIC_2FA".into(), "xyz".into()), ("UBIC_AUTH".into(), "a=b==".into())])
        );
        assert_eq!(cookie_header(&jar), "UBIC_2FA=xyz; UBIC_AUTH=a=b==");
    }

    #[test]
    fn session_round_trips_with_0600() {
        let dir = temp_dir("session");
        assert_eq!(load_session(&dir).unwrap(), None);
        save_session(&dir, &sample()).unwrap();
        assert_eq!(load_session(&dir).unwrap(), Some(sample()));
        let mode = std::fs::metadata(dir.join(SESSION_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        clear_session(&dir).unwrap();
        clear_session(&dir).unwrap();
        assert_eq!(load_session(&dir).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saving_tightens_an_existing_file() {
        let dir = temp_dir("tighten");
        let path = dir.join(SESSION_FILE);
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_session(&dir, &sample()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn session_without_cookies_is_no_session() {
        let dir = temp_dir("empty");
        std::fs::write(dir.join(SESSION_FILE), r#"{"user":"bob","cookies":{},"client_id":"x"}"#).unwrap();
        assert_eq!(load_session(&dir).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn browser_login_reads_the_tokens_out_of_the_link() {
        let (login, url) = BrowserLogin::start().unwrap();
        let key = url
            .strip_prefix("https://sp-dir.uwn.com/auth/sso/desktop?key=")
            .unwrap();
        // What the server does with the key: SPKI in base64, RSA-OAEP with SHA-1, base64 in the path.
        let spki = BASE64_STANDARD.decode(percent_decode(key)).unwrap();
        assert!(key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'%'));
        let public: rsa::PublicKey = rsa::pkcs8::DecodePublicKey::from_public_key_der(&spki).unwrap();
        let sealed = BASE64_STANDARD.encode(public.oaep_encrypt::<Sha1>(b"acc+ess\tref/resh\t3600").unwrap());

        for link in [
            format!("wifiman-desktop-dl://sso.ui.link/{}", percent_encode(&sealed)),
            format!("wifiman-desktop-dl://x/sso.ui.link/{sealed}"),
        ] {
            assert_eq!(
                login.tokens(&link).unwrap(),
                ("acc+ess".to_string(), "ref/resh".to_string(), 3600)
            );
        }
        let (other, _) = BrowserLogin::start().unwrap();
        assert!(
            other
                .tokens(&format!("wifiman-desktop-dl://sso.ui.link/{sealed}"))
                .is_err()
        );
        assert!(login.tokens("wifiman-desktop-dl://sso.ui.link/").is_err());
        assert!(login.tokens("nonsense").is_err());
    }

    #[test]
    fn a_token_that_still_has_time_is_not_refreshed() {
        let mut session = Session {
            refresh_token: "r".into(),
            expires_at: now() + 3600,
            ..sample()
        };
        assert!(!refresh(&mut session).unwrap());
        assert!(!refresh(&mut sample()).unwrap());
    }

    #[test]
    fn credentials_are_parsed_and_missing_fields_named() {
        let j = json!({"identityId": "us-west-2:id", "accessKeyId": "ASIA", "secretKey": "s", "sessionToken": "t", "expiration": 1700000000000u64});
        let creds = parse_credentials(&j).unwrap();
        assert_eq!(creds.identity_id, "us-west-2:id");
        assert_eq!(creds.expiration_ms, 1_700_000_000_000);
        let err = parse_credentials(&json!({"identityId": "x", "accessKeyId": "y"})).unwrap_err();
        assert_eq!(
            err.to_string(),
            "unexpected create-credentials body (missing secretKey)"
        );
    }
}
