//! Signing in to a UI account at sso.ui.com, keeping the session, and trading it for AWS credentials.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::http::{Reply, clip, request};
use crate::{AwsCredentials, CloudConfig, Result, Session};

const LOGIN_URL: &str = "https://sso.ui.com/api/sso/v1/login";
const PUSH_POLL_URL: &str = "https://sso.ui.com/api/sso/v1/user/self/mfa/push/poll-login";
const PUSH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const PUSH_POLL_TIMEOUT: Duration = Duration::from_secs(120);
const SESSION_FILE: &str = "session.json";

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
    })
}

pub fn load_session(dir: &Path) -> Result<Option<Session>> {
    let text = match std::fs::read_to_string(dir.join(SESSION_FILE)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let session: Session = serde_json::from_str(&text)?;
    Ok(Some(session).filter(|s| !s.cookies.is_empty()))
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
    let reply = request("POST", &url, &json_headers(&session.cookies), Some(b"{}"))?;
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
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("teleport-split-{name}-{}", uuid_v4().unwrap()));
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
