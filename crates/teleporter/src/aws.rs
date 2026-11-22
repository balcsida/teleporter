//! AWS Signature Version 4, for the API Gateway calls and the AWS IoT WebSocket.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::{AwsCredentials, Result};

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Percent-encodes everything but the RFC 3986 unreserved characters (and `/` when asked).
fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)`, by Hinnant's days-to-civil algorithm.
fn amz_dates(now: SystemTime) -> (String, String) {
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let date = format!("{year:04}{month:02}{day:02}");
    let stamp = format!("{date}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60);
    (date, stamp)
}

/// The signature over `canonical_request`, for the scope `date/region/service`.
fn signature(creds: &AwsCredentials, stamp: &str, region: &str, service: &str, canonical_request: &str) -> String {
    let date = &stamp[..8];
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{date}/{region}/{service}/aws4_request\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let mut key = hmac(format!("AWS4{}", creds.secret_key).as_bytes(), date.as_bytes());
    for part in [region, service, "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    hex(&hmac(&key, string_to_sign.as_bytes()))
}

/// `(host, path, query)` of an absolute URL.
fn split_url(url: &str) -> (&str, &str, &str) {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..], query),
        None => (rest, "/", query),
    }
}

fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Signs a request; returns the headers to add to it.
///
/// Like botocore, it signs every header it sends: `host`, `x-amz-date`,
/// `x-amz-security-token` (when set) and `content-type` (only when there is a body).
pub fn sign(
    creds: &AwsCredentials,
    region: &str,
    service: &str,
    method: &str,
    url: &str,
    body: &[u8],
    now: SystemTime,
) -> Result<Vec<(String, String)>> {
    let (host, path, query) = split_url(url);
    if host.is_empty() {
        return Err("cannot sign a URL without a host".into());
    }
    let (_, stamp) = amz_dates(now);

    let mut headers = Vec::new();
    if !body.is_empty() {
        headers.push(("content-type".to_string(), "application/json".to_string()));
    }
    headers.push(("x-amz-date".to_string(), stamp.clone()));
    if !creds.session_token.is_empty() {
        headers.push(("x-amz-security-token".to_string(), creds.session_token.clone()));
    }

    let mut signed: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    signed.push(("host", host));
    signed.sort();
    let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let signed_names = signed.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");

    let canonical_request = format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{signed_names}\n{}",
        uri_encode(path, true),
        canonical_query(query),
        sha256_hex(body)
    );
    let sig = signature(creds, &stamp, region, service, &canonical_request);
    headers.push((
        "authorization".to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}/{region}/{service}/aws4_request, SignedHeaders={signed_names}, Signature={sig}",
            creds.access_key_id,
            &stamp[..8]
        ),
    ));
    Ok(headers)
}

/// The `wss://` URL for AWS IoT's MQTT-over-WebSocket, authorized in the query string.
pub fn presign_iot_url(creds: &AwsCredentials, region: &str, host: &str, now: SystemTime) -> String {
    const SERVICE: &str = "iotdevicegateway";
    let (date, stamp) = amz_dates(now);
    let credential = uri_encode(
        &format!("{}/{date}/{region}/{SERVICE}/aws4_request", creds.access_key_id),
        false,
    );
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={credential}&X-Amz-Date={stamp}&X-Amz-SignedHeaders=host"
    );
    let canonical_request = format!("GET\n/mqtt\n{query}\nhost:{host}\n\nhost\n{}", sha256_hex(b""));
    let sig = signature(creds, &stamp, region, SERVICE, &canonical_request);
    let mut url = format!("wss://{host}/mqtt?{query}&X-Amz-Signature={sig}");
    // AWS IoT wants the session token outside the signed query.
    if !creds.session_token.is_empty() {
        url.push_str(&format!(
            "&X-Amz-Security-Token={}",
            uri_encode(&creds.session_token, false)
        ));
    }
    url
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// 2015-08-30T12:36:00Z, the date of the AWS SigV4 test suite.
    fn suite_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_440_938_160)
    }

    fn example_creds(token: &str) -> AwsCredentials {
        AwsCredentials {
            identity_id: String::new(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: token.into(),
            expiration_ms: 0,
        }
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
        &headers.iter().find(|(k, _)| k == name).unwrap().1
    }

    #[test]
    fn dates_are_formatted_in_utc() {
        assert_eq!(amz_dates(suite_time()), ("20150830".into(), "20150830T123600Z".into()));
        assert_eq!(amz_dates(UNIX_EPOCH).1, "19700101T000000Z");
        // 2024-02-29T23:59:59Z: leap day.
        assert_eq!(
            amz_dates(UNIX_EPOCH + Duration::from_secs(1_709_251_199)).1,
            "20240229T235959Z"
        );
    }

    #[test]
    fn get_vanilla_matches_the_aws_test_suite() {
        let headers = sign(
            &example_creds(""),
            "us-east-1",
            "service",
            "GET",
            "http://example.amazonaws.com/",
            b"",
            suite_time(),
        )
        .unwrap();
        assert_eq!(header(&headers, "x-amz-date"), "20150830T123600Z");
        assert_eq!(
            header(&headers, "authorization"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn post_signs_content_type_token_and_sorted_query() {
        // The signature was computed independently with Python's hmac/hashlib.
        let headers = sign(
            &example_creds("TOKEN"),
            "us-west-2",
            "execute-api",
            "POST",
            "https://api.example.com/teleport?b=2&a=1",
            br#"{"a":1}"#,
            suite_time(),
        )
        .unwrap();
        assert_eq!(header(&headers, "x-amz-security-token"), "TOKEN");
        assert_eq!(header(&headers, "content-type"), "application/json");
        assert_eq!(
            header(&headers, "authorization"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-west-2/execute-api/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, \
             Signature=7b8d58909a7833f09963c210fc695fc53d7172c1e08e891d06e79dce39a2bf6c"
        );
    }

    #[test]
    fn presigned_iot_url_shape() {
        let url = presign_iot_url(&example_creds("a/b+c"), "us-east-1", "iot.example.com", suite_time());
        assert_eq!(
            url,
            "wss://iot.example.com/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiotdevicegateway%2Faws4_request\
             &X-Amz-Date=20150830T123600Z&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=8a5b2c8a640145d2fdd677c3c47cfd512c9a64e34ae54714047db00352d03375\
             &X-Amz-Security-Token=a%2Fb%2Bc"
        );
    }
}
