//! Asking a console for access: an HTTP request tunneled (ucp4) through AWS IoT MQTT over WebSocket.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant, SystemTime};

use flate2::Compression;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use flate2::write::ZlibEncoder;
use serde_json::{Value, json};
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::http::clip;
use crate::sso::uuid_v4;
use crate::{AccessGrant, AwsCredentials, CloudConfig, Result, aws};

const ACCESS_REQUEST_PATH: &str = "/proxy/network/v2/api/site/default/teleport/access-request";
const TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_SECS: u16 = 30;

// ---- ucp4: [b0][b1][b2][00][u32 big-endian length] + zlib(JSON), an envelope frame then a body frame ----

const HEADER_LEN: usize = 8;
const INFLATE_MAX: u64 = 1 << 20;

// `types` and `length` are only checked by the tests of the wire format.
#[cfg_attr(not(test), allow(dead_code))]
struct Frame {
    types: [u8; 3],
    /// The declared length; the body is shorter when the payload was cut off.
    length: usize,
    raw: Vec<u8>,
}

/// Splits a payload into frames, stopping after a truncated one.
fn frames(payload: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + HEADER_LEN <= payload.len() {
        let length = u32::from_be_bytes(payload[i + 4..i + 8].try_into().expect("4 bytes")) as usize;
        let start = i + HEADER_LEN;
        let raw = payload[start..payload.len().min(start.saturating_add(length))].to_vec();
        let complete = raw.len() == length;
        out.push(Frame {
            types: [payload[i], payload[i + 1], payload[i + 2]],
            length,
            raw,
        });
        if !complete {
            break;
        }
        i = start + length;
    }
    out
}

/// Inflates zlib, falling back to raw DEFLATE as the reference does.
fn inflate(chunk: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // A console's answer is a few hundred bytes; the cap is against a zlib bomb.
    if ZlibDecoder::new(chunk).take(INFLATE_MAX).read_to_end(&mut out).is_ok() {
        return Ok(out);
    }
    out.clear();
    DeflateDecoder::new(chunk)
        .take(INFLATE_MAX)
        .read_to_end(&mut out)
        .map_err(|_| "ucp4: frame is not compressed JSON")?;
    Ok(out)
}

fn frame(body: &Value, types: [u8; 3]) -> Result<Vec<u8>> {
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(body.to_string().as_bytes())?;
    let compressed = zlib.finish()?;
    let mut out = vec![types[0], types[1], types[2], 0];
    out.extend(u32::try_from(compressed.len())?.to_be_bytes());
    out.extend(compressed);
    Ok(out)
}

pub fn encode_http_request(method: &str, path: &str, body: &Value, req_id: &str) -> Result<Vec<u8>> {
    let envelope = json!({
        "method": method,
        "path": path,
        "id": req_id,
        "type": "httpRequest",
        "headers": {"content-type": "application/json"},
    });
    let mut out = frame(&envelope, [1, 1, 1])?;
    out.extend(frame(body, [2, 3, 1])?);
    Ok(out)
}

/// `(envelope, body)`; either is `{}` when its frame is absent or blank.
pub fn decode_http_response(payload: &[u8]) -> Result<(Value, Value)> {
    let parts = frames(payload)
        .iter()
        .map(|f| inflate(&f.raw))
        .collect::<Result<Vec<_>>>()?;
    let envelope = match parts.first() {
        Some(p) => serde_json::from_slice(p).map_err(|_| "ucp4: envelope is not JSON")?,
        None => json!({}),
    };
    let body = match parts.get(1) {
        Some(p) if !p.trim_ascii().is_empty() => serde_json::from_slice(p).map_err(|_| "ucp4: body is not JSON")?,
        _ => json!({}),
    };
    Ok((envelope, body))
}

// ---- MQTT 3.1.1, only what one request/response needs ----

const DISCONNECT: [u8; 2] = [0xE0, 0];

fn remaining_length(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n % 128) as u8;
        n /= 128;
        out.push(if n > 0 { byte | 0x80 } else { byte });
        if n == 0 {
            return out;
        }
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend((s.len() as u16).to_be_bytes());
    out.extend(s.as_bytes());
}

fn packet(first_byte: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = vec![first_byte];
    out.extend(remaining_length(body.len()));
    out.extend(body);
    out
}

/// CONNECT with a clean session and no credentials: AWS IoT authorizes through the WebSocket URL.
fn connect_packet(client_id: &str, keep_alive: u16) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 0x02];
    body.extend(keep_alive.to_be_bytes());
    put_str(&mut body, client_id);
    packet(0x10, body)
}

fn subscribe_packet(id: u16, topic: &str) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    put_str(&mut body, topic);
    body.push(1); // QoS 1
    packet(0x82, body)
}

fn publish_packet(id: u16, topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put_str(&mut body, topic);
    body.extend(id.to_be_bytes());
    body.extend(payload);
    packet(0x32, body) // PUBLISH, QoS 1
}

fn puback_packet(id: u16) -> Vec<u8> {
    packet(0x40, id.to_be_bytes().to_vec())
}

#[derive(Debug, PartialEq)]
enum Packet {
    ConnAck {
        code: u8,
    },
    SubAck {
        id: u16,
        code: u8,
    },
    Publish {
        topic: String,
        id: Option<u16>,
        payload: Vec<u8>,
    },
    PubAck {
        id: u16,
    },
    Other,
}

fn parse_body(first_byte: u8, body: &[u8]) -> Option<Packet> {
    let id_at = |i: usize| Some(u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]));
    Some(match first_byte >> 4 {
        2 => Packet::ConnAck { code: *body.get(1)? },
        9 => Packet::SubAck {
            id: id_at(0)?,
            code: *body.get(2)?,
        },
        4 => Packet::PubAck { id: id_at(0)? },
        3 => {
            let topic_len = usize::from(id_at(0)?);
            let topic = String::from_utf8(body.get(2..2 + topic_len)?.to_vec()).ok()?;
            let qos = first_byte >> 1 & 3;
            let start = 2 + topic_len + if qos > 0 { 2 } else { 0 };
            let id = if qos > 0 { id_at(2 + topic_len) } else { None };
            Packet::Publish {
                topic,
                id,
                payload: body.get(start..)?.to_vec(),
            }
        }
        _ => Packet::Other,
    })
}

/// Removes and returns the first complete packet in `buf`, or `None` if more bytes are needed.
fn take_packet(buf: &mut Vec<u8>) -> Result<Option<Packet>> {
    let mut len = 0usize;
    let mut header = 1;
    loop {
        let Some(&byte) = buf.get(header) else { return Ok(None) };
        len |= usize::from(byte & 0x7f) << (7 * (header - 1));
        header += 1;
        if byte & 0x80 == 0 {
            break;
        }
        if header > 4 {
            return Err("MQTT: remaining length is longer than 4 bytes".into());
        }
    }
    // Nothing the broker sends here is near this size; do not buffer whatever it claims.
    if len as u64 > INFLATE_MAX {
        return Err("MQTT: packet is too large".into());
    }
    if buf.len() < header + len {
        return Ok(None);
    }
    let first_byte = buf[0];
    let parsed = parse_body(first_byte, &buf[header..header + len]);
    buf.drain(..header + len);
    parsed.map(Some).ok_or_else(|| "MQTT: malformed packet".into())
}

struct Mqtt {
    ws: WebSocket<MaybeTlsStream<TcpStream>>,
    /// A handle on the same socket, to change its read timeout under the TLS layer.
    tcp: TcpStream,
    buf: Vec<u8>,
}

impl Mqtt {
    fn open(host: &str, url: &str) -> Result<Mqtt> {
        let tcp = (host, 443)
            .to_socket_addrs()?
            .find_map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(10)).ok())
            .ok_or("AWS IoT MQTT connect failed: cannot reach the host")?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(TIMEOUT))?;
        tcp.set_write_timeout(Some(TIMEOUT))?;
        let mut request = url
            .into_client_request()
            .map_err(|_| "AWS IoT MQTT connect failed: bad URL")?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("mqtt"));
        // The error text is the handshake's, never the URL, which carries the signature and token.
        let (ws, _) = tungstenite::client_tls(request, tcp.try_clone()?)
            .map_err(|e| format!("AWS IoT MQTT connect failed: {e}"))?;
        Ok(Mqtt {
            ws,
            tcp,
            buf: Vec::new(),
        })
    }

    fn send(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.ws.send(Message::Binary(bytes.into()))?;
        Ok(())
    }

    fn next_packet(&mut self, deadline: Instant) -> Result<Packet> {
        loop {
            if let Some(p) = take_packet(&mut self.buf)? {
                return Ok(p);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("MQTT: timed out waiting for the broker".into());
            }
            self.tcp.set_read_timeout(Some(left))?;
            match self.ws.read() {
                Ok(Message::Binary(b)) => self.buf.extend_from_slice(&b),
                Ok(Message::Close(_)) => return Err("MQTT: the broker closed the connection".into()),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
                {
                    return Err("MQTT: timed out waiting for the broker".into());
                }
                Err(e) => return Err(format!("MQTT: {e}").into()),
            }
        }
    }

    /// Reads packets until `want` accepts one, acknowledging any QoS 1 PUBLISH on the way.
    fn wait_for<T>(&mut self, deadline: Instant, mut want: impl FnMut(&Packet) -> Option<T>) -> Result<T> {
        loop {
            let p = self.next_packet(deadline)?;
            if let Packet::Publish { id: Some(id), .. } = &p {
                self.send(puback_packet(*id))?;
            }
            if let Some(found) = want(&p) {
                return Ok(found);
            }
        }
    }
}

/// Publishes the ucp4 request and returns the first message on the response topic.
fn exchange(
    mqtt: &mut Mqtt,
    client_id: &str,
    request_topic: &str,
    response_topic: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let deadline = Instant::now() + TIMEOUT;
    mqtt.send(connect_packet(client_id, KEEP_ALIVE_SECS))?;
    match mqtt.wait_for(deadline, |p| match p {
        Packet::ConnAck { code } => Some(*code),
        _ => None,
    })? {
        0 => {}
        code => return Err(format!("AWS IoT MQTT connect refused (code {code})").into()),
    }
    mqtt.send(subscribe_packet(1, response_topic))?;
    // 0x80 is the broker's refusal; 0 and 1 are the granted QoS.
    let granted = mqtt.wait_for(deadline, |p| match p {
        Packet::SubAck { id: 1, code } => Some(*code),
        _ => None,
    })?;
    if granted == 0x80 {
        return Err("MQTT subscribe was refused".into());
    }
    mqtt.send(publish_packet(2, request_topic, payload))?;
    let deadline = Instant::now() + TIMEOUT;
    mqtt.wait_for(deadline, |p| match p {
        Packet::Publish { topic, payload, .. } if topic == response_topic => Some(payload.clone()),
        _ => None,
    })
    .map_err(|e| format!("no ucp4 response on the console topic: {e}").into())
}

pub fn access_request(
    cloud: &CloudConfig,
    creds: &AwsCredentials,
    console_id: &str,
    client_id: &str,
    client_name: &str,
) -> Result<AccessGrant> {
    let req_id = uuid_v4()?;
    let identity = &creds.identity_id;
    let request_topic = format!("client/{identity}/device/{console_id}/ucp4/{req_id}");
    let response_topic = format!("client/{identity}/{console_id}/ucp4/{req_id}");
    let payload = encode_http_request(
        "POST",
        ACCESS_REQUEST_PATH,
        &json!({"client_id": client_id, "client_name": client_name}),
        &req_id,
    )?;

    let url = aws::presign_iot_url(creds, &cloud.iot_region, &cloud.mqtt_host, SystemTime::now());
    let mut mqtt = Mqtt::open(&cloud.mqtt_host, &url)?;
    let answer = exchange(
        &mut mqtt,
        &format!("teleporter-{}", uuid_v4()?),
        &request_topic,
        &response_topic,
        &payload,
    );
    // Best effort: the answer, or the reason there is none, matters more than a clean goodbye.
    let _ = mqtt.send(DISCONNECT.to_vec());
    let _ = mqtt.ws.close(None);

    let (envelope, body) = decode_http_response(&answer?)?;
    parse_grant(&envelope, &body)
}

fn parse_grant(envelope: &Value, body: &Value) -> Result<AccessGrant> {
    match envelope.get("statusCode") {
        None | Some(Value::Null) => {}
        Some(code) if code.as_u64() == Some(200) => {}
        Some(code) => {
            return Err(format!("POST {ACCESS_REQUEST_PATH} -> HTTP {code}: {}", clip(&body.to_string())).into());
        }
    }
    let field = |name: &str| body.get(name).and_then(Value::as_str).filter(|s| !s.is_empty());
    match (field("secret"), field("token")) {
        (Some(secret), Some(token)) => Ok(AccessGrant {
            secret: secret.into(),
            token: token.into(),
        }),
        _ => Err("access-request returned a body without secret and token".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_frame(raw_body: &[u8], types: [u8; 3]) -> Vec<u8> {
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(raw_body).unwrap();
        let compressed = zlib.finish().unwrap();
        let mut out = vec![types[0], types[1], types[2], 0];
        out.extend((compressed.len() as u32).to_be_bytes());
        out.extend(compressed);
        out
    }

    fn json_frame(v: Value, types: [u8; 3]) -> Vec<u8> {
        build_frame(v.to_string().as_bytes(), types)
    }

    #[test]
    fn request_is_two_frames_with_type_bytes() {
        let payload = encode_http_request("POST", "/api/thing", &json!({"k": "v"}), "req-1").unwrap();
        let f = frames(&payload);
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].types, f[1].types), ([1, 1, 1], [2, 3, 1]));
    }

    #[test]
    fn request_envelope_round_trips() {
        let payload = encode_http_request("PUT", "/x/y", &json!({"a": 1, "b": [2, 3]}), "abc").unwrap();
        let (envelope, body) = decode_http_response(&payload).unwrap();
        assert_eq!(
            envelope,
            json!({"method": "PUT", "path": "/x/y", "id": "abc", "type": "httpRequest",
                   "headers": {"content-type": "application/json"}})
        );
        assert_eq!(body, json!({"a": 1, "b": [2, 3]}));
    }

    #[test]
    fn declared_length_matches_the_compressed_body() {
        for f in frames(&encode_http_request("GET", "/p", &json!({}), "id0").unwrap()) {
            assert_eq!(f.length, f.raw.len());
            serde_json::from_slice::<Value>(&inflate(&f.raw).unwrap()).unwrap();
        }
    }

    #[test]
    fn response_decodes_to_envelope_and_body() {
        let mut payload = json_frame(
            json!({"statusCode": 200, "type": "httpResponse", "headers": {}}),
            [1, 1, 1],
        );
        payload.extend(json_frame(json!({"ok": true, "data": [1, 2, 3]}), [2, 3, 1]));
        let (envelope, body) = decode_http_response(&payload).unwrap();
        assert_eq!(envelope["statusCode"], 200);
        assert_eq!(envelope["type"], "httpResponse");
        assert_eq!(body, json!({"ok": true, "data": [1, 2, 3]}));
    }

    #[test]
    fn missing_or_blank_body_frame_is_an_empty_object() {
        let env = json_frame(json!({"statusCode": 404}), [1, 1, 1]);
        assert_eq!(
            decode_http_response(&env).unwrap(),
            (json!({"statusCode": 404}), json!({}))
        );
        let mut blank = env.clone();
        blank.extend(build_frame(b"   ", [2, 3, 1]));
        assert_eq!(decode_http_response(&blank).unwrap().1, json!({}));
        assert_eq!(decode_http_response(b"").unwrap(), (json!({}), json!({})));
    }

    #[test]
    fn inflate_accepts_raw_deflate() {
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
        raw.write_all(br#"{"x":1}"#).unwrap();
        assert_eq!(inflate(&raw.finish().unwrap()).unwrap(), br#"{"x":1}"#);
        assert!(inflate(b"not compressed").is_err());
    }

    #[test]
    fn truncated_frame_ends_the_iteration() {
        let mut payload = json_frame(json!({"statusCode": 200}), [1, 1, 1]);
        let body = json_frame(json!({"big": "payload"}), [2, 3, 1]);
        payload.extend(&body[..body.len() - 4]);
        let f = frames(&payload);
        assert_eq!(f.len(), 2);
        assert!(f[1].raw.len() < f[1].length);
        assert!(decode_http_response(&payload).is_err());
    }

    #[test]
    fn dangling_partial_header_is_not_a_frame() {
        let mut payload = json_frame(json!({"statusCode": 200}), [1, 1, 1]);
        payload.extend([1, 2]);
        assert_eq!(frames(&payload).len(), 1);
    }

    #[test]
    fn remaining_length_is_a_varint() {
        for (n, bytes) in [
            (0, &[0x00][..]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (16_383, &[0xff, 0x7f]),
            (16_384, &[0x80, 0x80, 0x01]),
        ] {
            assert_eq!(remaining_length(n), bytes, "{n}");
        }
    }

    #[test]
    fn connect_packet_is_clean_session_with_keep_alive() {
        assert_eq!(
            connect_packet("c1", 30),
            [0x10, 14, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 30, 0, 2, b'c', b'1']
        );
    }

    #[test]
    fn subscribe_packet_asks_for_qos_1() {
        assert_eq!(subscribe_packet(1, "a/b"), [0x82, 8, 0, 1, 0, 3, b'a', b'/', b'b', 1]);
    }

    #[test]
    fn publish_round_trips_even_with_a_long_payload() {
        let payload = vec![7u8; 300]; // needs a two-byte remaining length
        let mut buf = publish_packet(9, "t/1", &payload);
        assert_eq!(buf[0], 0x32);
        assert_eq!(
            take_packet(&mut buf).unwrap(),
            Some(Packet::Publish {
                topic: "t/1".into(),
                id: Some(9),
                payload
            })
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn packets_are_taken_one_at_a_time_and_partial_ones_wait() {
        let mut buf = vec![0x20, 2, 0, 0, 0x90, 3, 0, 1, 1, 0x40, 2, 0, 5];
        assert_eq!(take_packet(&mut buf).unwrap(), Some(Packet::ConnAck { code: 0 }));
        assert_eq!(take_packet(&mut buf).unwrap(), Some(Packet::SubAck { id: 1, code: 1 }));
        assert_eq!(take_packet(&mut buf).unwrap(), Some(Packet::PubAck { id: 5 }));
        assert_eq!(take_packet(&mut buf).unwrap(), None);
        let mut half = publish_packet(1, "t", b"abc");
        half.pop();
        assert_eq!(take_packet(&mut half).unwrap(), None);
        assert_eq!(half.len(), 9, "an incomplete packet is left alone");
        assert!(take_packet(&mut vec![0x30, 0x80, 0x80, 0x80, 0x80, 1]).is_err());
        assert!(take_packet(&mut vec![0x20, 1, 0]).is_err());
    }

    #[test]
    fn qos_0_publish_has_no_packet_id() {
        let mut buf = vec![0x30, 7, 0, 3, b't', b'/', b'x', b'h', b'i'];
        assert_eq!(
            take_packet(&mut buf).unwrap(),
            Some(Packet::Publish {
                topic: "t/x".into(),
                id: None,
                payload: b"hi".to_vec()
            })
        );
    }

    #[test]
    fn puback_acknowledges_the_packet_id() {
        assert_eq!(puback_packet(0x0102), [0x40, 2, 1, 2]);
    }

    #[test]
    fn grant_needs_secret_and_token_and_a_good_status() {
        let ok = json!({"statusCode": 200});
        let body = json!({"secret": "s", "token": "t"});
        assert_eq!(
            parse_grant(&ok, &body).unwrap(),
            AccessGrant {
                secret: "s".into(),
                token: "t".into()
            }
        );
        assert!(parse_grant(&json!({}), &body).is_ok());
        assert!(parse_grant(&json!({"statusCode": 403}), &body).is_err());
        assert!(parse_grant(&ok, &json!({"secret": "s"})).is_err());
        assert!(parse_grant(&ok, &json!({"secret": "", "token": "t"})).is_err());
    }
}
