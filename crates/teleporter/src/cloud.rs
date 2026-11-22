//! Ubiquiti's cloud: where it lives, which consoles an account has, and the ICE/connect RPCs.

use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};

use crate::http::{Reply, clip, request};
use crate::{
    AccessGrant, AwsCredentials, Candidate, ClientOffer, CloudConfig, ConnectResult, Console, IceServer, Net, Result,
    aws,
};

const CONFIG_URL: &str = "https://config.ubnt.com/cloudAccessConfig.json";
const HOSTS_PATH: &str = "/network-cloud/v2/sd-wan/hosts?withVpnConf=true";
const SERVICE: &str = "execute-api";
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

fn str_at<'a>(j: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut v = j;
    for key in path {
        v = v.get(key).unwrap_or(&Value::Null);
    }
    match v.as_str() {
        Some(s) => Ok(s),
        None => Err(format!("cloudAccessConfig.json: missing {}", path.join(".")).into()),
    }
}

fn parse_config(j: &Value) -> Result<CloudConfig> {
    let root = ["unifiCloudAccess"];
    let at = |rest: &[&str]| str_at(j, &[&root[..], rest].concat()).map(str::to_string);
    let config = CloudConfig {
        region: at(&["region"])?,
        iot_region: at(&["iot", "region"])?,
        mqtt_host: at(&["iot", "host"])?,
        api_gateway_ui: at(&["apiGatewayUI", "url"])?,
    };
    // The session cookie and the AWS credentials are sent to these hosts, so a
    // tampered config must not be able to name somebody else's.
    let ours = |host: &str, domains: &[&str]| {
        let clean = host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        clean && domains.iter().any(|d| host.ends_with(d))
    };
    let api_host = config.api_gateway_ui.strip_prefix("https://").unwrap_or("");
    if !ours(api_host, &[".ui.com", ".ubnt.com"]) || !ours(&config.mqtt_host, &[".amazonaws.com", ".ui.com"]) {
        return Err("cloudAccessConfig.json names a host that is not Ubiquiti's".into());
    }
    Ok(config)
}

pub fn fetch_config() -> Result<CloudConfig> {
    let reply = request("GET", CONFIG_URL, &[], None)?;
    if reply.status != 200 {
        return Err(format!("cloudAccessConfig.json -> HTTP {}", reply.status).into());
    }
    parse_config(&serde_json::from_str(&reply.body).map_err(|_| "cloudAccessConfig.json: body is not JSON")?)
}

/// A SigV4-signed call to the API gateway; `body` is JSON.
fn signed(cloud: &CloudConfig, creds: &AwsCredentials, method: &str, url: &str, body: Option<&Value>) -> Result<Reply> {
    let body = body.map(|b| b.to_string().into_bytes());
    let headers = aws::sign(
        creds,
        &cloud.region,
        SERVICE,
        method,
        url,
        body.as_deref().unwrap_or(b""),
        SystemTime::now(),
    )?;
    request(method, url, &headers, body.as_deref())
}

fn truthy_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn parse_consoles(j: &Value) -> Vec<Console> {
    let hosts = j.get("data").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    hosts
        .iter()
        .filter(|h| !truthy_str(h, "hostId").is_empty())
        .map(|h| {
            let id = truthy_str(h, "hostId");
            let site = h.get("sites").and_then(|s| s.get(0)).unwrap_or(&Value::Null);
            let networks = site
                .get("networks")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice);
            let subnets = networks
                .iter()
                .filter(|n| {
                    n.get("routingAllowed").and_then(Value::as_bool) == Some(true)
                        && !truthy_str(n, "routerIp").is_empty()
                        // The Teleport network is the tunnel's own plumbing, never a destination.
                        && !truthy_str(n, "networkName").eq_ignore_ascii_case("teleport")
                })
                .filter_map(|n| truthy_str(n, "subnet").parse::<Net>().ok())
                .collect();
            Console {
                id: id.to_string(),
                name: h.get("hostName").and_then(Value::as_str).unwrap_or(id).to_string(),
                online: truthy_str(h, "connectionState") == "CONNECTED",
                subnets,
                public_ip: truthy_str(site, "publicIp").to_string(),
            }
        })
        .collect()
}

pub fn consoles(cloud: &CloudConfig, creds: &AwsCredentials) -> Result<Vec<Console>> {
    let url = format!("{}{HOSTS_PATH}", cloud.api_gateway_ui.trim_end_matches('/'));
    let reply = signed(cloud, creds, "GET", &url, None)?;
    if reply.status != 200 {
        return Err(format!("sd-wan/hosts -> HTTP {}: {}", reply.status, clip(&reply.body)).into());
    }
    Ok(parse_consoles(
        &serde_json::from_str(&reply.body).map_err(|_| "sd-wan/hosts: body is not JSON")?,
    ))
}

/// Submits one RPC and polls for its answer.
fn rpc(
    cloud: &CloudConfig,
    creds: &AwsCredentials,
    grant: &AccessGrant,
    request_type: &str,
    mut payload: Value,
) -> Result<Value> {
    payload["request_type"] = request_type.into();
    let body = json!({"token": grant.token, "payload": payload});
    let base = cloud.api_gateway_ui.trim_end_matches('/');

    let mut submitted = None;
    for attempt in 0..3 {
        // The cloud POST is occasionally slow; retry transport errors like the reference.
        match signed(cloud, creds, "POST", &format!("{base}/teleport"), Some(&body)) {
            Ok(reply) => {
                submitted = Some(reply);
                break;
            }
            Err(e) if attempt == 2 => return Err(format!("{request_type} submit failed after retries: {e}").into()),
            Err(_) => {}
        }
    }
    let reply = submitted.expect("the loop returns or sets a reply");
    if reply.status != 200 {
        return Err(format!("{request_type} submit -> HTTP {}: {}", reply.status, clip(&reply.body)).into());
    }
    let id = serde_json::from_str::<Value>(&reply.body)
        .ok()
        .and_then(|j| {
            j.get("teleportRequestId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .ok_or_else(|| format!("{request_type}: no teleportRequestId in {}", clip(&reply.body)))?;
    poll(cloud, creds, request_type, &format!("{base}/teleport/{id}"))
}

fn poll(cloud: &CloudConfig, creds: &AwsCredentials, request_type: &str, url: &str) -> Result<Value> {
    let deadline = Instant::now() + RPC_TIMEOUT;
    let mut last = String::new();
    while Instant::now() < deadline {
        match signed(cloud, creds, "GET", url, None) {
            Err(e) => last = format!("http error: {e}"),
            Ok(reply) if reply.status == 200 => match serde_json::from_str::<Value>(&reply.body) {
                Ok(j)
                    if j.get("response_type")
                        .and_then(Value::as_str)
                        .is_some_and(|t| !t.is_empty()) =>
                {
                    return Ok(j);
                }
                _ => last = reply.body.chars().take(160).collect(),
            },
            Ok(reply) if [404, 202, 204].contains(&reply.status) => {}
            Ok(reply) => {
                return Err(format!("{request_type} poll -> HTTP {}: {}", reply.status, clip(&reply.body)).into());
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(format!(
        "{request_type} timed out after {}s (last: {last})",
        RPC_TIMEOUT.as_secs()
    )
    .into())
}

fn parse_ice(j: &Value) -> Vec<IceServer> {
    let servers = j
        .get("ice_configuration")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    servers
        .iter()
        .map(|s| IceServer {
            urls: s.get("urls").and_then(Value::as_array).map_or(vec![], |u| {
                u.iter().filter_map(Value::as_str).map(str::to_string).collect()
            }),
            username: truthy_str(s, "username").to_string(),
            credential: truthy_str(s, "credential").to_string(),
        })
        .collect()
}

pub fn ice_configuration(cloud: &CloudConfig, creds: &AwsCredentials, grant: &AccessGrant) -> Result<Vec<IceServer>> {
    let j = rpc(
        cloud,
        creds,
        grant,
        "GET_ICE_CONFIGURATION",
        json!({"secret": grant.secret}),
    )?;
    Ok(parse_ice(&j))
}

fn parse_candidates(j: &Value) -> Result<Vec<Candidate>> {
    let list = j
        .get("candidates")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    list.iter()
        .map(|c| {
            match (
                c.get("type").and_then(Value::as_str),
                c.get("addr").and_then(Value::as_str),
            ) {
                (Some(kind), Some(addr)) => Ok(Candidate {
                    kind: kind.into(),
                    addr: addr.into(),
                }),
                _ => Err("CONNECT: candidate without type or addr".into()),
            }
        })
        .collect()
}

fn parse_connect(j: &Value) -> Result<ConnectResult> {
    let info = j.get("server_info").unwrap_or(&Value::Null);
    let peer = info.get("peer_desc").unwrap_or(&Value::Null);
    Ok(ConnectResult {
        server_wg_public_key: truthy_str(info, "wg_pub_key").to_string(),
        client_ip: truthy_str(j, "client_ip").to_string(),
        dns_addrs: j.get("dns_addrs").and_then(Value::as_array).map_or(vec![], |a| {
            a.iter().filter_map(Value::as_str).map(str::to_string).collect()
        }),
        remote_candidates: parse_candidates(peer)?,
        is_master: peer.get("is_master").and_then(Value::as_bool).unwrap_or(true),
        udp_echo_addr: truthy_str(info, "udp_echo_addr").to_string(),
        udp_echo_port: info
            .get("udp_echo_port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0),
        tunnel_addr: truthy_str(info, "tunnel_addr").to_string(),
        tunnel_mask: info
            .get("tunnel_mask")
            .and_then(Value::as_u64)
            .and_then(|m| u8::try_from(m).ok())
            .unwrap_or(0),
    })
}

pub fn connect(
    cloud: &CloudConfig,
    creds: &AwsCredentials,
    grant: &AccessGrant,
    client_name: &str,
    offer: &ClientOffer,
) -> Result<ConnectResult> {
    parse_connect(&rpc(
        cloud,
        creds,
        grant,
        "CONNECT",
        connect_payload(grant, client_name, offer),
    )?)
}

fn connect_payload(grant: &AccessGrant, client_name: &str, offer: &ClientOffer) -> Value {
    json!({
        "secret": grant.secret,
        "client_name": client_name,
        "client_info": {
            "wg_pub_key": offer.wg_public_key,
            "peer_desc": {
                "candidates": offer.candidates,
                "ice_config": offer.ice_servers,
                // The console is the controlling ICE agent.
                "is_master": false,
            },
            "stun_session_secret": offer.stun_session_secret,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    #[test]
    fn config_is_parsed_from_the_live_shape() {
        let j = json!({"unifiCloudAccess": {
            "region": "us-west-2", "accountId": "1",
            "iot": {"region": "us-east-1", "mqttHost": "nca.example", "host": "a1-ats.iot.us-west-2.amazonaws.com"},
            "apiGateway": {"url": "https://cloudaccess.svc.ubnt.com"},
            "apiGatewayUI": {"url": "https://cloudaccess.svc.ui.com"},
        }});
        assert_eq!(
            parse_config(&j).unwrap(),
            CloudConfig {
                region: "us-west-2".into(),
                iot_region: "us-east-1".into(),
                mqtt_host: "a1-ats.iot.us-west-2.amazonaws.com".into(),
                api_gateway_ui: "https://cloudaccess.svc.ui.com".into(),
            }
        );
    }

    #[test]
    fn config_naming_a_foreign_host_is_refused() {
        let config = |api: &str, mqtt: &str| {
            parse_config(&json!({"unifiCloudAccess": {
                "region": "r", "iot": {"region": "r", "host": mqtt}, "apiGatewayUI": {"url": api},
            }}))
        };
        assert!(config("https://cloudaccess.svc.ui.com", "a1-ats.iot.us-west-2.amazonaws.com").is_ok());
        for api in [
            "http://cloudaccess.svc.ui.com",
            "https://evil.example",
            "https://evil.example/x.ui.com",
            "https://ui.com@evil.example",
        ] {
            assert!(config(api, "a.amazonaws.com").is_err(), "{api}");
        }
        assert!(config("https://cloudaccess.svc.ui.com", "evil.example").is_err());
    }

    #[test]
    fn config_names_the_missing_key() {
        let j = json!({"unifiCloudAccess": {"region": "r", "iot": {"region": "r", "host": "h"}}});
        assert_eq!(
            parse_config(&j).unwrap_err().to_string(),
            "cloudAccessConfig.json: missing unifiCloudAccess.apiGatewayUI.url"
        );
    }

    #[test]
    fn consoles_keep_routable_lans_only() {
        let j = json!({"data": [
            {"hostId": "EXAMPLECONSOLEID:000000000", "hostName": "My Console", "connectionState": "CONNECTED",
             "sites": [{"wanIp": "203.0.113.10", "publicIp": "203.0.113.11", "networks": [
                {"networkName": "Default", "subnet": "10.20.0.0/24", "routerIp": "10.20.0.1", "routingAllowed": true},
                {"networkName": "IoT", "subnet": "10.20.30.7/24", "routerIp": "10.20.30.1", "routingAllowed": true},
                {"networkName": "Guest", "subnet": "10.20.40.0/24", "routerIp": "10.20.40.1", "routingAllowed": false},
                {"networkName": "NoGateway", "subnet": "10.20.50.0/24", "routingAllowed": true},
                {"networkName": "Broken", "subnet": "not-a-subnet", "routerIp": "10.20.60.1", "routingAllowed": true},
                {"networkName": "TELEPORT", "subnet": "192.0.2.0/24", "routerIp": "192.0.2.1", "routingAllowed": true}]}]},
            {"hostId": "OTHER:1", "connectionState": "DISCONNECTED"},
            {"hostName": "no id"}
        ]});
        assert_eq!(
            parse_consoles(&j),
            [
                Console {
                    id: "EXAMPLECONSOLEID:000000000".into(),
                    name: "My Console".into(),
                    online: true,
                    subnets: vec![net("10.20.0.0/24"), net("10.20.30.0/24")],
                    public_ip: "203.0.113.11".into(),
                },
                Console {
                    id: "OTHER:1".into(),
                    name: "OTHER:1".into(),
                    online: false,
                    subnets: vec![],
                    public_ip: String::new(),
                },
            ]
        );
        assert_eq!(parse_consoles(&json!({})), []);
    }

    #[test]
    fn ice_servers_default_missing_credentials() {
        let j = json!({"response_type": "ICE_CONFIGURATION", "ice_configuration": [
            {"urls": ["stun:stun.example.net:3478"]},
            {"urls": ["turn:turn.example.net:3478?transport=udp"], "username": "u", "credential": "c"}]});
        assert_eq!(
            parse_ice(&j),
            [
                IceServer {
                    urls: vec!["stun:stun.example.net:3478".into()],
                    username: String::new(),
                    credential: String::new()
                },
                IceServer {
                    urls: vec!["turn:turn.example.net:3478?transport=udp".into()],
                    username: "u".into(),
                    credential: "c".into()
                },
            ]
        );
        assert_eq!(parse_ice(&json!({"response_type": "ICE_CONFIGURATION"})), []);
    }

    #[test]
    fn connect_answer_is_parsed() {
        let j = json!({"response_type": "CONNECT", "client_ip": "10.99.0.2", "dns_addrs": ["10.99.0.1"],
            "server_info": {"wg_pub_key": "SRV=", "tunnel_addr": "10.99.0.0", "tunnel_mask": 24,
                "udp_echo_addr": "203.0.113.5", "udp_echo_port": 51820,
                "peer_desc": {"is_master": false, "candidates": [
                    {"type": "iface", "addr": "192.0.2.20:51820"}, {"type": "reflex", "addr": "203.0.113.5:51820"}]}}});
        assert_eq!(
            parse_connect(&j).unwrap(),
            ConnectResult {
                server_wg_public_key: "SRV=".into(),
                client_ip: "10.99.0.2".into(),
                dns_addrs: vec!["10.99.0.1".into()],
                remote_candidates: vec![
                    Candidate {
                        kind: "iface".into(),
                        addr: "192.0.2.20:51820".into()
                    },
                    Candidate {
                        kind: "reflex".into(),
                        addr: "203.0.113.5:51820".into()
                    },
                ],
                is_master: false,
                udp_echo_addr: "203.0.113.5".into(),
                udp_echo_port: 51820,
                tunnel_addr: "10.99.0.0".into(),
                tunnel_mask: 24,
            }
        );
    }

    #[test]
    fn connect_offer_has_the_wire_shape() {
        let grant = AccessGrant {
            secret: "s".into(),
            token: "t".into(),
        };
        let offer = ClientOffer {
            wg_public_key: "CLI=".into(),
            candidates: vec![Candidate {
                kind: "iface".into(),
                addr: "192.0.2.10:51820".into(),
            }],
            ice_servers: vec![IceServer {
                urls: vec!["stun:x:3478".into()],
                username: String::new(),
                credential: String::new(),
            }],
            stun_session_secret: "stun".into(),
        };
        assert_eq!(
            connect_payload(&grant, "My Laptop", &offer),
            json!({"secret": "s", "client_name": "My Laptop", "client_info": {
                "wg_pub_key": "CLI=",
                "peer_desc": {
                    "candidates": [{"type": "iface", "addr": "192.0.2.10:51820"}],
                    "ice_config": [{"urls": ["stun:x:3478"], "username": "", "credential": ""}],
                    "is_master": false},
                "stun_session_secret": "stun"}})
        );
    }

    #[test]
    fn connect_answer_defaults_like_the_reference() {
        let r = parse_connect(&json!({"response_type": "CONNECT"})).unwrap();
        assert_eq!(
            r,
            ConnectResult {
                is_master: true,
                ..ConnectResult::default()
            }
        );
        assert!(parse_connect(&json!({"server_info": {"peer_desc": {"candidates": [{"type": "iface"}]}}})).is_err());
    }
}
