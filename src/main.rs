use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, rdata::A};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use moka::future::Cache;
use pnet::datalink::{self, Channel, DataLinkSender};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::util::MacAddr;
use serde::Deserialize;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task;

#[derive(Deserialize)]
struct Config {
    upstream_resolver: String,
    cache_ttl_seconds: u64,
    #[serde(default)]
    blocklist: Vec<String>,
}

fn is_blocked(name: &Name, blocklist: &[String]) -> bool {
    let name_str = name.to_utf8();
    for pattern in blocklist {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // e.g., ".ads.com"
            if name_str.ends_with(suffix) {
                return true;
            }
        } else if &name_str == pattern {
            return true;
        }
    }
    false
}

fn send_response(
    tx: &mut Box<dyn DataLinkSender>,
    response_message: &Message,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    source_port: u16,
    target_port: u16,
) -> Result<()> {
    let response_bytes = response_message.to_bytes()?;
    let udp_len = 8 + response_bytes.len();
    let ipv4_len = 20 + udp_len;
    let mut ipv4_buffer = vec![0u8; ipv4_len];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(ipv4_len as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(target_ip);
    ipv4_packet.set_checksum(pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable()));

    let mut udp_buffer = vec![0u8; udp_len];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_packet.set_source(source_port);
    udp_packet.set_destination(target_port);
    udp_packet.set_length(udp_len as u16);
    udp_packet.set_payload(&response_bytes);
    udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &source_ip,
        &target_ip,
    ));
    ipv4_packet.set_payload(udp_packet.packet());

    let ethernet_len = 14 + ipv4_len;
    let mut ethernet_buffer = vec![0u8; ethernet_len];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_packet.set_payload(ipv4_packet.packet());

    tx.send_to(ethernet_packet.packet(), None).unwrap()?;
    Ok(())
}

async fn resolve_queries(
    query_message: Message,
    cache: Cache<Name, Message>,
    config: Arc<Config>,
) -> Result<Message> {
    let query = query_message.queries().first().unwrap().clone();
    let name = query.name();

    // 1. Check blocklist
    if is_blocked(name, &config.blocklist) {
        println!("Domain {} is blocked.", name);
        let mut response = Message::new();
        response
            .set_id(query_message.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);
        let record = Record::from_rdata(
            name.clone(),
            300, // TTL
            RData::A(A(Ipv4Addr::new(127, 0, 0, 1))),
        );
        response.add_answer(record);
        return Ok(response);
    }

    // 2. Check cache
    if let Some(response) = cache.get(name).await {
        return Ok(response);
    }

    // 3. Forward to upstream if not in cache or blocked
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(&config.upstream_resolver).await?;
    socket.send(&query_message.to_bytes()?).await?;

    let mut response_bytes = vec![0; 512];
    let len = socket.recv(&mut response_bytes).await?;
    let response_message = Message::from_bytes(&response_bytes[..len])?;

    cache.insert(name.clone(), response_message.clone()).await;
    Ok(response_message)
}

async fn run() -> Result<()> {
    let config_str = fs::read_to_string("config.toml").context("Failed to read config.toml")?;
    let config: Arc<Config> = Arc::new(toml::from_str(&config_str)?);

    println!("Starting Bluebox DNS interceptor...");
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| {
            iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .context("Failed to find a suitable network interface")?;
    println!("Listening on interface: {}", interface.name.clone());

    let cache: Cache<Name, Message> = Cache::builder()
        .time_to_live(Duration::from_secs(config.cache_ttl_seconds))
        .build();

    let (mut datalink_tx, mut datalink_rx) = match datalink::channel(&interface, Default::default())
    {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("Unknown channel type"),
        Err(e) => anyhow::bail!("Error opening channel: {}", e),
    };

    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(1000);
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let capture_handle = task::spawn_blocking(move || {
        while r.load(Ordering::SeqCst) {
            if let Ok(packet) = datalink_rx.next() {
                if packet_tx.blocking_send(packet.to_vec()).is_err() {
                    break;
                }
            }
        }
    });

    let config_clone = config.clone();
    let packet_handler = tokio::spawn(async move {
        while let Some(packet) = packet_rx.recv().await {
            let ethernet_packet = if let Some(p) = EthernetPacket::new(&packet) {
                p
            } else {
                continue;
            };
            let ipv4_packet = if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                if let Some(p) = Ipv4Packet::new(ethernet_packet.payload()) {
                    p
                } else {
                    continue;
                }
            } else {
                continue;
            };
            let udp_packet = if let Some(p) = UdpPacket::new(ipv4_packet.payload()) {
                p
            } else {
                continue;
            };

            if udp_packet.get_destination() == 53 {
                if let Ok(message) = Message::from_bytes(udp_packet.payload()) {
                    if let Ok(response) =
                        resolve_queries(message, cache.clone(), config_clone.clone()).await
                    {
                        send_response(
                            &mut datalink_tx,
                            &response,
                            ipv4_packet.get_destination(),
                            ethernet_packet.get_destination(),
                            ipv4_packet.get_source(),
                            ethernet_packet.get_source(),
                            udp_packet.get_destination(),
                            udp_packet.get_source(),
                        )
                        .unwrap_or_else(|e| eprintln!("Failed to send response: {}", e));
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Ctrl-C received, shutting down.");
            running.store(false, Ordering::SeqCst);
        }
        _ = packet_handler => {}
    }

    capture_handle.await?;
    println!("Shutdown complete.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_is_blocked() {
        let blocklist = vec!["google.com".to_string(), "*.ads.com".to_string()];

        // Exact match
        let name = Name::from_str("google.com").unwrap();
        assert!(is_blocked(&name, &blocklist));

        // Wildcard match
        let name = Name::from_str("analytics.ads.com").unwrap();
        assert!(is_blocked(&name, &blocklist));

        // Subdomain of wildcard
        let name = Name::from_str("sub.analytics.ads.com").unwrap();
        assert!(is_blocked(&name, &blocklist));

        // Not blocked
        let name = Name::from_str("rust-lang.org").unwrap();
        assert!(!is_blocked(&name, &blocklist));

        // Partial match (should not be blocked)
        let name = Name::from_str("ads.com").unwrap();
        assert!(!is_blocked(&name, &blocklist));
    }
}
