use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use moka::future::Cache;
use pnet::datalink::{self, Channel, DataLinkSender};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::util::MacAddr;
use serde::Deserialize;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task;
use tracing::{info, instrument, warn};
use tracing_subscriber;

#[derive(Deserialize)]
struct Config {
    upstream_resolver: String,
    cache_ttl_seconds: u64,
    #[serde(default)]
    blocklist: Vec<String>,
}

#[derive(Clone, Debug)]
struct PacketInfo {
    source_mac: MacAddr,
    dest_mac: MacAddr,
    source_ip: IpAddr,
    dest_ip: IpAddr,
    source_port: u16,
    dest_port: u16,
}

fn is_blocked(name: &Name, blocklist: &[String]) -> bool {
    let name_str = name.to_utf8();
    for pattern in blocklist {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..];
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
    packet_info: &PacketInfo,
) -> Result<()> {
    let response_bytes = response_message.to_bytes()?;
    let udp_len = 8 + response_bytes.len();

    let mut udp_buffer = vec![0u8; udp_len];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_packet.set_source(packet_info.dest_port);
    udp_packet.set_destination(packet_info.source_port);
    udp_packet.set_length(udp_len as u16);
    udp_packet.set_payload(&response_bytes);

    match (packet_info.source_ip, packet_info.dest_ip) {
        (IpAddr::V4(source_ip), IpAddr::V4(dest_ip)) => {
            udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(
                &udp_packet.to_immutable(),
                &dest_ip,
                &source_ip,
            ));

            let ipv4_len = 20 + udp_len;
            let mut ipv4_buffer = vec![0u8; ipv4_len];
            let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(ipv4_len as u16);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_source(dest_ip);
            ipv4_packet.set_destination(source_ip);
            ipv4_packet.set_checksum(pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable()));
            ipv4_packet.set_payload(udp_packet.packet());

            let ethernet_len = 14 + ipv4_len;
            let mut ethernet_buffer = vec![0u8; ethernet_len];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
            ethernet_packet.set_destination(packet_info.source_mac);
            ethernet_packet.set_source(packet_info.dest_mac);
            ethernet_packet.set_ethertype(EtherTypes::Ipv4);
            ethernet_packet.set_payload(ipv4_packet.packet());

            tx.send_to(ethernet_packet.packet(), None).unwrap()?;
        }
        (IpAddr::V6(source_ip), IpAddr::V6(dest_ip)) => {
            udp_packet.set_checksum(pnet::packet::udp::ipv6_checksum(
                &udp_packet.to_immutable(),
                &dest_ip,
                &source_ip,
            ));

            let ipv6_len = 40 + udp_len;
            let mut ipv6_buffer = vec![0u8; ipv6_len];
            let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
            ipv6_packet.set_version(6);
            ipv6_packet.set_payload_length(udp_len as u16);
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Udp);
            ipv6_packet.set_hop_limit(64);
            ipv6_packet.set_source(dest_ip);
            ipv6_packet.set_destination(source_ip);
            ipv6_packet.set_payload(udp_packet.packet());

            let ethernet_len = 14 + ipv6_len;
            let mut ethernet_buffer = vec![0u8; ethernet_len];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
            ethernet_packet.set_destination(packet_info.source_mac);
            ethernet_packet.set_source(packet_info.dest_mac);
            ethernet_packet.set_ethertype(EtherTypes::Ipv6);
            ethernet_packet.set_payload(ipv6_packet.packet());

            tx.send_to(ethernet_packet.packet(), None).unwrap()?;
        }
        _ => {
            warn!("Mixed IPv4/IPv6 packet, cannot construct response.");
        }
    }
    Ok(())
}

#[instrument(skip(cache, config))]
async fn resolve_queries(
    query_message: Message,
    cache: Cache<Name, Message>,
    config: Arc<Config>,
) -> Result<Message> {
    let query = query_message.queries().first().unwrap().clone();
    let name = query.name();
    info!("Resolving query for {}", name);

    if is_blocked(name, &config.blocklist) {
        info!("Domain {} is blocked.", name);
        let mut response = Message::new();
        response
            .set_id(query_message.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);

        let record = match query.query_type() {
            hickory_proto::rr::RecordType::AAAA => Record::from_rdata(
                name.clone(),
                300,
                RData::AAAA(rdata::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
            ),
            _ => Record::from_rdata(
                name.clone(),
                300,
                RData::A(rdata::A(Ipv4Addr::new(127, 0, 0, 1))),
            ),
        };
        response.add_answer(record);
        return Ok(response);
    }

    if let Some(response) = cache.get(name).await {
        info!("Cache hit for {}", name);
        return Ok(response);
    }
    info!("Cache miss for {}", name);

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

    info!("Starting Bluebox DNS interceptor...");
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && iface.ips.iter().any(|ip| ip.is_ipv4() || ip.is_ipv6())
        })
        .context("Failed to find a suitable network interface")?;
    info!("Listening on interface: {}", interface.name.clone());

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

            let (source_ip, dest_ip, udp_payload) = match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4 = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                    (
                        IpAddr::V4(ipv4.get_source()),
                        IpAddr::V4(ipv4.get_destination()),
                        ipv4.payload().to_vec(),
                    )
                }
                EtherTypes::Ipv6 => {
                    let ipv6 = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
                    (
                        IpAddr::V6(ipv6.get_source()),
                        IpAddr::V6(ipv6.get_destination()),
                        ipv6.payload().to_vec(),
                    )
                }
                _ => continue,
            };

            let udp_packet = if let Some(p) = UdpPacket::new(&udp_payload) {
                p
            } else {
                continue;
            };

            if udp_packet.get_destination() == 53 {
                if let Ok(message) = Message::from_bytes(udp_packet.payload()) {
                    let packet_info = PacketInfo {
                        source_mac: ethernet_packet.get_source(),
                        dest_mac: ethernet_packet.get_destination(),
                        source_ip,
                        dest_ip,
                        source_port: udp_packet.get_source(),
                        dest_port: udp_packet.get_destination(),
                    };

                    if let Ok(response) =
                        resolve_queries(message, cache.clone(), config_clone.clone()).await
                    {
                        send_response(&mut datalink_tx, &response, &packet_info)
                            .unwrap_or_else(|e| warn!("Failed to send response: {}", e));
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down.");
            running.store(false, Ordering::SeqCst);
        }
        _ = packet_handler => {}
    }

    capture_handle.await?;
    info!("Shutdown complete.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_is_blocked() {
        let blocklist = vec!["google.com".to_string(), "*.ads.com".to_string()];

        let name = Name::from_str("google.com").unwrap();
        assert!(is_blocked(&name, &blocklist));

        let name = Name::from_str("analytics.ads.com").unwrap();
        assert!(is_blocked(&name, &blocklist));

        let name = Name::from_str("sub.analytics.ads.com").unwrap();
        assert!(is_blocked(&name, &blocklist));

        let name = Name::from_str("rust-lang.org").unwrap();
        assert!(!is_blocked(&name, &blocklist));

        let name = Name::from_str("ads.com").unwrap();
        assert!(!is_blocked(&name, &blocklist));
    }
}
