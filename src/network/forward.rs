//! Traffic forwarding for non-DNS packets.
//!
//! When we intercept traffic via ARP spoofing, we receive ALL traffic
//! destined for the gateway. We need to forward non-DNS traffic to the
//! real gateway to maintain normal network operation.

use std::net::Ipv4Addr;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;
use tracing::debug;

use super::arp::ArpTable;
use super::capture::PacketSender;
use crate::error::Result;

/// Where a captured non-DNS packet should be forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardTarget {
    Gateway,
    Client(MacAddr),
}

/// Determines if a packet should be forwarded to the real gateway.
///
/// Returns `true` for packets that are NOT DNS queries destined for port 53.
/// DNS queries will be handled by our server instead.
pub fn should_forward(frame: &[u8], our_ip: Ipv4Addr) -> bool {
    let Some(ethernet) = EthernetPacket::new(frame) else {
        return false;
    };

    // Only handle IPv4 for now
    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        // Forward non-IPv4 traffic (IPv6, etc.)
        return true;
    }

    let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) else {
        return true;
    };

    // Don't forward our own packets
    if ipv4.get_source() == our_ip {
        return false;
    }

    // Check if this is a DNS query (UDP port 53)
    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp
        && let Some(udp) = UdpPacket::new(ipv4.payload())
        && udp.get_destination() == 53
    {
        // This is a DNS query - don't forward, we'll handle it
        return false;
    }

    // Forward everything else
    true
}

/// Determines where a captured packet should be forwarded.
///
/// Returns:
/// - `None` for packets that should not be forwarded (DNS queries or own traffic)
/// - `Some(ForwardTarget::Client)` for gateway/internet responses to known clients
/// - `Some(ForwardTarget::Gateway)` for everything else that should transit to gateway
pub fn resolve_forward_target(
    frame: &[u8],
    our_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    arp_table: &ArpTable,
) -> Option<ForwardTarget> {
    if !should_forward(frame, our_ip) {
        return None;
    }

    if let Some(dest_ip) = get_destination_ip(frame)
        && dest_ip != our_ip
        && dest_ip != gateway_ip
        && let Some(client_mac) = arp_table.get(&dest_ip)
    {
        return Some(ForwardTarget::Client(client_mac));
    }

    Some(ForwardTarget::Gateway)
}

/// Forwards a packet to the real gateway by rewriting the destination MAC.
pub fn forward_to_gateway<S: PacketSender>(
    frame: &[u8],
    gateway_mac: MacAddr,
    our_mac: MacAddr,
    sender: &mut S,
) -> Result<()> {
    let mut buffer = frame.to_vec();

    // Rewrite Ethernet header
    if let Some(mut ethernet) = MutableEthernetPacket::new(&mut buffer) {
        ethernet.set_destination(gateway_mac);
        ethernet.set_source(our_mac);
    }

    sender.send(&buffer)?;
    debug!("Forwarded packet to gateway");
    Ok(())
}

/// Forwards a packet from the gateway back to the original client.
pub fn forward_to_client<S: PacketSender>(
    frame: &[u8],
    client_mac: MacAddr,
    our_mac: MacAddr,
    sender: &mut S,
) -> Result<()> {
    let mut buffer = frame.to_vec();

    // Rewrite Ethernet header
    if let Some(mut ethernet) = MutableEthernetPacket::new(&mut buffer) {
        ethernet.set_destination(client_mac);
        ethernet.set_source(our_mac);
    }

    sender.send(&buffer)?;
    debug!("Forwarded packet to client");
    Ok(())
}

/// Extracts the destination IP from an IPv4 packet.
pub fn get_destination_ip(frame: &[u8]) -> Option<Ipv4Addr> {
    let ethernet = EthernetPacket::new(frame)?;

    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    Some(ipv4.get_destination())
}

/// Extracts the source IP from an IPv4 packet.
pub fn get_source_ip(frame: &[u8]) -> Option<Ipv4Addr> {
    let ethernet = EthernetPacket::new(frame)?;

    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    Some(ipv4.get_source())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;

    fn build_test_packet(dest_port: u16, src_ip: Ipv4Addr) -> Vec<u8> {
        let mut buffer = vec![0u8; 14 + 20 + 8]; // Ethernet + IPv4 + UDP

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
            eth.set_source(MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66));
            eth.set_destination(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        }

        // IPv4 header
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut buffer[14..]).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(28); // 20 + 8
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4.set_source(src_ip);
            ipv4.set_destination(Ipv4Addr::new(192, 168, 1, 1));
        }

        // UDP header
        {
            let mut udp = MutableUdpPacket::new(&mut buffer[34..]).unwrap();
            udp.set_source(12345);
            udp.set_destination(dest_port);
            udp.set_length(8);
        }

        buffer
    }

    #[test]
    #[allow(clippy::similar_names, reason = "https and http, come on...")]
    fn should_not_forward_dns_queries_but_forward_other_traffic() {
        let our_ip = Ipv4Addr::new(192, 168, 1, 100);
        let client_ip = Ipv4Addr::new(192, 168, 1, 50);

        // DNS query (port 53) should NOT be forwarded
        let dns_packet = build_test_packet(53, client_ip);
        assert!(!should_forward(&dns_packet, our_ip));

        // HTTPS (port 443) should be forwarded
        let https_packet = build_test_packet(443, client_ip);
        assert!(should_forward(&https_packet, our_ip));

        // HTTP (port 80) should be forwarded
        let http_packet = build_test_packet(80, client_ip);
        assert!(should_forward(&http_packet, our_ip));
    }

    #[test]
    fn should_not_forward_packets_from_own_ip() {
        let our_ip = Ipv4Addr::new(192, 168, 1, 100);

        // Packets from ourselves should not be forwarded
        let own_packet = build_test_packet(443, our_ip);
        assert!(!should_forward(&own_packet, our_ip));
    }

    #[test]
    fn should_route_gateway_responses_to_known_client() {
        let our_ip = Ipv4Addr::new(192, 168, 1, 100);
        let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
        let client_ip = Ipv4Addr::new(192, 168, 1, 50);
        let client_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        let arp_table = ArpTable::new();
        arp_table.insert(client_ip, client_mac);

        let mut packet = build_test_packet(443, Ipv4Addr::new(8, 8, 8, 8));
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut packet[14..]).unwrap();
            ipv4.set_destination(client_ip);
        }

        let target = resolve_forward_target(&packet, our_ip, gateway_ip, &arp_table);
        assert_eq!(target, Some(ForwardTarget::Client(client_mac)));
    }

    #[test]
    fn should_extract_destination_ip_from_packet() {
        let packet = build_test_packet(80, Ipv4Addr::new(192, 168, 1, 50));
        let dest = get_destination_ip(&packet);
        assert_eq!(dest, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn should_extract_source_ip_from_packet() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 50);
        let packet = build_test_packet(80, src_ip);
        let src = get_source_ip(&packet);
        assert_eq!(src, Some(src_ip));
    }
}
