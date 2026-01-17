//! Packet construction for DNS responses.
//!
//! Builds complete Ethernet frames with proper checksums for
//! both IPv4 and IPv6 responses.

// DNS packets are always small (max 512 bytes for standard UDP DNS),
// so these casts from usize to u16 are safe and will never truncate.
#![allow(clippy::cast_possible_truncation)]

use std::net::IpAddr;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::udp::MutableUdpPacket;

use super::buffer::BufferPool;
use super::capture::PacketInfo;
use crate::error::{NetworkError, Result};

/// Ethernet header size in bytes.
const ETHERNET_HEADER_SIZE: usize = 14;
/// IPv4 header size in bytes (without options).
const IPV4_HEADER_SIZE: usize = 20;
/// IPv6 header size in bytes.
const IPV6_HEADER_SIZE: usize = 40;
/// UDP header size in bytes.
const UDP_HEADER_SIZE: usize = 8;

/// Builder for constructing DNS response packets.
///
/// Uses a buffer pool to minimize allocations.
pub struct PacketBuilder {
    buffer_pool: BufferPool,
}

impl PacketBuilder {
    /// Create a new packet builder with the given buffer pool.
    pub const fn new(buffer_pool: BufferPool) -> Self {
        Self { buffer_pool }
    }

    /// Build a complete Ethernet frame for a DNS response.
    ///
    /// The `packet_info` should contain the original query's addressing info;
    /// this function swaps source/destination appropriately for the response.
    pub fn build_response(&self, response: &Message, packet_info: &PacketInfo) -> Result<Vec<u8>> {
        let dns_bytes = response
            .to_bytes()
            .map_err(|e| NetworkError::PacketConstruction(e.to_string()))?;

        match (packet_info.source_ip, packet_info.dest_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                self.build_ipv4_response(&dns_bytes, packet_info, src_ip, dst_ip)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                self.build_ipv6_response(&dns_bytes, packet_info, src_ip, dst_ip)
            }
            _ => Err(NetworkError::PacketConstruction("mixed IPv4/IPv6 addresses".into()).into()),
        }
    }

    fn build_ipv4_response(
        &self,
        dns_bytes: &[u8],
        packet_info: &PacketInfo,
        src_ip: std::net::Ipv4Addr,
        dst_ip: std::net::Ipv4Addr,
    ) -> Result<Vec<u8>> {
        let udp_len = UDP_HEADER_SIZE + dns_bytes.len();
        let ipv4_len = IPV4_HEADER_SIZE + udp_len;
        let total_len = ETHERNET_HEADER_SIZE + ipv4_len;

        let mut buffer = self.buffer_pool.get_zeroed(total_len);
        let packet_data = buffer.as_mut_slice();

        // Build UDP packet
        let udp_start = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE;
        {
            let mut udp =
                MutableUdpPacket::new(&mut packet_data[udp_start..]).ok_or_else(|| {
                    NetworkError::PacketConstruction("UDP packet creation failed".into())
                })?;
            udp.set_source(packet_info.dest_port);
            udp.set_destination(packet_info.source_port);
            udp.set_length(udp_len as u16);
            udp.set_payload(dns_bytes);
            // Checksum will be set after we have the IP header
        }

        // Build IPv4 packet
        let ipv4_start = ETHERNET_HEADER_SIZE;
        {
            let mut ipv4 =
                MutableIpv4Packet::new(&mut packet_data[ipv4_start..]).ok_or_else(|| {
                    NetworkError::PacketConstruction("IPv4 packet creation failed".into())
                })?;
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len as u16);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            // Swap: response goes from original dest to original source
            ipv4.set_source(dst_ip);
            ipv4.set_destination(src_ip);
            ipv4.set_checksum(pnet::packet::ipv4::checksum(&ipv4.to_immutable()));
        }

        // Now set UDP checksum (needs IP addresses)
        {
            let udp_immutable = pnet::packet::udp::UdpPacket::new(&packet_data[udp_start..])
                .ok_or_else(|| NetworkError::PacketConstruction("UDP checksum failed".into()))?;
            let checksum = pnet::packet::udp::ipv4_checksum(&udp_immutable, &dst_ip, &src_ip);
            let mut udp = MutableUdpPacket::new(&mut packet_data[udp_start..]).unwrap();
            udp.set_checksum(checksum);
        }

        // Build Ethernet frame
        {
            let mut ethernet = MutableEthernetPacket::new(packet_data).ok_or_else(|| {
                NetworkError::PacketConstruction("Ethernet frame creation failed".into())
            })?;
            // Swap: response goes from original dest to original source
            ethernet.set_destination(packet_info.source_mac);
            ethernet.set_source(packet_info.dest_mac);
            ethernet.set_ethertype(EtherTypes::Ipv4);
        }

        // Copy to a new Vec since we need to return ownership
        Ok(packet_data.to_vec())
    }

    fn build_ipv6_response(
        &self,
        dns_bytes: &[u8],
        packet_info: &PacketInfo,
        src_ip: std::net::Ipv6Addr,
        dst_ip: std::net::Ipv6Addr,
    ) -> Result<Vec<u8>> {
        let udp_len = UDP_HEADER_SIZE + dns_bytes.len();
        let total_len = ETHERNET_HEADER_SIZE + IPV6_HEADER_SIZE + udp_len;

        let mut buffer = self.buffer_pool.get_zeroed(total_len);
        let packet_data = buffer.as_mut_slice();

        // Build UDP packet
        let udp_start = ETHERNET_HEADER_SIZE + IPV6_HEADER_SIZE;
        {
            let mut udp =
                MutableUdpPacket::new(&mut packet_data[udp_start..]).ok_or_else(|| {
                    NetworkError::PacketConstruction("UDP packet creation failed".into())
                })?;
            udp.set_source(packet_info.dest_port);
            udp.set_destination(packet_info.source_port);
            udp.set_length(udp_len as u16);
            udp.set_payload(dns_bytes);
        }

        // Build IPv6 packet
        let ipv6_start = ETHERNET_HEADER_SIZE;
        {
            let mut ipv6 =
                MutableIpv6Packet::new(&mut packet_data[ipv6_start..]).ok_or_else(|| {
                    NetworkError::PacketConstruction("IPv6 packet creation failed".into())
                })?;
            ipv6.set_version(6);
            ipv6.set_payload_length(udp_len as u16);
            ipv6.set_next_header(IpNextHeaderProtocols::Udp);
            ipv6.set_hop_limit(64);
            // Swap: response goes from original dest to original source
            ipv6.set_source(dst_ip);
            ipv6.set_destination(src_ip);
        }

        // Set UDP checksum for IPv6
        {
            let udp_immutable = pnet::packet::udp::UdpPacket::new(&packet_data[udp_start..])
                .ok_or_else(|| NetworkError::PacketConstruction("UDP checksum failed".into()))?;
            let checksum = pnet::packet::udp::ipv6_checksum(&udp_immutable, &dst_ip, &src_ip);
            let mut udp = MutableUdpPacket::new(&mut packet_data[udp_start..]).unwrap();
            udp.set_checksum(checksum);
        }

        // Build Ethernet frame
        {
            let mut ethernet = MutableEthernetPacket::new(packet_data).ok_or_else(|| {
                NetworkError::PacketConstruction("Ethernet frame creation failed".into())
            })?;
            ethernet.set_destination(packet_info.source_mac);
            ethernet.set_source(packet_info.dest_mac);
            ethernet.set_ethertype(EtherTypes::Ipv6);
        }

        Ok(packet_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, ResponseCode};
    use pnet::packet::Packet;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::udp::UdpPacket;
    use pnet::util::MacAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn create_test_response() -> Message {
        let mut msg = Message::new();
        msg.set_id(1234)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);
        msg
    }

    fn create_ipv4_packet_info() -> PacketInfo {
        PacketInfo {
            source_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
            dest_mac: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            source_port: 12345,
            dest_port: 53,
        }
    }

    fn create_ipv6_packet_info() -> PacketInfo {
        PacketInfo {
            source_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
            dest_mac: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            source_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            dest_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
            source_port: 12345,
            dest_port: 53,
        }
    }

    #[test]
    fn test_build_ipv4_response() {
        let pool = BufferPool::new(4);
        let builder = PacketBuilder::new(pool);
        let response = create_test_response();
        let packet_info = create_ipv4_packet_info();

        let packet = builder.build_response(&response, &packet_info).unwrap();

        // Verify Ethernet header
        let eth = EthernetPacket::new(&packet).unwrap();
        // Response swaps src/dst
        assert_eq!(eth.get_destination(), packet_info.source_mac);
        assert_eq!(eth.get_source(), packet_info.dest_mac);
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);

        // Verify IPv4 header
        let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
        assert_eq!(ipv4.get_version(), 4);
        assert_eq!(
            ipv4.get_source(),
            match packet_info.dest_ip {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => panic!(),
            }
        );
        assert_eq!(
            ipv4.get_destination(),
            match packet_info.source_ip {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => panic!(),
            }
        );

        // Verify UDP header
        let udp = UdpPacket::new(ipv4.payload()).unwrap();
        assert_eq!(udp.get_source(), packet_info.dest_port);
        assert_eq!(udp.get_destination(), packet_info.source_port);
    }

    #[test]
    fn test_build_ipv6_response() {
        let pool = BufferPool::new(4);
        let builder = PacketBuilder::new(pool);
        let response = create_test_response();
        let packet_info = create_ipv6_packet_info();

        let packet = builder.build_response(&response, &packet_info).unwrap();

        // Verify Ethernet header
        let eth = EthernetPacket::new(&packet).unwrap();
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv6);
        assert_eq!(eth.get_destination(), packet_info.source_mac);
        assert_eq!(eth.get_source(), packet_info.dest_mac);
    }

    #[test]
    fn test_mixed_ip_versions_error() {
        let pool = BufferPool::new(4);
        let builder = PacketBuilder::new(pool);
        let response = create_test_response();

        let packet_info = PacketInfo {
            source_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
            dest_mac: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dest_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            source_port: 12345,
            dest_port: 53,
        };

        let result = builder.build_response(&response, &packet_info);
        assert!(result.is_err());
    }
}
