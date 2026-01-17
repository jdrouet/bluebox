//! Packet capture abstraction.
//!
//! Provides a trait-based abstraction over packet capture to enable:
//! - Testing without real network interfaces
//! - Different capture backends

use std::net::IpAddr;

use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;

use crate::error::{NetworkError, Result};

/// Information extracted from a captured packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    pub source_mac: MacAddr,
    pub dest_mac: MacAddr,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
}

/// Trait for packet capture implementations.
pub trait PacketCapture: Send {
    /// Receive the next packet.
    /// Returns None if the capture has ended.
    fn next_packet(&mut self) -> Option<Vec<u8>>;
}

/// Trait for packet sending implementations.
pub trait PacketSender: Send {
    /// Send a packet.
    fn send(&mut self, packet: &[u8]) -> Result<()>;
}

/// Find a suitable network interface.
///
/// Returns the first interface that is:
/// - Up (active)
/// - Not a loopback interface
/// - Has at least one IP address
pub fn find_interface(name: Option<&str>) -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();

    if let Some(name) = name {
        interfaces
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| NetworkError::NoInterface.into())
    } else {
        interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .ok_or_else(|| NetworkError::NoInterface.into())
    }
}

/// Production packet capture using pnet.
pub struct PnetCapture {
    rx: Box<dyn DataLinkReceiver>,
}

impl PnetCapture {
    /// Create a new capture for the given interface.
    pub fn new(interface: &NetworkInterface) -> Result<(Self, PnetSender)> {
        let (tx, rx) = match datalink::channel(interface, pnet::datalink::Config::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(NetworkError::UnsupportedChannel.into()),
            Err(e) => return Err(NetworkError::ChannelOpen(e.to_string()).into()),
        };

        Ok((Self { rx }, PnetSender { tx }))
    }
}

impl PacketCapture for PnetCapture {
    fn next_packet(&mut self) -> Option<Vec<u8>> {
        self.rx.next().ok().map(<[u8]>::to_vec)
    }
}

/// Production packet sender using pnet.
pub struct PnetSender {
    tx: Box<dyn DataLinkSender>,
}

impl PacketSender for PnetSender {
    fn send(&mut self, packet: &[u8]) -> Result<()> {
        self.tx
            .send_to(packet, None)
            .ok_or_else(|| NetworkError::SendFailed("send returned None".into()))?
            .map_err(|e| NetworkError::SendFailed(e.to_string()))?;
        Ok(())
    }
}

/// Extract DNS query information from an Ethernet packet.
///
/// Returns None if:
/// - The packet is not IPv4 or IPv6
/// - The packet is not UDP
/// - The destination port is not 53 (DNS)
pub fn extract_dns_query(packet: &[u8]) -> Option<(PacketInfo, Vec<u8>)> {
    let ethernet = EthernetPacket::new(packet)?;

    let (source_ip, dest_ip, udp_payload) = match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(ethernet.payload())?;
            (
                IpAddr::V4(ipv4.get_source()),
                IpAddr::V4(ipv4.get_destination()),
                ipv4.payload().to_vec(),
            )
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(ethernet.payload())?;
            (
                IpAddr::V6(ipv6.get_source()),
                IpAddr::V6(ipv6.get_destination()),
                ipv6.payload().to_vec(),
            )
        }
        _ => return None,
    };

    let udp = UdpPacket::new(&udp_payload)?;

    // Only interested in DNS queries (port 53)
    if udp.get_destination() != 53 {
        return None;
    }

    let packet_info = PacketInfo {
        source_mac: ethernet.get_source(),
        dest_mac: ethernet.get_destination(),
        source_ip,
        dest_ip,
        source_port: udp.get_source(),
        dest_port: udp.get_destination(),
    };

    Some((packet_info, udp.payload().to_vec()))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Mock packet capture for testing.
    pub struct MockCapture {
        packets: VecDeque<Vec<u8>>,
    }

    impl MockCapture {
        pub fn new(packets: Vec<Vec<u8>>) -> Self {
            Self {
                packets: packets.into(),
            }
        }
    }

    impl PacketCapture for MockCapture {
        fn next_packet(&mut self) -> Option<Vec<u8>> {
            self.packets.pop_front()
        }
    }

    /// Mock packet sender for testing.
    #[derive(Clone, Default)]
    pub struct MockSender {
        pub sent_packets: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockSender {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn sent_count(&self) -> usize {
            self.sent_packets.lock().unwrap().len()
        }

        pub fn last_sent(&self) -> Option<Vec<u8>> {
            self.sent_packets.lock().unwrap().last().cloned()
        }
    }

    impl PacketSender for MockSender {
        fn send(&mut self, packet: &[u8]) -> Result<()> {
            self.sent_packets.lock().unwrap().push(packet.to_vec());
            Ok(())
        }
    }

    #[test]
    fn test_mock_capture() {
        let packets = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let mut capture = MockCapture::new(packets);

        assert_eq!(capture.next_packet(), Some(vec![1, 2, 3]));
        assert_eq!(capture.next_packet(), Some(vec![4, 5, 6]));
        assert_eq!(capture.next_packet(), None);
    }

    #[test]
    fn test_mock_sender() {
        let mut sender = MockSender::new();

        sender.send(&[1, 2, 3]).unwrap();
        assert_eq!(sender.sent_count(), 1);

        sender.send(&[4, 5, 6]).unwrap();
        assert_eq!(sender.sent_count(), 2);
        assert_eq!(sender.last_sent(), Some(vec![4, 5, 6]));
    }

    #[test]
    fn test_packet_info_equality() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let info1 = PacketInfo {
            source_mac: MacAddr::new(1, 2, 3, 4, 5, 6),
            dest_mac: MacAddr::new(6, 5, 4, 3, 2, 1),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 12345,
            dest_port: 53,
        };

        let info2 = info1.clone();
        assert_eq!(info1, info2);

        let info3 = PacketInfo {
            source_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ..info1
        };
        assert_ne!(info1, info3);
    }
}
