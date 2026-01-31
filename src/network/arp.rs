//! ARP spoofing for transparent DNS interception.
//!
//! This module implements ARP cache poisoning to redirect DNS traffic
//! from network devices to this server without requiring client configuration.
//!
//! # How it works
//!
//! 1. Discover the gateway (router) IP and MAC address
//! 2. Periodically send ARP replies to all devices claiming we are the gateway
//! 3. Intercept DNS queries (port 53) and respond with our filtered answers
//! 4. Forward all other traffic to the real gateway
//!
//! # Security Note
//!
//! This technique is commonly used for:
//! - Parental control devices
//! - Enterprise network monitoring
//! - Pi-hole style DNS filtering
//!
//! It requires root privileges and should only be used on networks you own/manage.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use tracing::{debug, info, warn};

use super::capture::PacketSender;
use crate::error::{NetworkError, Result};

/// Broadcast MAC address for ARP requests.
const BROADCAST_MAC: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

/// Size of an ARP packet payload.
const ARP_PACKET_SIZE: usize = 28;

/// Size of an Ethernet frame with ARP payload.
const ARP_FRAME_SIZE: usize = 14 + ARP_PACKET_SIZE;

/// Information about a network host discovered via ARP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

/// ARP table mapping IP addresses to MAC addresses.
#[derive(Debug, Clone, Default)]
pub struct ArpTable {
    entries: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
}

impl ArpTable {
    /// Create a new empty ARP table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update an entry.
    pub fn insert(&self, ip: Ipv4Addr, mac: MacAddr) {
        self.entries.write().insert(ip, mac);
    }

    /// Get the MAC address for an IP.
    pub fn get(&self, ip: &Ipv4Addr) -> Option<MacAddr> {
        self.entries.read().get(ip).copied()
    }

    /// Get all entries.
    pub fn all(&self) -> Vec<HostInfo> {
        self.entries
            .read()
            .iter()
            .map(|(&ip, &mac)| HostInfo { ip, mac })
            .collect()
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

/// Configuration for ARP spoofing.
#[derive(Debug, Clone)]
pub struct ArpSpoofConfig {
    /// The gateway (router) IP address to impersonate.
    pub gateway_ip: Ipv4Addr,
    /// Our interface's IP address.
    pub our_ip: Ipv4Addr,
    /// Our interface's MAC address.
    pub our_mac: MacAddr,
    /// Interval between ARP announcements.
    pub spoof_interval: Duration,
    /// Whether to restore ARP tables on shutdown.
    pub restore_on_shutdown: bool,
}

/// Builds ARP packets for spoofing and restoration.
pub struct ArpPacketBuilder {
    config: ArpSpoofConfig,
}

impl ArpPacketBuilder {
    /// Create a new ARP packet builder.
    pub const fn new(config: ArpSpoofConfig) -> Self {
        Self { config }
    }

    /// Build an ARP reply that tells `target_ip` that `spoofed_ip` is at `our_mac`.
    ///
    /// This is the core of ARP spoofing: we tell devices that the gateway's IP
    /// belongs to our MAC address.
    pub fn build_spoof_reply(&self, target_ip: Ipv4Addr, target_mac: MacAddr) -> Vec<u8> {
        Self::build_arp_reply(
            self.config.gateway_ip, // Claim to be the gateway
            self.config.our_mac,    // But use our MAC
            target_ip,
            target_mac,
        )
    }

    /// Build a gratuitous ARP announcement (broadcast).
    ///
    /// This tells all devices on the network that the gateway IP is at our MAC.
    pub fn build_gratuitous_arp(&self) -> Vec<u8> {
        Self::build_arp_reply(
            self.config.gateway_ip,
            self.config.our_mac,
            self.config.gateway_ip, // Target is also the gateway IP
            BROADCAST_MAC,          // Broadcast to all
        )
    }

    /// Build an ARP reply to restore the real gateway's MAC address.
    ///
    /// Used during graceful shutdown to restore normal network operation.
    pub fn build_restore_reply(
        &self,
        gateway_mac: MacAddr,
        target_ip: Ipv4Addr,
        target_mac: MacAddr,
    ) -> Vec<u8> {
        Self::build_arp_reply(self.config.gateway_ip, gateway_mac, target_ip, target_mac)
    }

    /// Build an ARP request to discover a host's MAC address.
    pub fn build_arp_request(&self, target_ip: Ipv4Addr) -> Vec<u8> {
        let mut buffer = vec![0u8; ARP_FRAME_SIZE];

        // Ethernet header
        {
            let mut ethernet = MutableEthernetPacket::new(&mut buffer).unwrap();
            ethernet.set_destination(BROADCAST_MAC);
            ethernet.set_source(self.config.our_mac);
            ethernet.set_ethertype(EtherTypes::Arp);
        }

        // ARP payload
        {
            let mut arp = MutableArpPacket::new(&mut buffer[14..]).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Request);
            arp.set_sender_hw_addr(self.config.our_mac);
            arp.set_sender_proto_addr(self.config.our_ip);
            arp.set_target_hw_addr(MacAddr::zero());
            arp.set_target_proto_addr(target_ip);
        }

        buffer
    }

    /// Build an ARP reply packet.
    fn build_arp_reply(
        sender_ip: Ipv4Addr,
        sender_mac: MacAddr,
        target_ip: Ipv4Addr,
        target_mac: MacAddr,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; ARP_FRAME_SIZE];

        // Ethernet header
        {
            let mut ethernet = MutableEthernetPacket::new(&mut buffer).unwrap();
            ethernet.set_destination(target_mac);
            ethernet.set_source(sender_mac);
            ethernet.set_ethertype(EtherTypes::Arp);
        }

        // ARP payload
        {
            let mut arp = MutableArpPacket::new(&mut buffer[14..]).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Reply);
            arp.set_sender_hw_addr(sender_mac);
            arp.set_sender_proto_addr(sender_ip);
            arp.set_target_hw_addr(target_mac);
            arp.set_target_proto_addr(target_ip);
        }

        buffer
    }
}

/// Parse an ARP packet from an Ethernet frame.
pub fn parse_arp_packet(frame: &[u8]) -> Option<(ArpOperation, HostInfo)> {
    let ethernet = EthernetPacket::new(frame)?;

    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;

    let host = HostInfo {
        ip: arp.get_sender_proto_addr(),
        mac: arp.get_sender_hw_addr(),
    };

    Some((arp.get_operation(), host))
}

/// ARP spoofer that maintains network interception.
pub struct ArpSpoofer<S: PacketSender> {
    config: ArpSpoofConfig,
    packet_builder: ArpPacketBuilder,
    sender: S,
    arp_table: ArpTable,
    gateway_mac: Option<MacAddr>,
}

impl<S: PacketSender> ArpSpoofer<S> {
    /// Create a new ARP spoofer.
    pub fn new(config: ArpSpoofConfig, sender: S) -> Self {
        let packet_builder = ArpPacketBuilder::new(config.clone());
        Self {
            config,
            packet_builder,
            sender,
            arp_table: ArpTable::new(),
            gateway_mac: None,
        }
    }

    /// Get a reference to the ARP table.
    pub const fn arp_table(&self) -> &ArpTable {
        &self.arp_table
    }

    /// Set the real gateway MAC address (discovered externally).
    pub const fn set_gateway_mac(&mut self, mac: MacAddr) {
        self.gateway_mac = Some(mac);
    }

    /// Get the gateway MAC if known.
    pub const fn gateway_mac(&self) -> Option<MacAddr> {
        self.gateway_mac
    }

    /// Process an incoming ARP packet and update our table.
    pub fn process_arp_packet(&mut self, frame: &[u8]) {
        if let Some((operation, host)) = parse_arp_packet(frame) {
            // Don't add our own entries
            if host.ip == self.config.our_ip {
                return;
            }

            // Record the gateway's real MAC when we see it
            if host.ip == self.config.gateway_ip && self.gateway_mac.is_none() {
                info!("Discovered gateway MAC: {} -> {}", host.ip, host.mac);
                self.gateway_mac = Some(host.mac);
            }

            debug!("ARP {:?}: {} -> {}", operation, host.ip, host.mac);
            self.arp_table.insert(host.ip, host.mac);
        }
    }

    /// Send ARP request to discover the gateway.
    pub fn discover_gateway(&mut self) -> Result<()> {
        info!(
            "Sending ARP request to discover gateway {}",
            self.config.gateway_ip
        );
        let packet = self
            .packet_builder
            .build_arp_request(self.config.gateway_ip);
        self.sender.send(&packet)
    }

    /// Send spoofed ARP replies to all known hosts.
    ///
    /// This tells all devices that the gateway IP belongs to our MAC.
    pub fn spoof_all(&mut self) -> Result<()> {
        let hosts = self.arp_table.all();

        // Send gratuitous ARP (broadcast)
        let gratuitous = self.packet_builder.build_gratuitous_arp();
        self.sender.send(&gratuitous)?;

        // Send targeted replies to each known host
        for host in hosts {
            // Don't spoof to ourselves or the gateway
            if host.ip == self.config.our_ip || host.ip == self.config.gateway_ip {
                continue;
            }

            let packet = self.packet_builder.build_spoof_reply(host.ip, host.mac);
            self.sender.send(&packet)?;
        }

        debug!("Sent ARP spoof packets to {} hosts", self.arp_table.len());
        Ok(())
    }

    /// Restore the real gateway MAC to all known hosts.
    ///
    /// Called during graceful shutdown.
    pub fn restore_all(&mut self) -> Result<()> {
        let Some(gateway_mac) = self.gateway_mac else {
            warn!("Cannot restore ARP: gateway MAC unknown");
            return Ok(());
        };

        info!("Restoring ARP tables to real gateway MAC {}", gateway_mac);

        let hosts = self.arp_table.all();
        for host in hosts {
            if host.ip == self.config.our_ip || host.ip == self.config.gateway_ip {
                continue;
            }

            let packet = self
                .packet_builder
                .build_restore_reply(gateway_mac, host.ip, host.mac);
            self.sender.send(&packet)?;
        }

        Ok(())
    }
}

/// Extract our IP and MAC from a network interface.
pub fn get_interface_info(interface: &NetworkInterface) -> Result<(Ipv4Addr, MacAddr)> {
    let mac = interface.mac.ok_or(NetworkError::NoInterface)?;

    let ip = interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
        .ok_or(NetworkError::NoInterface)?;

    Ok((ip, mac))
}

/// Detect the default gateway IP address.
///
/// This reads the system routing table to find the default gateway.
#[cfg(target_os = "linux")]
pub fn detect_gateway() -> Result<Ipv4Addr> {
    use std::fs;

    // Read /proc/net/route to find default gateway
    let route = fs::read_to_string("/proc/net/route")
        .map_err(|e| NetworkError::ChannelOpen(format!("Failed to read routing table: {e}")))?;

    for line in route.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 {
            let dest = fields[1];
            let gateway = fields[2];

            // Default route has destination 00000000
            if dest == "00000000" {
                // Gateway is in hex, little-endian
                let gw = u32::from_str_radix(gateway, 16)
                    .map_err(|e| NetworkError::ChannelOpen(format!("Invalid gateway: {e}")))?;
                return Ok(Ipv4Addr::from(gw.to_be()));
            }
        }
    }

    Err(NetworkError::ChannelOpen("No default gateway found".into()).into())
}

/// Detect the default gateway IP address (macOS version).
#[cfg(target_os = "macos")]
pub fn detect_gateway() -> Result<Ipv4Addr> {
    use std::process::Command;

    // Use netstat to find default gateway
    let output = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .map_err(|e| NetworkError::ChannelOpen(format!("Failed to run netstat: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[0] == "default" {
            let gateway: Ipv4Addr = fields[1]
                .parse()
                .map_err(|e| NetworkError::ChannelOpen(format!("Invalid gateway IP: {e}")))?;
            return Ok(gateway);
        }
    }

    Err(NetworkError::ChannelOpen("No default gateway found".into()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_store_and_retrieve_arp_entries() {
        let table = ArpTable::new();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        assert!(table.is_empty());
        table.insert(ip, mac);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&ip), Some(mac));
    }

    #[test]
    fn should_build_valid_arp_request_and_gratuitous_packets() {
        let config = ArpSpoofConfig {
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            our_ip: Ipv4Addr::new(192, 168, 1, 100),
            our_mac: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            spoof_interval: Duration::from_secs(2),
            restore_on_shutdown: true,
        };

        let builder = ArpPacketBuilder::new(config.clone());

        // Test ARP request
        let request = builder.build_arp_request(Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(request.len(), ARP_FRAME_SIZE);

        let eth = EthernetPacket::new(&request).unwrap();
        assert_eq!(eth.get_ethertype(), EtherTypes::Arp);
        assert_eq!(eth.get_destination(), BROADCAST_MAC);

        // Test gratuitous ARP
        let gratuitous = builder.build_gratuitous_arp();
        let eth = EthernetPacket::new(&gratuitous).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
        assert_eq!(arp.get_sender_proto_addr(), config.gateway_ip);
        assert_eq!(arp.get_sender_hw_addr(), config.our_mac);
    }

    #[test]
    fn should_parse_arp_packet_and_extract_host_info() {
        let config = ArpSpoofConfig {
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            our_ip: Ipv4Addr::new(192, 168, 1, 100),
            our_mac: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            spoof_interval: Duration::from_secs(2),
            restore_on_shutdown: true,
        };

        let builder = ArpPacketBuilder::new(config.clone());
        let packet = builder.build_gratuitous_arp();

        let (operation, host) = parse_arp_packet(&packet).unwrap();
        assert_eq!(operation, ArpOperations::Reply);
        assert_eq!(host.ip, config.gateway_ip);
        assert_eq!(host.mac, config.our_mac);
    }
}
