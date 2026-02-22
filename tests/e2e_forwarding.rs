use std::net::Ipv4Addr;

use bluebox::network::forward::{self, ForwardTarget};
use bluebox::network::{ArpTable, PacketSender};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::util::MacAddr;

#[derive(Default)]
struct TestSender {
    sent: Vec<Vec<u8>>,
}

impl PacketSender for TestSender {
    fn send(&mut self, packet: &[u8]) -> bluebox::Result<()> {
        self.sent.push(packet.to_vec());
        Ok(())
    }
}

fn build_ipv4_udp_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut buffer = vec![0u8; 14 + 20 + 8];

    {
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    {
        let mut ipv4 = MutableIpv4Packet::new(&mut buffer[14..]).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(28);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4.set_source(src_ip);
        ipv4.set_destination(dst_ip);
    }

    {
        let mut udp = MutableUdpPacket::new(&mut buffer[34..]).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(8);
    }

    buffer
}

#[test]
fn should_forward_client_and_gateway_paths_transparently() {
    let our_ip = Ipv4Addr::new(192, 168, 1, 100);
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let client_ip = Ipv4Addr::new(192, 168, 1, 50);
    let internet_ip = Ipv4Addr::new(1, 1, 1, 1);

    let our_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x64);
    let client_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x32);
    let gateway_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);

    let arp_table = ArpTable::new();
    arp_table.insert(client_ip, client_mac);

    let mut sender = TestSender::default();

    // Client -> internet packet should go to gateway.
    let outbound = build_ipv4_udp_packet(client_mac, our_mac, client_ip, internet_ip, 50000, 443);
    let outbound_target =
        forward::resolve_forward_target(&outbound, our_ip, gateway_ip, &arp_table);
    assert_eq!(outbound_target, Some(ForwardTarget::Gateway));

    forward::forward_to_gateway(&outbound, gateway_mac, our_mac, &mut sender).unwrap();

    let forwarded_outbound = EthernetPacket::new(&sender.sent[0]).unwrap();
    assert_eq!(forwarded_outbound.get_destination(), gateway_mac);
    assert_eq!(forwarded_outbound.get_source(), our_mac);

    // Internet -> client response should go back to client, not gateway.
    let inbound = build_ipv4_udp_packet(gateway_mac, our_mac, internet_ip, client_ip, 443, 50000);
    let inbound_target = forward::resolve_forward_target(&inbound, our_ip, gateway_ip, &arp_table);
    assert_eq!(inbound_target, Some(ForwardTarget::Client(client_mac)));

    forward::forward_to_client(&inbound, client_mac, our_mac, &mut sender).unwrap();

    let forwarded_inbound = EthernetPacket::new(&sender.sent[1]).unwrap();
    assert_eq!(forwarded_inbound.get_destination(), client_mac);
    assert_eq!(forwarded_inbound.get_source(), our_mac);
}

#[test]
fn should_not_forward_dns_queries() {
    let our_ip = Ipv4Addr::new(192, 168, 1, 100);
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let client_ip = Ipv4Addr::new(192, 168, 1, 50);

    let our_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x64);
    let client_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x32);

    let packet = build_ipv4_udp_packet(client_mac, our_mac, client_ip, gateway_ip, 53000, 53);
    let arp_table = ArpTable::new();

    let target = forward::resolve_forward_target(&packet, our_ip, gateway_ip, &arp_table);
    assert_eq!(target, None);
}
