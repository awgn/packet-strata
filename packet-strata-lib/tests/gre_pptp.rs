use std::net::{Ipv4Addr, Ipv6Addr};

use packet_strata::packet::ether::EtherHeaderVlan;
use packet_strata::packet::header::{LinkLayer, NetworkLayer, TransportLayer, TunnelLayer};
use packet_strata::packet::iter::{Header, LinkType, PacketIter};
use packet_strata::packet::protocol::EtherProto;
use packet_strata::packet::tunnel::ipip::IpipType;
use packet_strata::packet::tunnel::ppp::PPP_PROTO_IPV4;
use packet_strata::packet::tunnel::pppoe::PPPOE_CODE_SESSION;
use packet_strata::packet::tunnel::pptp::PPTP_PROTOCOL_PPP;
use packet_strata::packet::{Packet, ParseMode};

/// Frame 1 (197 bytes) from `gre-pptp.pcap` dumped via `tshark -r gre-pptp.pcap -x`:
/// Ethernet -> 802.1Q (vid=100) -> IPv6 (IP4in6) -> IPv4 -> PPTP-GRE (v1, PPP) -> PPP -> IPv4 -> UDP -> DNS query
#[rustfmt::skip]
const GRE_PPTP_PKT1: [u8; 197] = [
    0xc5, 0x00, 0x00, 0x00, 0x82, 0xc4, 0x00, 0x12, 0x1e, 0xf2, 0x61, 0x3d, 0x81, 0x00, 0x00, 0x64,
    0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x04, 0xf6, 0x24, 0x02, 0xf0, 0x00, 0x00, 0x01,
    0x8e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x26, 0x07, 0xfc, 0xd0, 0x01, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb1, 0x08, 0x2a, 0x6b, 0x45, 0x00, 0x00, 0x8b, 0x8c, 0xaf,
    0x00, 0x00, 0x40, 0x2f, 0x75, 0xfe, 0x10, 0x00, 0x00, 0xc8, 0xc0, 0x34, 0xa6, 0x9a, 0x30, 0x81,
    0x88, 0x0b, 0x00, 0x67, 0x17, 0x80, 0x00, 0x06, 0x8f, 0xb1, 0x00, 0x08, 0x3a, 0x76, 0xff, 0x03,
    0x00, 0x21, 0x45, 0x00, 0x00, 0x63, 0x00, 0x00, 0x40, 0x00, 0x3c, 0x11, 0x56, 0x67, 0xac, 0x10,
    0x2c, 0x03, 0x08, 0x08, 0x08, 0x08, 0x9f, 0x40, 0x00, 0x35, 0x00, 0x4f, 0x2d, 0x23, 0xa6, 0x2c,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x78, 0x71, 0x74, 0x2d, 0x64,
    0x65, 0x74, 0x65, 0x63, 0x74, 0x2d, 0x6d, 0x6f, 0x64, 0x65, 0x32, 0x2d, 0x39, 0x37, 0x37, 0x31,
    0x32, 0x65, 0x38, 0x38, 0x2d, 0x31, 0x36, 0x37, 0x61, 0x2d, 0x34, 0x35, 0x62, 0x39, 0x2d, 0x39,
    0x33, 0x65, 0x65, 0x2d, 0x39, 0x31, 0x33, 0x31, 0x34, 0x30, 0x65, 0x37, 0x36, 0x36, 0x37, 0x38,
    0x00, 0x00, 0x1c, 0x00, 0x01,
];

/// Frame 2 (268 bytes) from `gre-pptp.pcap` dumped via `tshark -r gre-pptp.pcap -x`:
/// Ethernet -> 802.1Q (vid=100) -> IPv6 (IP4in6) -> IPv4 -> PPTP-GRE (v1, PPP) -> PPP -> IPv4 -> UDP -> DNS response
#[rustfmt::skip]
const GRE_PPTP_PKT2: [u8; 268] = [
    0x0c, 0x01, 0x00, 0x00, 0x61, 0x3d, 0x00, 0x19, 0x06, 0xe6, 0x82, 0xc4, 0x81, 0x00, 0x00, 0x64,
    0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x04, 0x39, 0x26, 0x07, 0xfc, 0xd0, 0x01, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb1, 0x08, 0x2a, 0x6b, 0x24, 0x02, 0xf0, 0x00, 0x00, 0x01,
    0x8e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x45, 0x00, 0x00, 0xd2, 0x86, 0xd7,
    0x40, 0x00, 0x40, 0x2f, 0x3b, 0x8f, 0xc0, 0x34, 0xa6, 0x9a, 0x10, 0x00, 0x00, 0xc8, 0x30, 0x01,
    0x88, 0x0b, 0x00, 0xb2, 0x00, 0x11, 0x00, 0x08, 0x3a, 0xb8, 0xff, 0x03, 0x00, 0x21, 0x45, 0x00,
    0x00, 0xae, 0x03, 0x06, 0x00, 0x00, 0x32, 0x11, 0x9d, 0x16, 0x08, 0x08, 0x08, 0x08, 0xac, 0x10,
    0x2c, 0x03, 0x00, 0x35, 0x9f, 0x40, 0x00, 0x9a, 0xbb, 0xda, 0xa6, 0x2c, 0x81, 0x83, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x35, 0x78, 0x71, 0x74, 0x2d, 0x64, 0x65, 0x74, 0x65, 0x63,
    0x74, 0x2d, 0x6d, 0x6f, 0x64, 0x65, 0x32, 0x2d, 0x39, 0x37, 0x37, 0x31, 0x32, 0x65, 0x38, 0x38,
    0x2d, 0x31, 0x36, 0x37, 0x61, 0x2d, 0x34, 0x35, 0x62, 0x39, 0x2d, 0x39, 0x33, 0x65, 0x65, 0x2d,
    0x39, 0x31, 0x33, 0x31, 0x34, 0x30, 0x65, 0x37, 0x36, 0x36, 0x37, 0x38, 0x00, 0x00, 0x1c, 0x00,
    0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x02, 0xf5, 0x00, 0x40, 0x01, 0x61, 0x0c, 0x72,
    0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
    0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d,
    0x67, 0x72, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x78, 0x0d, 0x09, 0x09, 0x00, 0x00, 0x07, 0x08,
    0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80,
];

#[test]
fn test_gre_pptp_pkt1_full_parse_detunneling() {
    let packet = Packet::from_bytes(&GRE_PPTP_PKT1, LinkType::Ethernet, ParseMode::Innermost)
        .expect("Failed to parse GRE-PPTP packet 1");

    // Link layer: Ethernet + 802.1Q VLAN 100
    match packet.link() {
        LinkLayer::Ethernet(eth @ EtherHeaderVlan::VLAN8021Q(_, vlan)) => {
            assert_eq!(vlan.vlan_id(), 100);
            assert_eq!(eth.inner_type(), EtherProto::IPV6);
        }
        other => panic!("Expected Ethernet + 802.1Q link layer, got {:?}", other),
    }

    // Tunnels: IP4in6 -> PPTP-GRE -> PPP
    assert_eq!(
        packet.tunnels().len(),
        3,
        "Expected 3 tunnel layers (IP4in6, PPTP, PPP), got {}",
        packet.tunnels().len()
    );

    // Tunnel 0: IP4in6 (2402:f000:1:8e01::5555 -> 2607:fcd0:100:2300::b108:2a6b)
    match packet.tunnels()[0].tunnel() {
        TunnelLayer::Ipip(ipip) => {
            assert_eq!(ipip.tunnel_type(), IpipType::Ip4in6);
            let ipv6 = ipip.outer_ipv6().expect("Expected outer IPv6 in IP4in6");
            assert_eq!(
                ipv6.src_ip(),
                "2402:f000:1:8e01::5555".parse::<Ipv6Addr>().unwrap()
            );
            assert_eq!(
                ipv6.dst_ip(),
                "2607:fcd0:100:2300::b108:2a6b".parse::<Ipv6Addr>().unwrap()
            );
        }
        other => panic!("Expected Ipip tunnel at layer 0, got {:?}", other),
    }

    // Tunnel 1: Outer IPv4 (16.0.0.200 -> 192.52.166.154) + PPTP-GRE v1
    match packet.tunnels()[1].outer() {
        Some(NetworkLayer::Ipv4(ipv4)) => {
            assert_eq!(ipv4.src_ip(), Ipv4Addr::new(16, 0, 0, 200));
            assert_eq!(ipv4.dst_ip(), Ipv4Addr::new(192, 52, 166, 154));
        }
        other => panic!("Expected outer IPv4 for PPTP tunnel, got {:?}", other),
    }
    match packet.tunnels()[1].tunnel() {
        TunnelLayer::Pptp(pptp) => {
            assert_eq!(pptp.version(), 1);
            assert_eq!(pptp.protocol_type(), EtherProto::from(PPTP_PROTOCOL_PPP));
            assert_eq!(pptp.payload_length(), 103);
            assert_eq!(pptp.call_id(), 6016);
            assert_eq!(pptp.sequence_number(), Some(430001));
            assert_eq!(pptp.acknowledgment_number(), Some(539254));
        }
        other => panic!("Expected PPTP tunnel at layer 1, got {:?}", other),
    }

    // Tunnel 2: PPP (0xff03 0x0021 -> IPv4)
    assert!(packet.tunnels()[2].outer().is_none());
    match packet.tunnels()[2].tunnel() {
        TunnelLayer::Ppp(ppp) => {
            assert_eq!(ppp.protocol(), PPP_PROTO_IPV4);
            assert!(ppp.has_hdlc_framing());
            assert!(!ppp.is_protocol_compressed());
            assert_eq!(ppp.header_len(), 4);
            assert_eq!(ppp.inner_ether_proto(), Some(EtherProto::IPV4));
        }
        other => panic!("Expected PPP tunnel at layer 2, got {:?}", other),
    }

    // Innermost network layer: IPv4 (172.16.44.3 -> 8.8.8.8) decapsulated from PPP (0xff03 0x0021)
    let inner_net = packet
        .network()
        .expect("Expected innermost IPv4 network layer after PPTP/PPP detunneling");
    match inner_net {
        NetworkLayer::Ipv4(ipv4) => {
            assert_eq!(ipv4.src_ip(), Ipv4Addr::new(172, 16, 44, 3));
            assert_eq!(ipv4.dst_ip(), Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(ipv4.total_length(), 99);
            assert_eq!(ipv4.ttl(), 60);
        }
        other => panic!("Expected inner IPv4, got {:?}", other),
    }

    // Innermost transport layer: UDP (40768 -> 53)
    let inner_transport = packet
        .transport()
        .expect("Expected innermost UDP transport layer after PPTP/PPP detunneling");
    match inner_transport {
        TransportLayer::Udp(udp) => {
            assert_eq!(udp.src_port(), 40768);
            assert_eq!(udp.dst_port(), 53);
            assert_eq!(udp.length(), 79);
        }
        other => panic!("Expected inner UDP, got {:?}", other),
    }

    // Innermost payload: DNS query (71 bytes, Transaction ID 0xa62c)
    assert_eq!(packet.data().len(), 71);
    assert_eq!(&packet.data()[0..2], &[0xa6, 0x2c]);
}

#[test]
fn test_gre_pptp_pkt2_full_parse_detunneling() {
    let packet = Packet::from_bytes(&GRE_PPTP_PKT2, LinkType::Ethernet, ParseMode::Innermost)
        .expect("Failed to parse GRE-PPTP packet 2");

    // Link layer: Ethernet + 802.1Q VLAN 100
    match packet.link() {
        LinkLayer::Ethernet(eth @ EtherHeaderVlan::VLAN8021Q(_, vlan)) => {
            assert_eq!(vlan.vlan_id(), 100);
            assert_eq!(eth.inner_type(), EtherProto::IPV6);
        }
        other => panic!("Expected Ethernet + 802.1Q link layer, got {:?}", other),
    }

    // Tunnels: IP4in6 -> PPTP-GRE -> PPP
    assert_eq!(
        packet.tunnels().len(),
        3,
        "Expected 3 tunnel layers (IP4in6, PPTP, PPP), got {}",
        packet.tunnels().len()
    );

    // Tunnel 0: IP4in6 (2607:fcd0:100:2300::b108:2a6b -> 2402:f000:1:8e01::5555)
    match packet.tunnels()[0].tunnel() {
        TunnelLayer::Ipip(ipip) => {
            assert_eq!(ipip.tunnel_type(), IpipType::Ip4in6);
            let ipv6 = ipip.outer_ipv6().expect("Expected outer IPv6 in IP4in6");
            assert_eq!(
                ipv6.src_ip(),
                "2607:fcd0:100:2300::b108:2a6b".parse::<Ipv6Addr>().unwrap()
            );
            assert_eq!(
                ipv6.dst_ip(),
                "2402:f000:1:8e01::5555".parse::<Ipv6Addr>().unwrap()
            );
        }
        other => panic!("Expected Ipip tunnel at layer 0, got {:?}", other),
    }

    // Tunnel 1: Outer IPv4 (192.52.166.154 -> 16.0.0.200) + PPTP-GRE v1
    match packet.tunnels()[1].outer() {
        Some(NetworkLayer::Ipv4(ipv4)) => {
            assert_eq!(ipv4.src_ip(), Ipv4Addr::new(192, 52, 166, 154));
            assert_eq!(ipv4.dst_ip(), Ipv4Addr::new(16, 0, 0, 200));
        }
        other => panic!("Expected outer IPv4 for PPTP tunnel, got {:?}", other),
    }
    match packet.tunnels()[1].tunnel() {
        TunnelLayer::Pptp(pptp) => {
            assert_eq!(pptp.version(), 1);
            assert_eq!(pptp.protocol_type(), EtherProto::from(PPTP_PROTOCOL_PPP));
            assert_eq!(pptp.payload_length(), 178);
            assert_eq!(pptp.call_id(), 17);
            assert_eq!(pptp.sequence_number(), Some(539320));
            assert_eq!(pptp.acknowledgment_number(), None);
        }
        other => panic!("Expected PPTP tunnel at layer 1, got {:?}", other),
    }

    // Tunnel 2: PPP (0xff03 0x0021 -> IPv4)
    assert!(packet.tunnels()[2].outer().is_none());
    match packet.tunnels()[2].tunnel() {
        TunnelLayer::Ppp(ppp) => {
            assert_eq!(ppp.protocol(), PPP_PROTO_IPV4);
            assert!(ppp.has_hdlc_framing());
            assert!(!ppp.is_protocol_compressed());
            assert_eq!(ppp.header_len(), 4);
            assert_eq!(ppp.inner_ether_proto(), Some(EtherProto::IPV4));
        }
        other => panic!("Expected PPP tunnel at layer 2, got {:?}", other),
    }

    // Innermost network layer: IPv4 (8.8.8.8 -> 172.16.44.3) decapsulated from PPP (0xff03 0x0021)
    let inner_net = packet
        .network()
        .expect("Expected innermost IPv4 network layer after PPTP/PPP detunneling");
    match inner_net {
        NetworkLayer::Ipv4(ipv4) => {
            assert_eq!(ipv4.src_ip(), Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(ipv4.dst_ip(), Ipv4Addr::new(172, 16, 44, 3));
            assert_eq!(ipv4.total_length(), 174);
            assert_eq!(ipv4.ttl(), 50);
        }
        other => panic!("Expected inner IPv4, got {:?}", other),
    }

    // Innermost transport layer: UDP (53 -> 40768)
    let inner_transport = packet
        .transport()
        .expect("Expected innermost UDP transport layer after PPTP/PPP detunneling");
    match inner_transport {
        TransportLayer::Udp(udp) => {
            assert_eq!(udp.src_port(), 53);
            assert_eq!(udp.dst_port(), 40768);
            assert_eq!(udp.length(), 154);
        }
        other => panic!("Expected inner UDP, got {:?}", other),
    }

    // Innermost payload: DNS response (146 bytes, Transaction ID 0xa62c)
    assert_eq!(packet.data().len(), 146);
    assert_eq!(&packet.data()[0..2], &[0xa6, 0x2c]);
}

#[test]
fn test_gre_pptp_iter_detunneling() {
    for (idx, raw) in [(&GRE_PPTP_PKT1[..], 71usize), (&GRE_PPTP_PKT2[..], 146usize)]
        .into_iter()
        .enumerate()
    {
        let (pkt, expected_dns_len) = raw;
        let mut iter = PacketIter::new(pkt, LinkType::Ethernet);
        let headers: Vec<Header<'_>> = iter
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("Packet {} iteration failed: {}", idx + 1, e));

        assert_eq!(
            headers.len(),
            7,
            "Packet {} expected 7 headers, got: {:?}",
            idx + 1,
            headers.iter().map(|h| h.name()).collect::<Vec<_>>()
        );
        assert!(matches!(headers[0], Header::Ethernet(_)));
        assert!(matches!(headers[1], Header::Ipip(_)));
        assert!(matches!(headers[2], Header::Ipv4(_)));
        assert!(matches!(headers[3], Header::Pptp(_)));
        assert!(matches!(headers[4], Header::Ppp(_)));
        assert!(matches!(headers[5], Header::Ipv4(_)));
        assert!(matches!(headers[6], Header::Udp(_)));
        assert_eq!(iter.remaining().len(), expected_dns_len);
    }
}

/// Frame 2 (82 bytes) from `pppoe-over-qinq.pcap` dumped via `tshark -r pppoe-over-qinq.pcap -x`:
/// Ethernet -> QinQ (3704, 2474) -> PPPoE Session (sid=0x0f07, len=54) -> PPP (0x0021) -> IPv4 (2.2.2.2 -> 1.1.1.1) -> TCP (443 -> 20394)
#[rustfmt::skip]
const PPPOE_QINQ_PKT: [u8; 82] = [
    0xbc, 0xd1, 0x77, 0x17, 0x75, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x0e, 0x78,
    0x81, 0x00, 0x09, 0xaa, 0x88, 0x64, 0x11, 0x00, 0x0f, 0x07, 0x00, 0x36, 0x00, 0x21, 0x45, 0x00,
    0x00, 0x34, 0x1c, 0x2f, 0x40, 0x00, 0xef, 0x06, 0x69, 0x8f, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01,
    0x01, 0x01, 0x01, 0xbb, 0x4f, 0xaa, 0xfc, 0x90, 0xa2, 0xfe, 0xd7, 0xa8, 0x41, 0x56, 0x80, 0x12,
    0x1f, 0xfe, 0x3f, 0x21, 0x00, 0x00, 0x02, 0x04, 0x05, 0xa0, 0x01, 0x03, 0x03, 0x04, 0x01, 0x01,
    0x04, 0x02,
];

#[test]
fn test_pppoe_qinq_detunneling() {
    let packet = Packet::from_bytes(&PPPOE_QINQ_PKT, LinkType::Ethernet, ParseMode::Innermost)
        .expect("Failed to parse PPPoE over QinQ packet");

    // Link layer: Ethernet + QinQ (3704, 2474)
    match packet.link() {
        LinkLayer::Ethernet(eth @ EtherHeaderVlan::VLAN8021QNested(_, v1, v2)) => {
            assert_eq!(v1.vlan_id(), 3704);
            assert_eq!(v2.vlan_id(), 2474);
            assert_eq!(eth.inner_type(), EtherProto::PPP_SES);
        }
        other => panic!("Expected QinQ Ethernet link layer, got {:?}", other),
    }

    // Tunnels: PPPoE -> PPP
    assert_eq!(packet.tunnels().len(), 2);
    match packet.tunnels()[0].tunnel() {
        TunnelLayer::Pppoe(pppoe) => {
            assert_eq!(pppoe.code(), PPPOE_CODE_SESSION);
            assert!(pppoe.is_session_data());
            assert_eq!(pppoe.session_id(), 0x0f07);
            assert_eq!(pppoe.length(), 54);
        }
        other => panic!("Expected PPPoE tunnel at layer 0, got {:?}", other),
    }
    match packet.tunnels()[1].tunnel() {
        TunnelLayer::Ppp(ppp) => {
            assert_eq!(ppp.protocol(), PPP_PROTO_IPV4);
            assert!(!ppp.has_hdlc_framing());
            assert_eq!(ppp.header_len(), 2);
        }
        other => panic!("Expected PPP tunnel at layer 1, got {:?}", other),
    }

    // Innermost IPv4 + TCP
    match packet.network().expect("Expected inner IPv4") {
        NetworkLayer::Ipv4(ipv4) => {
            assert_eq!(ipv4.src_ip(), Ipv4Addr::new(2, 2, 2, 2));
            assert_eq!(ipv4.dst_ip(), Ipv4Addr::new(1, 1, 1, 1));
        }
        other => panic!("Expected inner IPv4, got {:?}", other),
    }
    match packet.transport().expect("Expected inner TCP") {
        TransportLayer::Tcp(tcp) => {
            assert_eq!(tcp.src_port(), 443);
            assert_eq!(tcp.dst_port(), 20394);
        }
        other => panic!("Expected inner TCP, got {:?}", other),
    }
}
