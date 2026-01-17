//! Packet header iterator for traversing protocol stack layers
//!
//!
//! This module provides an iterator that traverses the headers of a network packet,
//! parsing each layer from link layer through transport layer, including tunnel protocols.
//!
//! # Overview
//!
//! The [`PacketIter`] struct implements [`Iterator`] and yields [`Header`] enum variants
//! for each successfully parsed protocol header. The iterator automatically determines
//! the next protocol to parse based on the `inner_type()` of the current header.
//!
//! # Supported Protocols
//!
//! ## Link Layer
//! - Ethernet II (with VLAN 802.1Q support)
//! - Linux cooked capture (SLL, SLLv2)
//! - BSD Null/Loopback (LINKTYPE_NULL)
//! - Raw IPv4 (LINKTYPE_RAW with IPv4)
//! - Raw IPv6 (LINKTYPE_RAW with IPv6)
//!
//! ## Network Layer
//! - IPv4 (with options parsing)
//! - IPv6 (with extension headers: Hop-by-Hop, Routing, Fragment, Destination, AH, ESP)
//! - ARP (Address Resolution Protocol)
//!
//! ## Transport Layer
//! - TCP (with options parsing: MSS, Window Scale, SACK, Timestamps, etc.)
//! - UDP
//! - SCTP (Stream Control Transmission Protocol)
//! - ICMPv4
//! - ICMPv6
//!
//! ## Tunnel Protocols
//! - VXLAN (Virtual Extensible LAN, UDP port 4789)
//! - Geneve (Generic Network Virtualization Encapsulation, UDP port 6081)
//! - GRE (Generic Routing Encapsulation, IP protocol 47)
//! - NVGRE (Network Virtualization using GRE, GRE with Key and TEB protocol)
//! - MPLS (Multi-Protocol Label Switching, EtherType 0x8847/0x8848)
//! - Teredo (IPv6 over UDP, UDP port 3544)
//! - GTPv1-U (GPRS Tunneling Protocol User Plane, UDP port 2152)
//! - GTPv1-C (GPRS Tunneling Protocol Control Plane, UDP port 2123)
//! - GTPv2-C (GTPv2 Control Plane, UDP port 2123)
//! - L2TPv2 (Layer 2 Tunneling Protocol v2, UDP port 1701)
//! - L2TPv3 (Layer 2 Tunneling Protocol v3, IP protocol 115)
//! - PBB (Provider Backbone Bridge, EtherType 0x88E7/0x88A8)
//! - STT (Stateless Transport Tunneling, TCP port 7471)
//! - PPTP (Point-to-Point Tunneling Protocol, Enhanced GRE version 1)
//!
//! ## IP-in-IP Tunnels
//! - IPIP (IPv4-in-IPv4, IP protocol 4)
//! - SIT/6in4 (IPv6-in-IPv4, IP protocol 41)
//! - IP4in6 (IPv4-in-IPv6, IPv6 next header 4)
//! - IP6Tnl (IPv6-in-IPv6, IPv6 next header 41)
//!
//! # Example
//!
//! ```
//! use packet_strata::packet::iter::{PacketIter, Header, LinkType};
//!
//! // Example Ethernet + IPv4 + TCP packet
//! let packet = vec![
//!     // Ethernet header (14 bytes)
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
//!     0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  // Source MAC
//!     0x08, 0x00,                          // EtherType: IPv4
//!     // IPv4 header (20 bytes, no options)
//!     0x45, 0x00, 0x00, 0x28,              // Version, IHL, DSCP, Total Length
//!     0x00, 0x00, 0x00, 0x00,              // ID, Flags, Fragment Offset
//!     0x40, 0x06, 0x00, 0x00,              // TTL, Protocol (TCP), Checksum
//!     0xc0, 0xa8, 0x01, 0x01,              // Source IP
//!     0xc0, 0xa8, 0x01, 0x02,              // Destination IP
//!     // TCP header (20 bytes, no options)
//!     0x00, 0x50, 0x01, 0xbb,              // Src Port, Dst Port
//!     0x00, 0x00, 0x00, 0x00,              // Sequence Number
//!     0x00, 0x00, 0x00, 0x00,              // Acknowledgment Number
//!     0x50, 0x02, 0x00, 0x00,              // Data Offset, Flags, Window
//!     0x00, 0x00, 0x00, 0x00,              // Checksum, Urgent Pointer
//! ];
//!
//! let mut iter = PacketIter::new(&packet, LinkType::Ethernet);
//!
//! // First header should be Ethernet
//! let first = iter.next().unwrap().unwrap();
//! assert!(matches!(first, Header::Ethernet(_)));
//!
//! // Second header should be IPv4
//! let second = iter.next().unwrap().unwrap();
//! assert!(matches!(second, Header::Ipv4(_)));
//!
//! // Third header should be TCP
//! let third = iter.next().unwrap().unwrap();
//! assert!(matches!(third, Header::Tcp(_)));
//!
//! // No more headers
//! assert!(iter.next().is_none());
//! ```
//!
//! # Error Handling
//!
//! The iterator yields `Result<Header<'a>, PacketHeaderError>`. When parsing fails:
//! - `Some(Err(e))` is returned with the error
//! - The iterator becomes "fused" and subsequent calls return `None`
//!
//! # Unsupported Protocols
//!
//! When an unsupported protocol is encountered, the iterator returns `Header::Unknown`
//! with the protocol identifier and remaining buffer, then terminates.

use super::arp::ArpHeader;
use super::detect::{
    detect_gre_variant, detect_mpls_inner_protocol, detect_udp_tunnel, find_ipv6_upper_protocol,
    is_stt_port, NextLayer, TunnelType,
};
use super::ether::EtherHeader;
// Re-export Header and UnknownProto for API compatibility
pub use super::header::{Header, UnknownProto};
use super::icmp::IcmpHeader;
use super::icmp6::Icmp6Header;
use super::ipv4::Ipv4Header;
use super::ipv6::Ipv6Header;
use super::null::NullHeader;
use super::protocol::{EtherProto, IpProto};
use super::sctp::SctpHeader;
use super::sll::{SllHeader, Sllv2Header};
use super::tcp::TcpHeader;
use super::tunnel::geneve::GeneveHeader;
use super::tunnel::gre::GreHeader;
use super::tunnel::gtpv1::Gtpv1Header;
use super::tunnel::gtpv2::Gtpv2Header;
use super::tunnel::ipip::IpipTunnel;
use super::tunnel::l2tp::{L2tpv2Header, L2tpv3SessionHeader};
use super::tunnel::mpls::MplsLabelStack;
use super::tunnel::nvgre::NvgreHeader;
use super::tunnel::pbb::PbbHeader;
use super::tunnel::pptp::PptpGreHeader;
use super::tunnel::stt::SttPacket;
use super::tunnel::teredo::TeredoPacket;
use super::tunnel::vxlan::VxlanHeader;
use super::udp::UdpHeader;
use super::{HeaderParser, PacketHeaderError};

/// Link layer type for the packet capture
///
/// This determines what protocol to expect at the beginning of the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Standard Ethernet II frame
    Ethernet,
    /// Linux cooked capture v1 (SLL)
    Sll,
    /// Linux cooked capture v2 (SLLv2)
    Sllv2,
    /// BSD Null/Loopback encapsulation
    Null,
    /// Raw IPv4 (no link layer header)
    RawIpv4,
    /// Raw IPv6 (no link layer header)
    RawIpv6,
}

/// Iterator over packet headers
///
/// Parses each protocol layer and yields [`Header`] variants.
/// The iterator is fused after an error or when parsing is complete.
pub struct PacketIter<'a> {
    /// Remaining unparsed buffer
    remaining: &'a [u8],
    /// Next layer to parse
    next_layer: NextLayer,
    /// Whether the iterator is done (fused)
    done: bool,
    /// Track the last UDP header for tunnel detection
    last_udp_ports: Option<(u16, u16)>,
}

impl<'a> PacketIter<'a> {
    /// Create a new packet iterator
    ///
    /// # Arguments
    ///
    /// * `buf` - The packet buffer to parse
    /// * `link_type` - The link layer type of the packet
    ///
    /// # Example
    ///
    /// ```
    /// use packet_strata::packet::iter::{PacketIter, LinkType};
    ///
    /// let packet = vec![/* ... */];
    /// let iter = PacketIter::new(&packet, LinkType::Ethernet);
    /// ```
    pub fn new(buf: &'a [u8], link_type: LinkType) -> Self {
        Self {
            remaining: buf,
            next_layer: NextLayer::Link(link_type),
            done: false,
            last_udp_ports: None,
        }
    }

    /// Guess the link type from raw packet bytes
    ///
    /// This is a super fast heuristic that examines a few bytes to determine
    /// the most likely link layer type. It's designed for speed over accuracy.
    ///
    /// # Returns
    ///
    /// The guessed `LinkType`, defaulting to `Ethernet` if undetermined.
    #[inline]
    pub fn guess_link_type(buf: &[u8]) -> LinkType {
        // Need at least 1 byte to check anything
        if buf.is_empty() {
            return LinkType::Ethernet;
        }

        // Fast path: Check for raw IP (most common in tunnels/VPNs)
        // IPv4: version = 4 in high nibble (0x4X), IHL >= 5 in low nibble
        // IPv6: version = 6 in high nibble (0x6X)
        let first_byte = buf[0];
        let version = first_byte >> 4;

        if version == 4 {
            // Likely IPv4: check IHL is valid (5-15)
            let ihl = first_byte & 0x0F;
            if (5..=15).contains(&ihl) {
                return LinkType::RawIpv4;
            }
        } else if version == 6 {
            // Likely IPv6
            return LinkType::RawIpv6;
        }

        // Check for Null/Loopback (4 bytes AF_* in host byte order)
        if buf.len() >= 4 {
            let le_val = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let be_val = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

            // Valid AF_* values: 2 (INET), 10 (INET6 Linux), 24 (OpenBSD), 28 (FreeBSD), 30 (Darwin)
            let is_valid_af = |v: u32| matches!(v, 2 | 10 | 24 | 28 | 30);

            if is_valid_af(le_val) || is_valid_af(be_val) {
                // Additional check: after the 4-byte header, should be IP
                if buf.len() >= 5 {
                    let next_version = buf[4] >> 4;
                    if next_version == 4 || next_version == 6 {
                        return LinkType::Null;
                    }
                }
            }
        }

        // Check for Ethernet (14 byte header, EtherType at 12-13)
        if buf.len() >= 14 {
            let ether_type = u16::from_be_bytes([buf[12], buf[13]]);

            // Common EtherTypes: IPv4 (0x0800), IPv6 (0x86DD), ARP (0x0806), VLAN (0x8100, 0x88A8)
            // MPLS (0x8847, 0x8848), PPPoE (0x8863, 0x8864)
            match ether_type {
                0x0800 | 0x86DD | 0x0806 | 0x8100 | 0x88A8 | 0x8847 | 0x8848 | 0x8863 | 0x8864 => {
                    return LinkType::Ethernet;
                }
                _ => {}
            }
        }

        // Check for SLL (16 bytes) - packet type at 0-1 should be 0-4
        if buf.len() >= 16 {
            let packet_type = u16::from_be_bytes([buf[0], buf[1]]);
            let protocol = u16::from_be_bytes([buf[14], buf[15]]);

            // Packet type: 0=host, 1=broadcast, 2=multicast, 3=otherhost, 4=outgoing
            // Protocol should be a valid EtherType
            if packet_type <= 4 {
                match protocol {
                    0x0800 | 0x86DD | 0x0806 | 0x8100 => {
                        return LinkType::Sll;
                    }
                    _ => {}
                }
            }
        }

        // Check for SLLv2 (20 bytes) - protocol at 0-1
        if buf.len() >= 20 {
            let protocol = u16::from_be_bytes([buf[0], buf[1]]);
            let packet_type = buf[10]; // Packet type at byte 10

            if packet_type <= 4 {
                match protocol {
                    0x0800 | 0x86DD | 0x0806 | 0x8100 => {
                        return LinkType::Sllv2;
                    }
                    _ => {}
                }
            }
        }

        // Default to Ethernet (most common)
        LinkType::Ethernet
    }

    /// Create a new packet iterator starting at the network layer
    ///
    /// Use this when you already know the EtherType/protocol and want
    /// to skip link layer parsing.
    ///
    /// # Arguments
    ///
    /// * `buf` - The packet buffer to parse (starting at network layer)
    /// * `ether_proto` - The EtherType indicating the network protocol
    pub fn from_network_layer(buf: &'a [u8], ether_proto: EtherProto) -> Self {
        Self {
            remaining: buf,
            next_layer: NextLayer::Network(ether_proto),
            done: false,
            last_udp_ports: None,
        }
    }

    /// Create a new packet iterator starting at the transport layer
    ///
    /// Use this when you already know the IP protocol and want
    /// to skip network layer parsing.
    ///
    /// # Arguments
    ///
    /// * `buf` - The packet buffer to parse (starting at transport layer)
    /// * `ip_proto` - The IP protocol number
    pub fn from_transport_layer(buf: &'a [u8], ip_proto: IpProto) -> Self {
        Self {
            remaining: buf,
            next_layer: NextLayer::Transport(ip_proto),
            done: false,
            last_udp_ports: None,
        }
    }

    /// Returns the remaining unparsed bytes
    ///
    /// This is the payload after all parsed headers.
    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    /// Returns true if the iterator is done
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Parse link layer header
    fn parse_link(&mut self, link_type: LinkType) -> Option<Result<Header<'a>, PacketHeaderError>> {
        match link_type {
            LinkType::Ethernet => match EtherHeader::from_bytes(self.remaining) {
                Ok((eth, rest)) => {
                    let next_proto = eth.inner_type();
                    self.remaining = rest;
                    self.next_layer = NextLayer::Network(next_proto);
                    Some(Ok(Header::Ethernet(eth)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            LinkType::Sll => match SllHeader::from_bytes(self.remaining) {
                Ok((sll, rest)) => {
                    let next_proto = sll.protocol();
                    self.remaining = rest;
                    self.next_layer = NextLayer::Network(next_proto);
                    Some(Ok(Header::Sll(sll)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            LinkType::Sllv2 => match Sllv2Header::from_bytes(self.remaining) {
                Ok((sll, rest)) => {
                    let next_proto = sll.protocol();
                    self.remaining = rest;
                    self.next_layer = NextLayer::Network(next_proto);
                    Some(Ok(Header::Sllv2(sll)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            LinkType::Null => match NullHeader::from_bytes(self.remaining) {
                Ok((null, rest)) => {
                    let next_proto = null.protocol();
                    self.remaining = rest;
                    self.next_layer = NextLayer::Network(next_proto);
                    Some(Ok(Header::Null(null)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            LinkType::RawIpv4 => {
                self.next_layer = NextLayer::Network(EtherProto::IPV4);
                self.next()
            }
            LinkType::RawIpv6 => {
                self.next_layer = NextLayer::Network(EtherProto::IPV6);
                self.next()
            }
        }
    }

    /// Parse network layer header
    fn parse_network(
        &mut self,
        ether_proto: EtherProto,
    ) -> Option<Result<Header<'a>, PacketHeaderError>> {
        match ether_proto {
            EtherProto::IPV4 => match Ipv4Header::from_bytes(self.remaining) {
                Ok((ipv4, rest)) => {
                    let proto = ipv4.protocol();
                    self.remaining = rest;
                    // Common case first: transport protocol (TCP, UDP, etc.)
                    if proto != IpProto::IP_ENCAP && proto != IpProto::IPV6 {
                        self.next_layer = NextLayer::Transport(proto);
                        Some(Ok(Header::Ipv4(ipv4)))
                    } else if proto == IpProto::IP_ENCAP {
                        // Rare: IPv4-in-IPv4 tunnel
                        self.next_layer = NextLayer::Network(EtherProto::IPV4);
                        Some(Ok(Header::Ipip(IpipTunnel::ipip(ipv4))))
                    } else {
                        // Rare: IPv6-in-IPv4 (SIT) tunnel
                        self.next_layer = NextLayer::Network(EtherProto::IPV6);
                        Some(Ok(Header::Ipip(IpipTunnel::sit(ipv4))))
                    }
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            EtherProto::IPV6 => match Ipv6Header::from_bytes(self.remaining) {
                Ok((ipv6, rest)) => {
                    // For IPv6, find the upper layer protocol
                    // Fast path: no extension headers
                    let next_proto = if ipv6.raw_extensions.is_empty() {
                        ipv6.next_header()
                    } else {
                        find_ipv6_upper_protocol(&ipv6)
                    };
                    self.remaining = rest;
                    // Common case first: transport protocol
                    if next_proto != IpProto::IP_ENCAP && next_proto != IpProto::IPV6 {
                        self.next_layer = NextLayer::Transport(next_proto);
                        Some(Ok(Header::Ipv6(ipv6)))
                    } else if next_proto == IpProto::IP_ENCAP {
                        // Rare: IPv4-in-IPv6 (IP4in6) tunnel
                        self.next_layer = NextLayer::Network(EtherProto::IPV4);
                        Some(Ok(Header::Ipip(IpipTunnel::ip4in6(ipv6))))
                    } else {
                        // Rare: IPv6-in-IPv6 (IP6Tnl) tunnel
                        self.next_layer = NextLayer::Network(EtherProto::IPV6);
                        Some(Ok(Header::Ipip(IpipTunnel::ip6tnl(ipv6))))
                    }
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            EtherProto::ARP => match ArpHeader::from_bytes(self.remaining) {
                Ok((arp, rest)) => {
                    self.remaining = rest;
                    self.next_layer = NextLayer::Done;
                    Some(Ok(Header::Arp(arp)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            EtherProto::MPLS_UC | EtherProto::MPLS_MC => {
                // MPLS encapsulation
                self.next_layer = NextLayer::Tunnel(TunnelType::Mpls);
                self.next()
            }
            EtherProto::TEB => {
                // Transparent Ethernet Bridging - inner Ethernet frame
                self.next_layer = NextLayer::Link(LinkType::Ethernet);
                self.next()
            }
            EtherProto::VLAN_8021AH | EtherProto::VLAN_8021AD => {
                // PBB (Provider Backbone Bridge / MAC-in-MAC)
                // 0x88E7 = I-Tag (802.1ah), 0x88A8 = B-Tag (802.1ad)
                self.next_layer = NextLayer::Tunnel(TunnelType::Pbb);
                self.next()
            }
            _ => {
                // Unknown network protocol
                let header = Header::Unknown {
                    proto: UnknownProto::Ether(ether_proto),
                    data: self.remaining,
                };
                self.remaining = &[];
                self.done = true;
                Some(Ok(header))
            }
        }
    }

    /// Parse transport layer header
    fn parse_transport(
        &mut self,
        ip_proto: IpProto,
    ) -> Option<Result<Header<'a>, PacketHeaderError>> {
        match ip_proto {
            IpProto::TCP => match TcpHeader::from_bytes(self.remaining) {
                Ok((tcp, rest)) => {
                    let src_port = tcp.src_port();
                    let dst_port = tcp.dst_port();

                    // Check for STT tunnel (TCP port 7471)
                    if is_stt_port(dst_port) || is_stt_port(src_port) {
                        self.next_layer = NextLayer::Tunnel(TunnelType::Stt);
                    } else {
                        self.next_layer = NextLayer::Done;
                    }

                    self.remaining = rest;
                    Some(Ok(Header::Tcp(tcp)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            IpProto::UDP => match UdpHeader::from_bytes(self.remaining) {
                Ok((udp, rest)) => {
                    let src_port = udp.src_port();
                    let dst_port = udp.dst_port();
                    self.last_udp_ports = Some((src_port, dst_port));

                    // Check for tunnel protocols based on UDP ports
                    if let Some(tunnel_type) = detect_udp_tunnel(src_port, dst_port, rest) {
                        self.remaining = rest;
                        self.next_layer = NextLayer::Tunnel(tunnel_type);
                    } else {
                        self.remaining = rest;
                        self.next_layer = NextLayer::Done;
                    }
                    Some(Ok(Header::Udp(udp)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            IpProto::SCTP => match SctpHeader::from_bytes(self.remaining) {
                Ok((sctp, rest)) => {
                    self.remaining = rest;
                    self.next_layer = NextLayer::Done;
                    Some(Ok(Header::Sctp(sctp)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            IpProto::ICMP => match IcmpHeader::from_bytes(self.remaining) {
                Ok((icmp, rest)) => {
                    self.remaining = rest;
                    self.next_layer = NextLayer::Done;
                    Some(Ok(Header::Icmp(icmp)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            IpProto::ICMP6 => match Icmp6Header::from_bytes(self.remaining) {
                Ok((icmp6, rest)) => {
                    self.remaining = rest;
                    self.next_layer = NextLayer::Done;
                    Some(Ok(Header::Icmp6(icmp6)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            IpProto::GRE => {
                // GRE tunnel - detect specific variant (PPTP, NVGRE, or standard GRE)
                let tunnel_type = detect_gre_variant(self.remaining);
                self.next_layer = NextLayer::Tunnel(tunnel_type);
                self.next()
            }
            IpProto::L2TP => {
                // L2TPv3 over IP (protocol 115)
                self.next_layer = NextLayer::Tunnel(TunnelType::L2tpv3);
                self.next()
            }

            IpProto::IPV6_NONXT => {
                // No next header - we're done
                self.next_layer = NextLayer::Done;
                self.done = true;
                None
            }
            _ => {
                // Unknown transport protocol
                let header = Header::Unknown {
                    proto: UnknownProto::Ip(ip_proto),
                    data: self.remaining,
                };
                self.remaining = &[];
                self.done = true;
                Some(Ok(header))
            }
        }
    }

    /// Parse tunnel header
    fn parse_tunnel(
        &mut self,
        tunnel_type: TunnelType,
    ) -> Option<Result<Header<'a>, PacketHeaderError>> {
        match tunnel_type {
            TunnelType::Vxlan => match VxlanHeader::from_bytes(self.remaining) {
                Ok((vxlan, rest)) => {
                    self.remaining = rest;
                    // VXLAN always encapsulates Ethernet
                    self.next_layer = NextLayer::Link(LinkType::Ethernet);
                    Some(Ok(Header::Vxlan(vxlan)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            TunnelType::Geneve => match GeneveHeader::from_bytes(self.remaining) {
                Ok((geneve, rest)) => {
                    // Determine next protocol based on Geneve protocol type
                    let inner_proto = geneve.protocol_type();
                    self.remaining = rest;
                    self.next_layer = NextLayer::Network(inner_proto);
                    Some(Ok(Header::Geneve(geneve)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            TunnelType::Gre => match GreHeader::from_bytes(self.remaining) {
                Ok((gre, rest)) => {
                    let inner_proto = gre.protocol_type();
                    self.remaining = rest;

                    // Check if this is NVGRE (Ethernet over GRE) or standard GRE
                    if inner_proto == EtherProto::TEB {
                        self.next_layer = NextLayer::Link(LinkType::Ethernet);
                    } else {
                        self.next_layer = NextLayer::Network(inner_proto);
                    }
                    Some(Ok(Header::Gre(gre)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            TunnelType::Mpls => {
                // Parse MPLS label stack
                match MplsLabelStack::parse(self.remaining) {
                    Some((mpls_stack, payload)) => {
                        self.remaining = payload;

                        // Determine inner protocol based on first nibble after MPLS
                        if let Some(next) = detect_mpls_inner_protocol(payload) {
                            self.next_layer = next;
                        } else {
                            self.next_layer = NextLayer::Done;
                        }
                        Some(Ok(Header::Mpls(mpls_stack)))
                    }
                    None => {
                        self.done = true;
                        Some(Err(PacketHeaderError::TooShort("MPLS")))
                    }
                }
            }
            TunnelType::Teredo => {
                // Parse Teredo packet (may include auth/origin indicators + IPv6)
                match TeredoPacket::parse(self.remaining) {
                    Ok(teredo) => {
                        // The payload is IPv6
                        self.remaining = teredo.ipv6_payload();
                        self.next_layer = NextLayer::Network(EtherProto::IPV6);
                        Some(Ok(Header::Teredo(Box::new(teredo))))
                    }
                    Err(e) => {
                        self.done = true;
                        Some(Err(e))
                    }
                }
            }
            TunnelType::Gtpv1 => match Gtpv1Header::from_bytes(self.remaining) {
                Ok((gtpv1, rest)) => {
                    self.remaining = rest;

                    // Check if this is a G-PDU (user data) with encapsulated IP
                    if gtpv1.is_gpdu() && !rest.is_empty() {
                        // Detect inner IP version from first nibble
                        let version = (rest[0] & 0xF0) >> 4;
                        match version {
                            4 => self.next_layer = NextLayer::Network(EtherProto::IPV4),
                            6 => self.next_layer = NextLayer::Network(EtherProto::IPV6),
                            _ => self.next_layer = NextLayer::Done,
                        }
                    } else {
                        // Control plane message - no further parsing
                        self.next_layer = NextLayer::Done;
                    }
                    Some(Ok(Header::Gtpv1(gtpv1)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            TunnelType::Gtpv2 => match Gtpv2Header::from_bytes(self.remaining) {
                Ok((gtpv2, rest)) => {
                    self.remaining = rest;
                    // GTPv2 is control plane only - no encapsulated user data
                    self.next_layer = NextLayer::Done;
                    Some(Ok(Header::Gtpv2(gtpv2)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            TunnelType::L2tpv2 => match L2tpv2Header::from_bytes(self.remaining) {
                Ok((l2tpv2, rest)) => {
                    self.remaining = rest;
                    // L2TPv2 data messages encapsulate PPP frames
                    // Control messages don't have inner payload to parse
                    // For now, we stop parsing as PPP parsing is not implemented
                    self.next_layer = NextLayer::Done;
                    Some(Ok(Header::L2tpv2(l2tpv2)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            TunnelType::L2tpv3 => {
                // L2TPv3 over IP - parse session header with no cookie (default)
                // Cookie length is negotiated out-of-band, so we use 0 as default
                match L2tpv3SessionHeader::parse_with_cookie_len(self.remaining, 0) {
                    Ok((l2tpv3, rest)) => {
                        self.remaining = rest;
                        // L2TPv3 can encapsulate various L2 protocols
                        // Most commonly Ethernet
                        if !rest.is_empty() {
                            // Try to detect inner protocol from first nibble
                            let first_byte = rest[0];
                            if first_byte == 0x00 || (first_byte & 0xF0) == 0x00 {
                                // Likely Ethernet (starts with destination MAC)
                                self.next_layer = NextLayer::Link(LinkType::Ethernet);
                            } else {
                                self.next_layer = NextLayer::Done;
                            }
                        } else {
                            self.next_layer = NextLayer::Done;
                        }
                        Some(Ok(Header::L2tpv3(l2tpv3)))
                    }
                    Err(e) => {
                        self.done = true;
                        Some(Err(e))
                    }
                }
            }
            TunnelType::Nvgre => match NvgreHeader::from_bytes(self.remaining) {
                Ok((nvgre, rest)) => {
                    self.remaining = rest;
                    // NVGRE always encapsulates Ethernet (TEB)
                    self.next_layer = NextLayer::Link(LinkType::Ethernet);
                    Some(Ok(Header::Nvgre(nvgre)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            TunnelType::Pbb => {
                // Parse PBB (Provider Backbone Bridge) header
                match PbbHeader::parse(self.remaining) {
                    Ok((pbb, rest)) => {
                        self.remaining = rest;
                        // PBB encapsulates customer Ethernet frames
                        self.next_layer = NextLayer::Link(LinkType::Ethernet);
                        Some(Ok(Header::Pbb(pbb)))
                    }
                    Err(e) => {
                        self.done = true;
                        Some(Err(e))
                    }
                }
            }
            TunnelType::Stt => {
                // Parse STT packet (includes TCP-like header + STT frame header)
                match SttPacket::parse(self.remaining) {
                    Some(stt) => {
                        self.remaining = stt.payload;
                        // STT encapsulates Ethernet frames
                        self.next_layer = NextLayer::Link(LinkType::Ethernet);
                        Some(Ok(Header::Stt(stt)))
                    }
                    None => {
                        self.done = true;
                        Some(Err(PacketHeaderError::TooShort("STT")))
                    }
                }
            }
            TunnelType::Pptp => match PptpGreHeader::from_bytes(self.remaining) {
                Ok((pptp, rest)) => {
                    self.remaining = rest;
                    // PPTP encapsulates PPP frames
                    // PPP parsing is not implemented, so we stop here
                    self.next_layer = NextLayer::Done;
                    Some(Ok(Header::Pptp(pptp)))
                }
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
        }
    }
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Result<Header<'a>, PacketHeaderError>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.remaining.is_empty() {
            self.done = true;
            return None;
        }

        match self.next_layer {
            NextLayer::Link(link_type) => self.parse_link(link_type),
            NextLayer::Network(ether_proto) => self.parse_network(ether_proto),
            NextLayer::Transport(ip_proto) => self.parse_transport(ip_proto),
            NextLayer::Tunnel(tunnel_type) => self.parse_tunnel(tunnel_type),
            NextLayer::Done => {
                self.done = true;
                None
            }
        }
    }
}

/// Extension trait to create a packet iterator from a buffer
pub trait PacketIterExt {
    /// Create an iterator over packet headers
    fn headers(&self, link_type: LinkType) -> PacketIter<'_>;
}

impl PacketIterExt for [u8] {
    fn headers(&self, link_type: LinkType) -> PacketIter<'_> {
        PacketIter::new(self, link_type)
    }
}

/// Collect all headers from a packet into a Vec
///
/// This is a convenience function that collects all headers, stopping at the first error.
///
/// # Returns
///
/// - `Ok(headers)` - All headers were parsed successfully
/// - `Err(e)` - An error occurred during parsing
///
/// # Example
///
/// ```
/// use packet_strata::packet::iter::{collect_headers, LinkType};
///
/// let packet = vec![/* ... */];
/// match collect_headers(&packet, LinkType::Ethernet) {
///     Ok(headers) => {
///         for header in headers {
///             println!("{}", header);
///         }
///     }
///     Err(e) => eprintln!("Parse error: {}", e),
/// }
/// ```
pub fn collect_headers(
    buf: &[u8],
    link_type: LinkType,
) -> Result<Vec<Header<'_>>, PacketHeaderError> {
    let mut headers = Vec::new();
    for result in PacketIter::new(buf, link_type) {
        headers.push(result?);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn test_structure_sizes() {
        use crate::packet::arp::ArpHeaderFull;
        use crate::packet::ether::EtherHeaderVlan;
        use crate::packet::ipv4::Ipv4HeaderOpt;
        use crate::packet::ipv6::Ipv6HeaderExt;
        use crate::packet::tcp::TcpHeaderOpt;
        use crate::packet::tunnel::geneve::GeneveHeaderOpt;
        use crate::packet::tunnel::gre::GreHeaderOpt;
        use crate::packet::tunnel::gtpv1::Gtpv1HeaderOpt;
        use crate::packet::tunnel::gtpv2::Gtpv2HeaderOpt;
        use crate::packet::tunnel::ipip::IpipTunnel;
        use crate::packet::tunnel::l2tp::{L2tpv2HeaderOpt, L2tpv3SessionHeaderCookie};
        use crate::packet::tunnel::mpls::MplsLabelStack;
        use crate::packet::tunnel::pbb::PbbHeader;
        use crate::packet::tunnel::pptp::PptpGreHeaderOpt;
        use crate::packet::tunnel::stt::SttPacket;
        use crate::packet::tunnel::teredo::TeredoPacket;

        println!("\n=== Structure Sizes ===");
        println!("PacketIter: {} bytes", size_of::<PacketIter>());
        println!("NextLayer: {} bytes", size_of::<NextLayer>());
        println!("TunnelType: {} bytes", size_of::<TunnelType>());
        println!("Header: {} bytes", size_of::<Header>());
        println!(
            "Option<Result<Header, PacketHeaderError>>: {} bytes",
            size_of::<Option<Result<Header, crate::packet::PacketHeaderError>>>()
        );
        println!("&[u8]: {} bytes", size_of::<&[u8]>());
        println!("EtherProto: {} bytes", size_of::<EtherProto>());
        println!("IpProto: {} bytes", size_of::<IpProto>());

        println!("\n=== Potential Optimization ===");
        println!(
            "Box<TeredoPacket>: {} bytes",
            size_of::<Box<TeredoPacket>>()
        );
        println!("Box<IpipTunnel>: {} bytes", size_of::<Box<IpipTunnel>>());
        println!("If we Box Teredo, Header would be ~40 bytes (IpipTunnel is largest)");
        println!("If we Box both Teredo and IpipTunnel, Header would be ~32 bytes (MplsLabelStack/EtherHeaderVlan)");

        println!("\n=== Header Variant Inner Types (sorted by size) ===");
        println!("\n=== Header Variant Inner Types (sorted by size) ===");
        println!(
            "TeredoPacket: {} bytes  <-- LARGEST, causes Header to be 104 bytes!",
            size_of::<TeredoPacket>()
        );
        println!(
            "IpipTunnel: {} bytes  <-- second largest",
            size_of::<IpipTunnel>()
        );
        println!("SttPacket: {} bytes", size_of::<SttPacket>());
        println!("MplsLabelStack: {} bytes", size_of::<MplsLabelStack>());
        println!("EtherHeaderVlan: {} bytes", size_of::<EtherHeaderVlan>());
        println!("Ipv4HeaderOpt: {} bytes", size_of::<Ipv4HeaderOpt>());
        println!("Ipv6HeaderExt: {} bytes", size_of::<Ipv6HeaderExt>());
        println!("ArpHeaderFull: {} bytes", size_of::<ArpHeaderFull>());
        println!("TcpHeaderOpt: {} bytes", size_of::<TcpHeaderOpt>());
        println!("GeneveHeaderOpt: {} bytes", size_of::<GeneveHeaderOpt>());
        println!("GreHeaderOpt: {} bytes", size_of::<GreHeaderOpt>());
        println!("Gtpv1HeaderOpt: {} bytes", size_of::<Gtpv1HeaderOpt>());
        println!("Gtpv2HeaderOpt: {} bytes", size_of::<Gtpv2HeaderOpt>());
        println!("L2tpv2HeaderOpt: {} bytes", size_of::<L2tpv2HeaderOpt>());
        println!(
            "L2tpv3SessionHeaderCookie: {} bytes",
            size_of::<L2tpv3SessionHeaderCookie>()
        );
        println!("PptpGreHeaderOpt: {} bytes", size_of::<PptpGreHeaderOpt>());
        println!("PbbHeader: {} bytes", size_of::<PbbHeader>());

        println!("\n=== Summary ===");
        println!(
            "Current Header size: {} bytes (dominated by TeredoPacket)",
            size_of::<Header>()
        );
        println!("Most common headers (Ethernet+IPv4+TCP) are only 24-32 bytes each");
        println!(
            "Every iteration copies {} bytes even for simple TCP packets!",
            size_of::<Header>()
        );
        println!("========================\n");
    }

    /// Create a minimal Ethernet + IPv4 + TCP packet for testing
    fn create_eth_ipv4_tcp_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, no options)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&40u16.to_be_bytes()); // Total length (20 + 20)
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(6); // Protocol: TCP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        // TCP header (20 bytes, no options)
        packet.extend_from_slice(&80u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&443u16.to_be_bytes()); // Dst port
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq num
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack num
        packet.push(0x50); // Data offset (5 << 4)
        packet.push(0x02); // Flags (SYN)
        packet.extend_from_slice(&[0x00, 0x00]); // Window
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

        packet
    }

    /// Create a minimal Ethernet + IPv4 + UDP packet for testing
    fn create_eth_ipv4_udp_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&28u16.to_be_bytes()); // Total length (20 + 8)
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // UDP header (8 bytes)
        packet.extend_from_slice(&53u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&53u16.to_be_bytes()); // Dst port
        packet.extend_from_slice(&8u16.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        packet
    }

    /// Create a minimal Ethernet + ARP packet for testing
    fn create_eth_arp_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // Dest MAC (broadcast)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP

        // ARP header (28 bytes for Ethernet/IPv4)
        packet.extend_from_slice(&1u16.to_be_bytes()); // Hardware type: Ethernet
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // Protocol type: IPv4
        packet.push(6); // Hardware addr len
        packet.push(4); // Protocol addr len
        packet.extend_from_slice(&1u16.to_be_bytes()); // Operation: Request

        // Sender hardware address
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Sender protocol address
        packet.extend_from_slice(&[192, 168, 1, 1]);
        // Target hardware address
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Target protocol address
        packet.extend_from_slice(&[192, 168, 1, 2]);

        packet
    }

    #[test]
    fn test_eth_ipv4_tcp_iteration() {
        let packet = create_eth_ipv4_tcp_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // First: Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));
        assert_eq!(header.name(), "Ethernet");
        assert!(header.is_link_layer());

        // Second: IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));
        assert_eq!(header.name(), "IPv4");
        assert!(header.is_network_layer());

        // Third: TCP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Tcp(_)));
        assert_eq!(header.name(), "TCP");
        assert!(header.is_transport_layer());

        // Done
        assert!(iter.next().is_none());
        assert!(iter.is_done());
    }

    #[test]
    fn test_eth_ipv4_udp_iteration() {
        let packet = create_eth_ipv4_udp_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // UDP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Udp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_eth_arp_iteration() {
        let packet = create_eth_arp_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // ARP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Arp(_)));

        // Done (ARP is terminal)
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_raw_ipv4_iteration() {
        let packet = create_eth_ipv4_tcp_packet();
        // Skip Ethernet header (14 bytes) to get raw IPv4
        let ipv4_packet = &packet[14..];

        let mut iter = PacketIter::new(ipv4_packet, LinkType::RawIpv4);

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // TCP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Tcp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_null_loopback_ipv4_iteration() {
        // Null/Loopback header (4 bytes) + IPv4 + TCP
        let mut packet = Vec::new();

        // Null header: AF_INET = 2 (little-endian)
        packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&40u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(6); // Protocol: TCP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[127, 0, 0, 1]); // Src IP (localhost)
        packet.extend_from_slice(&[127, 0, 0, 1]); // Dst IP (localhost)

        // TCP header (20 bytes)
        packet.extend_from_slice(&8080u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&80u16.to_be_bytes()); // Dst port
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq num
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack num
        packet.push(0x50); // Data offset (5 words)
        packet.push(0x02); // Flags: SYN
        packet.extend_from_slice(&[0x00, 0x00]); // Window
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

        let mut iter = PacketIter::new(&packet, LinkType::Null);

        // Null header
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Null(_)));
        assert_eq!(header.name(), "Null/Loopback");

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // TCP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Tcp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_null_loopback_ipv6_iteration() {
        // Null/Loopback header (4 bytes) + IPv6 + UDP
        let mut packet = Vec::new();

        // Null header: AF_INET6 = 30 on macOS (little-endian)
        packet.extend_from_slice(&[0x1e, 0x00, 0x00, 0x00]);

        // IPv6 header (40 bytes)
        packet.push(0x60); // Version 6
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // Traffic class, Flow label
        packet.extend_from_slice(&8u16.to_be_bytes()); // Payload length
        packet.push(17); // Next header: UDP
        packet.push(64); // Hop limit
                         // Source address (::1)
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Destination address (::1)
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        // UDP header (8 bytes)
        packet.extend_from_slice(&53u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&53u16.to_be_bytes()); // Dst port
        packet.extend_from_slice(&8u16.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        let mut iter = PacketIter::new(&packet, LinkType::Null);

        // Null header
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Null(_)));

        // IPv6
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv6(_)));

        // UDP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Udp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_from_network_layer() {
        let packet = create_eth_ipv4_tcp_packet();
        // Skip Ethernet header (14 bytes)
        let ipv4_packet = &packet[14..];

        let mut iter = PacketIter::from_network_layer(ipv4_packet, EtherProto::IPV4);

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // TCP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Tcp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_from_transport_layer() {
        let packet = create_eth_ipv4_tcp_packet();
        // Skip Ethernet (14) + IPv4 (20) headers
        let tcp_packet = &packet[34..];

        let mut iter = PacketIter::from_transport_layer(tcp_packet, IpProto::TCP);

        // TCP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Tcp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_remaining_payload() {
        let mut packet = create_eth_ipv4_tcp_packet();
        // Add some payload
        packet.extend_from_slice(b"Hello, World!");

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Consume all headers
        while iter.next().is_some() {}

        // Check remaining payload
        assert_eq!(iter.remaining(), b"Hello, World!");
    }

    #[test]
    fn test_error_on_short_buffer() {
        let packet = vec![0u8; 5]; // Too short for any header

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        let result = iter.next().unwrap();
        assert!(result.is_err());

        // Iterator should be fused
        assert!(iter.is_done());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_unknown_ether_proto() {
        let mut packet = Vec::new();

        // Ethernet header with unknown EtherType
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x99, 0x99]); // Unknown EtherType

        // Some payload
        packet.extend_from_slice(b"unknown protocol data");

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // Unknown
        let header = iter.next().unwrap().unwrap();
        assert!(header.is_unknown());
        if let Header::Unknown { proto, data } = header {
            assert!(matches!(proto, UnknownProto::Ether(_)));
            assert_eq!(data, b"unknown protocol data");
        }

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_unknown_ip_proto() {
        let mut packet = Vec::new();

        // Ethernet header
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header with unknown protocol
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&30u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(200); // Protocol: Unknown (200)
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        // Some payload
        packet.extend_from_slice(b"unknown");

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        iter.next().unwrap().unwrap();

        // IPv4
        iter.next().unwrap().unwrap();

        // Unknown
        let header = iter.next().unwrap().unwrap();
        assert!(header.is_unknown());
        if let Header::Unknown { proto, .. } = header {
            assert!(matches!(proto, UnknownProto::Ip(_)));
        }

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_collect_headers() {
        let packet = create_eth_ipv4_tcp_packet();

        let headers = collect_headers(&packet, LinkType::Ethernet).unwrap();

        assert_eq!(headers.len(), 3);
        assert!(matches!(headers[0], Header::Ethernet(_)));
        assert!(matches!(headers[1], Header::Ipv4(_)));
        assert!(matches!(headers[2], Header::Tcp(_)));
    }

    #[test]
    fn test_collect_headers_error() {
        let packet = vec![0u8; 5]; // Too short

        let result = collect_headers(&packet, LinkType::Ethernet);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_buffer() {
        let packet: Vec<u8> = vec![];
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        assert!(iter.next().is_none());
        assert!(iter.is_done());
    }

    #[test]
    fn test_packet_iter_ext_trait() {
        let packet = create_eth_ipv4_tcp_packet();

        let headers: Vec<_> = packet
            .headers(LinkType::Ethernet)
            .filter_map(Result::ok)
            .collect();

        assert_eq!(headers.len(), 3);
    }

    #[test]
    fn test_header_display() {
        let packet = create_eth_ipv4_tcp_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        while let Some(Ok(header)) = iter.next() {
            // Just make sure Display doesn't panic
            let _ = format!("{}", header);
        }
    }

    /// Create a minimal Ethernet + IPv6 + ICMPv6 packet for testing
    fn create_eth_ipv6_icmp6_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x86, 0xdd]); // EtherType: IPv6

        // IPv6 header (40 bytes)
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, TC, Flow Label
        packet.extend_from_slice(&8u16.to_be_bytes()); // Payload length (ICMPv6 header)
        packet.push(58); // Next Header: ICMPv6
        packet.push(64); // Hop Limit
                         // Source IPv6 (16 bytes) - ::1
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Dest IPv6 (16 bytes) - ::2
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        // ICMPv6 Echo Request (8 bytes)
        packet.push(128); // Type: Echo Request
        packet.push(0); // Code
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x01]); // Identifier
        packet.extend_from_slice(&[0x00, 0x01]); // Sequence

        packet
    }

    /// Create an Ethernet + IPv6 + UDP packet for testing
    fn create_eth_ipv6_udp_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x86, 0xdd]); // EtherType: IPv6

        // IPv6 header (40 bytes)
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, TC, Flow Label
        packet.extend_from_slice(&8u16.to_be_bytes()); // Payload length (UDP header)
        packet.push(17); // Next Header: UDP
        packet.push(64); // Hop Limit
                         // Source IPv6 (16 bytes)
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Dest IPv6 (16 bytes)
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        // UDP header (8 bytes)
        packet.extend_from_slice(&53u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&53u16.to_be_bytes()); // Dst port
        packet.extend_from_slice(&8u16.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        packet
    }

    #[test]
    fn test_eth_ipv6_icmp6_iteration() {
        let packet = create_eth_ipv6_icmp6_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPv6
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv6(_)));
        assert_eq!(header.name(), "IPv6");

        // ICMPv6
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Icmp6(_)));
        assert_eq!(header.name(), "ICMPv6");

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_eth_ipv6_udp_iteration() {
        let packet = create_eth_ipv6_udp_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPv6
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv6(_)));

        // UDP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Udp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_raw_ipv6_iteration() {
        let packet = create_eth_ipv6_udp_packet();
        // Skip Ethernet header (14 bytes) to get raw IPv6
        let ipv6_packet = &packet[14..];

        let mut iter = PacketIter::new(ipv6_packet, LinkType::RawIpv6);

        // IPv6
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv6(_)));

        // UDP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Udp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    // ==================== TUNNEL TESTS ====================

    /// Create Ethernet + IPv4 + UDP + VXLAN + inner Ethernet + inner IPv4 packet
    fn create_vxlan_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Outer Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // Outer IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&72u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // Outer UDP header (8 bytes)
        packet.extend_from_slice(&12345u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&4789u16.to_be_bytes()); // Dst port (VXLAN)
        packet.extend_from_slice(&52u16.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        // VXLAN header (8 bytes)
        packet.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // Flags (I=1)
        packet.extend_from_slice(&[0x00, 0x00, 0x64, 0x00]); // VNI = 100

        // Inner Ethernet header (14 bytes)
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // Dest MAC
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // Inner IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&20u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(6); // Protocol: TCP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        packet
    }

    #[test]
    fn test_vxlan_tunnel_iteration() {
        let packet = create_vxlan_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Outer Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));
        assert!(header.is_link_layer());

        // Outer IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));
        assert!(header.is_network_layer());

        // Outer UDP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Udp(_)));
        assert!(header.is_transport_layer());

        // VXLAN
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Vxlan(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "VXLAN");

        // Inner Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // Inner IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // No TCP header in our test packet (just IPv4 with protocol=TCP)
        // The iterator would try to parse TCP but we don't have the bytes
    }

    /// Create Ethernet + IPv4 + GRE + inner IPv4 packet
    fn create_gre_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Outer Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // Outer IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&44u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(47); // Protocol: GRE
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // GRE header (4 bytes, no options)
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Version
        packet.extend_from_slice(&[0x08, 0x00]); // Protocol: IPv4

        // Inner IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&28u16.to_be_bytes()); // Total length (20 + 8 ICMP)
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(1); // Protocol: ICMP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        // ICMP Echo Request (8 bytes)
        packet.push(8); // Type: Echo Request
        packet.push(0); // Code
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x01]); // Identifier
        packet.extend_from_slice(&[0x00, 0x01]); // Sequence

        packet
    }

    #[test]
    fn test_gre_tunnel_iteration() {
        let packet = create_gre_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Outer Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // Outer IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // GRE
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Gre(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "GRE");

        // Inner IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // ICMP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Icmp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    /// Create Ethernet + MPLS + IPv4 packet
    fn create_mpls_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x88, 0x47]); // EtherType: MPLS Unicast

        // MPLS label (4 bytes) - Label=1000, TC=0, S=1 (bottom), TTL=64
        // Label (20 bits) = 1000 = 0x3E8
        // TC (3 bits) = 0
        // S (1 bit) = 1 (bottom of stack)
        // TTL (8 bits) = 64 = 0x40
        // Combined: 0x003E8140
        packet.extend_from_slice(&[0x00, 0x3E, 0x81, 0x40]);

        // Inner IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&28u16.to_be_bytes()); // Total length (20 + 8 UDP)
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // UDP header (8 bytes)
        packet.extend_from_slice(&53u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&53u16.to_be_bytes()); // Dst port
        packet.extend_from_slice(&8u16.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        packet
    }

    #[test]
    fn test_mpls_tunnel_iteration() {
        let packet = create_mpls_packet();
        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // MPLS
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Mpls(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "MPLS");

        // Inner IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // UDP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Udp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ip_in_ip_encapsulation() {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // Outer IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&40u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(4); // Protocol: IP-in-IP (IPIP)
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // Inner IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&28u16.to_be_bytes()); // Total length (20 + 8 ICMP)
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(1); // Protocol: ICMP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        // ICMP Echo Request (8 bytes)
        packet.push(8); // Type: Echo Request
        packet.push(0); // Code
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x01]); // Identifier
        packet.extend_from_slice(&[0x00, 0x01]); // Sequence

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPIP tunnel (wraps outer IPv4)
        let header = iter.next().unwrap().unwrap();
        assert!(
            matches!(header, Header::Ipip(_)),
            "Expected Ipip, got {:?}",
            header
        );
        if let Header::Ipip(tunnel) = &header {
            assert_eq!(
                tunnel.tunnel_type(),
                super::super::tunnel::ipip::IpipType::Ipip
            );
            assert!(tunnel.outer_ipv4().is_some());
        }

        // Inner IPv4 (after decapsulation)
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // ICMP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Icmp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_header_is_tunnel() {
        let packet = create_vxlan_packet();
        let headers: Vec<_> = PacketIter::new(&packet, LinkType::Ethernet)
            .filter_map(Result::ok)
            .collect();

        // Count tunnel headers
        let tunnel_count = headers.iter().filter(|h| h.is_tunnel()).count();
        assert_eq!(tunnel_count, 1); // Only VXLAN is a tunnel
    }

    #[test]
    fn test_collect_headers_with_tunnel() {
        let packet = create_gre_packet();

        let headers = collect_headers(&packet, LinkType::Ethernet).unwrap();

        // Should have: Ethernet, IPv4, GRE, IPv4, ICMP
        assert_eq!(headers.len(), 5);
        assert!(matches!(headers[0], Header::Ethernet(_)));
        assert!(matches!(headers[1], Header::Ipv4(_)));
        assert!(matches!(headers[2], Header::Gre(_)));
        assert!(matches!(headers[3], Header::Ipv4(_)));
        assert!(matches!(headers[4], Header::Icmp(_)));
    }

    #[test]
    fn test_l2tpv2_tunnel_detection() {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&38u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // UDP header (8 bytes)
        packet.extend_from_slice(&1701u16.to_be_bytes()); // Src port: L2TP
        packet.extend_from_slice(&1701u16.to_be_bytes()); // Dst port: L2TP
        packet.extend_from_slice(&18u16.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        // L2TPv2 header (minimal data message - 6 bytes)
        // Flags: 0x0002 (version 2, data message)
        packet.extend_from_slice(&0x0002u16.to_be_bytes()); // Flags/version
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Tunnel ID
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Session ID

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // UDP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Udp(_)));

        // L2TPv2
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::L2tpv2(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "L2TPv2");
    }

    #[test]
    fn test_nvgre_tunnel_detection() {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&44u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(47); // Protocol: GRE
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // NVGRE header (8 bytes): Key flag set, version 0, TEB protocol
        packet.extend_from_slice(&0x2000u16.to_be_bytes()); // Flags: Key present
        packet.extend_from_slice(&0x6558u16.to_be_bytes()); // Protocol: TEB
        packet.extend_from_slice(&0x00010001u32.to_be_bytes()); // VSID + FlowID

        // Inner Ethernet (14 bytes minimum)
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // Dest MAC
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // NVGRE
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Nvgre(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "NVGRE");

        // Inner Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));
    }

    #[test]
    fn test_pptp_tunnel_detection() {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&32u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(47); // Protocol: GRE
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // PPTP GRE header (Enhanced GRE version 1)
        // Flags: Key + Sequence, Version 1
        packet.extend_from_slice(&0x3001u16.to_be_bytes()); // K + S flags, version 1
        packet.extend_from_slice(&0x880Bu16.to_be_bytes()); // Protocol: PPP
        packet.extend_from_slice(&0x0004u16.to_be_bytes()); // Payload length
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Call ID
        packet.extend_from_slice(&0x00000001u32.to_be_bytes()); // Sequence number

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // PPTP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Pptp(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "PPTP");
    }

    #[test]
    fn test_pbb_tunnel_detection() {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes) - Backbone addresses
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // B-DA
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // B-SA
        packet.extend_from_slice(&[0x88, 0xE7]); // EtherType: PBB I-Tag (802.1ah)

        // I-Tag (6 bytes)
        packet.extend_from_slice(&[0x88, 0xE7]); // EtherType in I-Tag
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TCI + I-SID

        // Inner Ethernet (customer frame - 14 bytes)
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // C-DA
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // C-SA
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Backbone Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // PBB
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Pbb(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "PBB");

        // Customer Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));
    }

    #[test]
    fn test_stt_tunnel_detection() {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&100u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(6); // Protocol: TCP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // TCP header (20 bytes) - pointing to STT port 7471
        packet.extend_from_slice(&12345u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&7471u16.to_be_bytes()); // Dst port: STT
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq num
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack num
        packet.push(0x50); // Data offset (5 << 4)
        packet.push(0x02); // Flags (SYN)
        packet.extend_from_slice(&[0x00, 0x00]); // Window
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

        // STT TCP-like header (20 bytes)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Src port (unused)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Dst port (unused)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Seq (total len + frag offset)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack (fragment ID)
        packet.push(0x50); // Data offset
        packet.push(0x00); // Flags
        packet.extend_from_slice(&[0x00, 0x00]); // Window
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent

        // STT Frame Header (18 bytes)
        packet.push(0x00); // Version
        packet.push(0x00); // Flags
        packet.push(0x00); // L4 offset
        packet.push(0x00); // Reserved
        packet.extend_from_slice(&[0x00, 0x00]); // MSS
        packet.extend_from_slice(&[0x00, 0x00]); // VLAN TCI
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // Context ID
        packet.extend_from_slice(&[0x00, 0x00]); // Padding

        // Inner Ethernet frame (minimum 14 bytes header + 2 bytes for EtherType parsing)
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // Dest MAC
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
                                                 // Add minimal inner IPv4 header so Ethernet parsing succeeds
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&20u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(1); // Protocol: ICMP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));

        // TCP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Tcp(_)));

        // STT
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Stt(_)));
        assert!(header.is_tunnel());
        assert_eq!(header.name(), "STT");

        // Inner Ethernet
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ethernet(_)));

        // Inner IPv4
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Ipv4(_)));
    }

    #[test]
    fn test_gre_variant_detection() {
        // Test that standard GRE (version 0, no TEB) is detected correctly
        let mut packet = Vec::new();

        // Ethernet header
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        packet.extend_from_slice(&[0x08, 0x00]);

        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&32u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(47); // GRE
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[10, 0, 0, 2]);

        // Standard GRE header (version 0, IPv4 protocol)
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // No flags, version 0
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // Protocol: IPv4

        // Inner IPv4
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&20u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(1); // ICMP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[192, 168, 1, 1]);
        packet.extend_from_slice(&[192, 168, 1, 2]);

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        iter.next(); // Ethernet
        iter.next(); // IPv4

        // Should be standard GRE, not NVGRE or PPTP
        let header = iter.next().unwrap().unwrap();
        assert!(matches!(header, Header::Gre(_)));
        assert_eq!(header.name(), "GRE");
    }

    #[test]
    fn test_guess_link_type_raw_ipv4() {
        // Raw IPv4 packet (version 4, IHL 5)
        let packet = vec![
            0x45, 0x00, 0x00, 0x28, // IPv4 header start
            0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, // TTL, TCP, checksum
            0xc0, 0xa8, 0x01, 0x01, // Src IP
            0xc0, 0xa8, 0x01, 0x02, // Dst IP
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::RawIpv4);
    }

    #[test]
    fn test_guess_link_type_raw_ipv6() {
        // Raw IPv6 packet (version 6)
        let packet = vec![
            0x60, 0x00, 0x00, 0x00, // IPv6 header start
            0x00, 0x14, 0x06, 0x40, // Payload len, next header (TCP), hop limit
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::RawIpv6);
    }

    #[test]
    fn test_guess_link_type_null_ipv4() {
        // Null/Loopback with AF_INET (2) little-endian, followed by IPv4
        let packet = vec![
            0x02, 0x00, 0x00, 0x00, // AF_INET
            0x45, 0x00, 0x00, 0x28, // IPv4 follows
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Null);
    }

    #[test]
    fn test_guess_link_type_null_ipv6_darwin() {
        // Null/Loopback with AF_INET6 (30) little-endian on macOS, followed by IPv6
        let packet = vec![
            0x1e, 0x00, 0x00, 0x00, // AF_INET6 (Darwin)
            0x60, 0x00, 0x00, 0x00, // IPv6 follows
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Null);
    }

    #[test]
    fn test_guess_link_type_ethernet_ipv4() {
        // Ethernet frame with IPv4
        let packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Src MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, 0x00, // IPv4 header
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Ethernet);
    }

    #[test]
    fn test_guess_link_type_ethernet_ipv6() {
        // Ethernet frame with IPv6
        let packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Src MAC
            0x86, 0xdd, // EtherType: IPv6
            0x60, 0x00, // IPv6 header
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Ethernet);
    }

    #[test]
    fn test_guess_link_type_ethernet_arp() {
        // Ethernet frame with ARP
        let packet = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dest MAC (broadcast)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
            0x08, 0x06, // EtherType: ARP
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Ethernet);
    }

    #[test]
    fn test_guess_link_type_sll() {
        // SLL header (16 bytes)
        let packet = vec![
            0x00, 0x00, // Packet type: Host
            0x00, 0x01, // ARPHRD: Ethernet
            0x00, 0x06, // Address length
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Link-layer addr
            0x00, 0x00, // Padding
            0x08, 0x00, // Protocol: IPv4
            0x45, 0x00, // IPv4 data
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Sll);
    }

    #[test]
    fn test_guess_link_type_sllv2() {
        // SLLv2 header (20 bytes)
        let packet = vec![
            0x08, 0x00, // Protocol: IPv4
            0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x02, // Interface index
            0x00, 0x01, // ARPHRD: Ethernet
            0x00, // Packet type: Host
            0x06, // Address length
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Link-layer addr
            0x00, 0x00, // Padding
        ];
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Sllv2);
    }

    #[test]
    fn test_guess_link_type_empty() {
        let packet: Vec<u8> = vec![];
        // Default to Ethernet for empty buffer
        assert_eq!(PacketIter::guess_link_type(&packet), LinkType::Ethernet);
    }

    #[test]
    fn test_guess_constructor_ipv4() {
        // Raw IPv4 packet
        let packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
        ];

        let link_type = PacketIter::guess_link_type(&packet);
        let mut iter = PacketIter::new(&packet, link_type);
        let first = iter.next().unwrap().unwrap();
        assert!(matches!(first, Header::Ipv4(_)));
    }

    #[test]
    fn test_guess_constructor_ethernet() {
        let packet = create_eth_ipv4_tcp_packet();
        let link_type = PacketIter::guess_link_type(&packet);
        let mut iter = PacketIter::new(&packet, link_type);

        let first = iter.next().unwrap().unwrap();
        assert!(matches!(first, Header::Ethernet(_)));

        let second = iter.next().unwrap().unwrap();
        assert!(matches!(second, Header::Ipv4(_)));
    }

    #[test]
    fn test_gre_over_raw_ip() {
        // Same packet but with explicit LinkType::RawIpv4
        let mut packet = Vec::new();

        // Outer IPv4 header (20 bytes)
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&52u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(47); // GRE
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[10, 0, 0, 2]);

        // GRE header
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x08, 0x00]); // IPv4

        // Inner IPv4
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&28u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(1); // ICMP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[192, 168, 1, 1]);
        packet.extend_from_slice(&[192, 168, 1, 2]);

        // ICMP
        packet.push(8);
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x01]);

        let mut iter = PacketIter::new(&packet, LinkType::RawIpv4);

        // First: outer IPv4
        let h1 = iter.next().unwrap().unwrap();
        assert!(matches!(h1, Header::Ipv4(_)));
        if let Header::Ipv4(ipv4) = h1 {
            assert_eq!(ipv4.protocol(), IpProto::GRE);
        }

        // Second: GRE
        let h2 = iter.next().unwrap().unwrap();
        assert!(matches!(h2, Header::Gre(_)));

        // Third: inner IPv4
        let h3 = iter.next().unwrap().unwrap();
        assert!(matches!(h3, Header::Ipv4(_)));
        if let Header::Ipv4(ipv4) = h3 {
            assert_eq!(ipv4.protocol(), IpProto::ICMP);
        }

        // Fourth: ICMP
        let h4 = iter.next().unwrap().unwrap();
        assert!(matches!(h4, Header::Icmp(_)));

        // Done
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_gre_over_ethernet_ospf_packet() {
        // Real captured packet: Ethernet + IPv4 + GRE + inner IPv4 (OSPF)
        let packet: Vec<u8> = vec![
            0xcc, 0x01, 0x0f, 0x80, 0x00, 0x00, 0xcc, 0x00, 0x0f, 0x80, 0x00, 0x00, 0x08, 0x00,
            0x45, 0xc0, 0x00, 0x64, 0x00, 0x0f, 0x00, 0x00, 0xff, 0x2f, 0x16, 0x47, 0xc0, 0xa8,
            0x0c, 0x01, 0xc0, 0xa8, 0x17, 0x03, 0x00, 0x00, 0x08, 0x00, 0x45, 0xc0, 0x00, 0x4c,
            0x00, 0x27, 0x00, 0x00, 0x01, 0x59, 0x0a, 0xc4, 0xc0, 0xa8, 0x0d, 0x01, 0xe0, 0x00,
            0x00, 0x05, 0x02, 0x01, 0x00, 0x2c, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0xea, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0x00, 0x00, 0x0a, 0x12, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xf6, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x01,
        ];

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // First: Ethernet (EtherType 0x0800 = IPv4)
        let h1 = iter.next().unwrap().unwrap();
        assert!(matches!(h1, Header::Ethernet(_)));
        if let Header::Ethernet(eth) = h1 {
            assert_eq!(eth.protocol(), EtherProto::IPV4);
        }

        // Second: outer IPv4 (protocol 0x2f = 47 = GRE)
        let h2 = iter.next().unwrap().unwrap();
        assert!(matches!(h2, Header::Ipv4(_)));
        if let Header::Ipv4(ipv4) = h2 {
            assert_eq!(ipv4.protocol(), IpProto::GRE);
        }

        // Third: GRE (protocol 0x0800 = IPv4)
        let h3 = iter.next().unwrap().unwrap();
        assert!(matches!(h3, Header::Gre(_)), "Expected GRE, got {:?}", h3);

        // Fourth: inner IPv4 (protocol 0x59 = 89 = OSPF)
        let h4 = iter.next().unwrap().unwrap();
        assert!(matches!(h4, Header::Ipv4(_)));
        if let Header::Ipv4(ipv4) = h4 {
            assert_eq!(ipv4.protocol(), IpProto::from(89u8)); // OSPF
        }

        // Fifth: Unknown (OSPF is not parsed, should be Unknown)
        let h5 = iter.next().unwrap().unwrap();
        assert!(
            matches!(h5, Header::Unknown { .. }),
            "Expected Unknown for OSPF, got {:?}",
            h5
        );
    }

    #[test]
    fn test_ipv4_in_ipv6_tunnel() {
        // Real captured packet: Ethernet + IPv6 + IPv4 + TCP (IPv4-in-IPv6 tunnel)
        // IPv6 next header = 4 (IPIP = IPv4 encapsulated in IPv6)
        let packet: Vec<u8> = vec![
            0x00, 0x90, 0x1a, 0x41, 0x65, 0x41, 0x00, 0x16, 0xcf, 0x41, 0x9c, 0x20, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x04, 0x40, 0x20, 0x02, 0x46, 0x37, 0xd5, 0xd3,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x37, 0xd5, 0xd3, 0x20, 0x01, 0x48, 0x60,
            0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x45, 0x00,
            0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x3b, 0x6b, 0x46, 0x37, 0xd5, 0xd3,
            0xc0, 0x58, 0x63, 0x01, 0x7a, 0x69, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xd5, 0xc4, 0x00, 0x00,
        ];

        let mut iter = PacketIter::new(&packet, LinkType::Ethernet);

        // First: Ethernet (EtherType 0x86dd = IPv6)
        let h1 = iter.next().unwrap().unwrap();
        assert!(
            matches!(h1, Header::Ethernet(_)),
            "Expected Ethernet, got {:?}",
            h1
        );
        if let Header::Ethernet(eth) = h1 {
            assert_eq!(eth.protocol(), EtherProto::IPV6);
        }

        // Second: IP4in6 tunnel (wraps outer IPv6 with next header = 4)
        let h2 = iter.next().unwrap().unwrap();
        assert!(matches!(h2, Header::Ipip(_)), "Expected Ipip, got {:?}", h2);
        if let Header::Ipip(tunnel) = &h2 {
            assert_eq!(
                tunnel.tunnel_type(),
                super::super::tunnel::ipip::IpipType::Ip4in6,
                "Expected Ip4in6 tunnel type, got {:?}",
                tunnel.tunnel_type()
            );
            assert!(tunnel.outer_ipv6().is_some());
            let outer = tunnel.outer_ipv6().unwrap();
            assert_eq!(outer.next_header(), IpProto::from(4u8));
        }

        // Third: inner IPv4 (protocol 6 = TCP)
        let h3 = iter.next().unwrap().unwrap();
        assert!(matches!(h3, Header::Ipv4(_)), "Expected Ipv4, got {:?}", h3);
        if let Header::Ipv4(ipv4) = h3 {
            assert_eq!(ipv4.protocol(), IpProto::TCP);
        }

        // Fourth: TCP
        let h4 = iter.next().unwrap().unwrap();
        assert!(matches!(h4, Header::Tcp(_)), "Expected Tcp, got {:?}", h4);

        // Done
        assert!(iter.next().is_none());
    }
}
