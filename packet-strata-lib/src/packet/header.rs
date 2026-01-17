//! Header enum wrapper for all supported packet headers
//!
//! This module provides the [`Header`] enum which wraps all supported protocol headers
//! and [`UnknownProto`] for representing unknown/unsupported protocols.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::ether::EthAddr;

use super::arp::ArpHeaderFull;
use super::ether::EtherHeaderVlan;
use super::icmp::IcmpHeader;
use super::icmp6::Icmp6Header;
use super::ipv4::Ipv4HeaderOpt;
use super::ipv6::Ipv6HeaderExt;
use super::null::NullHeader;
use super::protocol::{EtherProto, IpProto};
use super::sctp::SctpHeader;
use super::sll::{SllHeader, Sllv2Header};
use super::tcp::TcpHeaderOpt;
use super::tunnel::geneve::GeneveHeaderOpt;
use super::tunnel::gre::GreHeaderOpt;
use super::tunnel::gtpv1::Gtpv1HeaderOpt;
use super::tunnel::gtpv2::Gtpv2HeaderOpt;
use super::tunnel::ipip::IpipTunnel;
use super::tunnel::l2tp::{L2tpv2HeaderOpt, L2tpv3SessionHeaderCookie};
use super::tunnel::mpls::MplsLabelStack;
use super::tunnel::nvgre::NvgreHeader;
use super::tunnel::pbb::PbbHeader;
use super::tunnel::pptp::PptpGreHeaderOpt;
use super::tunnel::stt::SttPacket;
use super::tunnel::teredo::TeredoPacket;
use super::tunnel::vxlan::VxlanHeader;
use super::udp::UdpHeader;

/// Represents an unknown/unsupported protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownProto {
    /// Unknown Ethernet protocol type
    Ether(EtherProto),
    /// Unknown IP protocol number
    Ip(IpProto),
    /// Unknown tunnel encapsulation
    Tunnel(&'static str),
}

impl std::fmt::Display for UnknownProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnknownProto::Ether(p) => write!(f, "EtherType(0x{:04x})", p.0.get()),
            UnknownProto::Ip(p) => write!(f, "IpProto({})", u8::from(*p)),
            UnknownProto::Tunnel(name) => write!(f, "Tunnel({})", name),
        }
    }
}

/// Enum wrapper for all supported packet headers
///
/// This enum provides a unified way to handle different protocol headers
/// when iterating through a packet's protocol stack.
pub enum Header<'a> {
    /// Ethernet II header (possibly with VLAN tags)
    Ethernet(EtherHeaderVlan<'a>),

    /// Linux cooked capture v1 header
    Sll(&'a SllHeader),

    /// Linux cooked capture v2 header
    Sllv2(&'a Sllv2Header),

    /// BSD Null/Loopback header
    Null(&'a NullHeader),

    /// IPv4 header with options
    Ipv4(Ipv4HeaderOpt<'a>),

    /// IPv6 header with extension headers
    Ipv6(Ipv6HeaderExt<'a>),

    /// ARP header with addresses
    Arp(ArpHeaderFull<'a>),

    /// TCP header with options
    Tcp(TcpHeaderOpt<'a>),

    /// UDP header
    Udp(&'a UdpHeader),

    /// SCTP header
    Sctp(&'a SctpHeader),

    /// ICMPv4 header
    Icmp(&'a IcmpHeader),

    /// ICMPv6 header
    Icmp6(&'a Icmp6Header),

    /// VXLAN tunnel header
    Vxlan(&'a VxlanHeader),

    /// Geneve tunnel header with options
    Geneve(GeneveHeaderOpt<'a>),

    /// GRE tunnel header with options
    Gre(GreHeaderOpt<'a>),

    /// MPLS label stack
    Mpls(MplsLabelStack<'a>),

    /// Teredo tunnel (parsed packet includes auth/origin indicators)
    /// Boxed to reduce Header enum size (TeredoPacket is 96 bytes)
    Teredo(Box<TeredoPacket<'a>>),

    /// GTPv1 header with options
    Gtpv1(Gtpv1HeaderOpt<'a>),

    /// GTPv2 header with options
    Gtpv2(Gtpv2HeaderOpt<'a>),

    /// L2TPv2 header with options
    L2tpv2(L2tpv2HeaderOpt<'a>),

    /// L2TPv3 session header with cookie
    L2tpv3(L2tpv3SessionHeaderCookie<'a>),

    /// NVGRE header (Network Virtualization using GRE)
    Nvgre(&'a NvgreHeader),

    /// PBB header (Provider Backbone Bridge / MAC-in-MAC)
    Pbb(PbbHeader<'a>),

    /// STT packet (Stateless Transport Tunneling)
    Stt(SttPacket<'a>),

    /// PPTP GRE header with options
    Pptp(PptpGreHeaderOpt<'a>),

    /// IP-in-IP tunnel (IPIP, SIT, IP4in6, IP6Tnl)
    Ipip(IpipTunnel<'a>),

    /// Unknown/unsupported protocol
    ///
    /// Contains the protocol identifier and the remaining unparsed data.
    Unknown {
        /// The protocol that couldn't be parsed
        proto: UnknownProto,
        /// The remaining unparsed data
        data: &'a [u8],
    },
}

impl<'a> Header<'a> {
    /// Returns the name of the protocol
    pub fn name(&self) -> &'static str {
        match self {
            Header::Ethernet(_) => "Ethernet",
            Header::Sll(_) => "SLL",
            Header::Sllv2(_) => "SLLv2",
            Header::Null(_) => "Null/Loopback",
            Header::Ipv4(_) => "IPv4",
            Header::Ipv6(_) => "IPv6",
            Header::Arp(_) => "ARP",
            Header::Tcp(_) => "TCP",
            Header::Udp(_) => "UDP",
            Header::Sctp(_) => "SCTP",
            Header::Icmp(_) => "ICMP",
            Header::Icmp6(_) => "ICMPv6",
            Header::Vxlan(_) => "VXLAN",
            Header::Geneve(_) => "Geneve",
            Header::Gre(_) => "GRE",
            Header::Mpls(_) => "MPLS",
            Header::Teredo(_) => "Teredo",
            Header::Gtpv1(_) => "GTPv1",
            Header::Gtpv2(_) => "GTPv2",
            Header::L2tpv2(_) => "L2TPv2",
            Header::L2tpv3(_) => "L2TPv3",
            Header::Nvgre(_) => "NVGRE",
            Header::Pbb(_) => "PBB",
            Header::Stt(_) => "STT",
            Header::Pptp(_) => "PPTP",
            Header::Ipip(t) => t.name(),
            Header::Unknown { .. } => "Unknown",
        }
    }

    /// Returns true if this is a link layer header
    pub fn is_link_layer(&self) -> bool {
        matches!(
            self,
            Header::Ethernet(_) | Header::Sll(_) | Header::Sllv2(_) | Header::Null(_)
        )
    }

    /// Returns true if this is a network layer header
    pub fn is_network_layer(&self) -> bool {
        matches!(self, Header::Ipv4(_) | Header::Ipv6(_) | Header::Arp(_))
    }

    /// Returns true if this is a transport layer header
    pub fn is_transport_layer(&self) -> bool {
        matches!(
            self,
            Header::Tcp(_) | Header::Udp(_) | Header::Sctp(_) | Header::Icmp(_) | Header::Icmp6(_)
        )
    }

    /// Returns true if this is a tunnel header
    pub fn is_tunnel(&self) -> bool {
        matches!(
            self,
            Header::Vxlan(_)
                | Header::Geneve(_)
                | Header::Gre(_)
                | Header::Mpls(_)
                | Header::Teredo(_)
                | Header::Gtpv1(_)
                | Header::Gtpv2(_)
                | Header::L2tpv2(_)
                | Header::L2tpv3(_)
                | Header::Nvgre(_)
                | Header::Pbb(_)
                | Header::Stt(_)
                | Header::Pptp(_)
                | Header::Ipip(_)
        )
    }

    /// Returns true if this is an unknown protocol
    pub fn is_unknown(&self) -> bool {
        matches!(self, Header::Unknown { .. })
    }
}

impl std::fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Header::Ethernet(h) => f.debug_tuple("Ethernet").field(h).finish(),
            Header::Sll(h) => f.debug_tuple("Sll").field(h).finish(),
            Header::Sllv2(h) => f.debug_tuple("Sllv2").field(h).finish(),
            Header::Null(h) => f.debug_tuple("Null").field(h).finish(),
            Header::Ipv4(h) => f.debug_tuple("Ipv4").field(h).finish(),
            Header::Ipv6(h) => f.debug_tuple("Ipv6").field(h).finish(),
            Header::Arp(h) => f.debug_tuple("Arp").field(h).finish(),
            Header::Tcp(h) => f.debug_tuple("Tcp").field(h).finish(),
            Header::Udp(h) => f.debug_tuple("Udp").field(h).finish(),
            Header::Sctp(h) => f.debug_tuple("Sctp").field(h).finish(),
            Header::Icmp(h) => f.debug_tuple("Icmp").field(h).finish(),
            Header::Icmp6(h) => f.debug_tuple("Icmp6").field(h).finish(),
            Header::Vxlan(h) => f.debug_tuple("Vxlan").field(h).finish(),
            Header::Geneve(h) => f.debug_tuple("Geneve").field(h).finish(),
            Header::Gre(h) => f.debug_tuple("Gre").field(h).finish(),
            Header::Mpls(h) => f.debug_tuple("Mpls").field(h).finish(),
            Header::Teredo(h) => f.debug_tuple("Teredo").field(h).finish(),
            Header::Gtpv1(h) => f.debug_tuple("Gtpv1").field(h).finish(),
            Header::Gtpv2(h) => f.debug_tuple("Gtpv2").field(h).finish(),
            Header::L2tpv2(h) => f.debug_tuple("L2tpv2").field(h).finish(),
            Header::L2tpv3(h) => f.debug_tuple("L2tpv3").field(h).finish(),
            Header::Nvgre(h) => f.debug_tuple("Nvgre").field(h).finish(),
            Header::Pbb(h) => f.debug_tuple("Pbb").field(h).finish(),
            Header::Stt(h) => f.debug_tuple("Stt").field(h).finish(),
            Header::Pptp(h) => f.debug_tuple("Pptp").field(h).finish(),
            Header::Ipip(h) => f.debug_tuple("Ipip").field(h).finish(),
            Header::Unknown { proto, data } => f
                .debug_struct("Unknown")
                .field("proto", proto)
                .field("data_len", &data.len())
                .finish(),
        }
    }
}

impl std::fmt::Display for Header<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Header::Ethernet(h) => write!(f, "{}", h),
            Header::Sll(h) => write!(f, "{}", h),
            Header::Sllv2(h) => write!(f, "{}", h),
            Header::Null(h) => write!(f, "{}", h),
            Header::Ipv4(h) => write!(f, "{}", h),
            Header::Ipv6(h) => write!(f, "{}", h),
            Header::Arp(h) => write!(f, "{}", h),
            Header::Tcp(h) => write!(f, "{}", h),
            Header::Udp(h) => write!(f, "{}", h),
            Header::Sctp(h) => write!(f, "{}", h),
            Header::Icmp(h) => write!(f, "{}", h),
            Header::Icmp6(h) => write!(f, "{}", h),
            Header::Vxlan(h) => write!(f, "{}", h),
            Header::Geneve(h) => write!(f, "{}", h),
            Header::Gre(h) => write!(f, "{}", h),
            Header::Mpls(h) => write!(f, "{}", h),
            Header::Teredo(h) => write!(f, "{}", h),
            Header::Gtpv1(h) => write!(f, "{}", h),
            Header::Gtpv2(h) => write!(f, "{}", h),
            Header::L2tpv2(h) => write!(f, "{}", h),
            Header::L2tpv3(h) => write!(f, "{}", h),
            Header::Nvgre(h) => write!(f, "{}", h),
            Header::Pbb(h) => write!(f, "{}", h),
            Header::Stt(h) => write!(f, "{}", h),
            Header::Pptp(h) => write!(f, "{}", h),
            Header::Ipip(t) => write!(f, "{}", t),
            Header::Unknown { proto, data } => {
                write!(f, "Unknown({}, {} bytes)", proto, data.len())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum LinkLayer<'a> {
    Ethernet(EtherHeaderVlan<'a>),
    Sll(&'a SllHeader),
    Sllv2(&'a Sllv2Header),
    Null(&'a NullHeader),
}

impl LinkLayer<'_> {
    #[inline]
    pub fn protocol(&self) -> EtherProto {
        match self {
            LinkLayer::Ethernet(h) => h.protocol(),
            LinkLayer::Sll(h) => h.protocol(),
            LinkLayer::Sllv2(h) => h.protocol(),
            LinkLayer::Null(h) => h.protocol(),
        }
    }

    #[inline]
    pub fn source(&self) -> EthAddr {
        match self {
            crate::packet::header::LinkLayer::Ethernet(ether) => *ether.source(),
            _ => EthAddr::default(),
        }
    }

    #[inline]
    pub fn dest(&self) -> EthAddr {
        match self {
            crate::packet::header::LinkLayer::Ethernet(ether) => *ether.dest(),
            _ => EthAddr::default(),
        }
    }
}

impl std::fmt::Display for LinkLayer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkLayer::Ethernet(h) => write!(f, "{}", h),
            LinkLayer::Sll(h) => write!(f, "{}", h),
            LinkLayer::Sllv2(h) => write!(f, "{}", h),
            LinkLayer::Null(h) => write!(f, "{}", h),
        }
    }
}

#[derive(Debug, Clone)]
pub enum NetworkLayer<'a> {
    Ipv4(Ipv4HeaderOpt<'a>),
    Ipv6(Ipv6HeaderExt<'a>),
    Mpls(MplsLabelStack<'a>),
}

impl std::fmt::Display for NetworkLayer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkLayer::Ipv4(h) => write!(f, "{}", h),
            NetworkLayer::Ipv6(h) => write!(f, "{}", h),
            NetworkLayer::Mpls(h) => write!(f, "{}", h),
        }
    }
}

/// Trait for extracting source and destination fields from packet headers.
///
/// This trait provides a generic interface for accessing source and destination
/// information from different types of network headers, regardless of whether
/// they contain IP addresses, ports, or other address types.
///
/// # Type Parameters
/// * `T` - The type of address/port information to extract (e.g., Ipv4Addr, Ipv6Addr, u16)
pub trait SourceDestLayer<T> {
    /// Extracts the source address/port from the header.
    ///
    /// Returns `None` if the header doesn't contain source information
    /// or if the source field is not applicable for this header type.
    fn source(&self) -> Option<T>;

    /// Extracts the destination address/port from the header.
    ///
    /// Returns `None` if the header doesn't contain destination information
    /// or if the destination field is not applicable for this header type.
    fn dest(&self) -> Option<T>;
}

impl SourceDestLayer<EthAddr> for LinkLayer<'_> {
    /// Extracts the source Ethernet MAC address from the link layer header.
    ///
    /// Returns the source MAC address if this is an Ethernet header,
    /// otherwise returns `None` for other link layer types (SLL, SLLv2, NULL).
    ///
    /// # Returns
    /// * `Some(EthAddr)` - The source MAC address for Ethernet frames
    /// * `None` - No MAC address available for non-Ethernet link layers
    #[inline]
    fn source(&self) -> Option<EthAddr> {
        match self {
            LinkLayer::Ethernet(h) => Some(*h.source()),
            _ => None,
        }
    }

    /// Extracts the destination Ethernet MAC address from the link layer header.
    ///
    /// Returns the destination MAC address if this is an Ethernet header,
    /// otherwise returns `None` for other link layer types (SLL, SLLv2, NULL).
    ///
    /// # Returns
    /// * `Some(EthAddr)` - The destination MAC address for Ethernet frames
    /// * `None` - No MAC address available for non-Ethernet link layers
    #[inline]
    fn dest(&self) -> Option<EthAddr> {
        match self {
            LinkLayer::Ethernet(h) => Some(*h.dest()),
            _ => None,
        }
    }
}

impl SourceDestLayer<Ipv4Addr> for NetworkLayer<'_> {
    /// Extracts the source IPv4 address from the network layer header.
    ///
    /// Returns the source IPv4 address if this is an IPv4 header,
    /// otherwise returns `None` for IPv6, MPLS, or other network layers.
    #[inline]
    fn source(&self) -> Option<Ipv4Addr> {
        match self {
            NetworkLayer::Ipv4(h) => Some(h.header.src_ip()),
            _ => None,
        }
    }

    /// Extracts the destination IPv4 address from the network layer header.
    ///
    /// Returns the destination IPv4 address if this is an IPv4 header,
    /// otherwise returns `None` for IPv6, MPLS, or other network layers.
    #[inline]
    fn dest(&self) -> Option<Ipv4Addr> {
        match self {
            NetworkLayer::Ipv4(h) => Some(h.header.dst_ip()),
            _ => None,
        }
    }
}

impl SourceDestLayer<Ipv6Addr> for NetworkLayer<'_> {
    /// Extracts the source IPv6 address from the network layer header.
    ///
    /// Returns the source IPv6 address if this is an IPv6 header,
    /// otherwise returns `None` for IPv4, MPLS, or other network layers.
    #[inline]
    fn source(&self) -> Option<Ipv6Addr> {
        match self {
            NetworkLayer::Ipv6(h) => Some(h.header.src_ip()),
            _ => None,
        }
    }

    /// Extracts the destination IPv6 address from the network layer header.
    ///
    /// Returns the destination IPv6 address if this is an IPv6 header,
    /// otherwise returns `None` for IPv4, MPLS, or other network layers.
    #[inline]
    fn dest(&self) -> Option<Ipv6Addr> {
        match self {
            NetworkLayer::Ipv6(h) => Some(h.header.dst_ip()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpHeaderOpt<'a>),
    Udp(&'a UdpHeader),
    Sctp(&'a SctpHeader),
    Icmp(&'a IcmpHeader),
    Icmp6(&'a Icmp6Header),
}

impl TransportLayer<'_> {
    /// Extracts the source and destination ports from the transport layer header.
    ///
    /// For TCP, UDP, and SCTP headers, returns the actual source and destination ports.
    /// For ICMP and ICMPv6 headers, which don't have port numbers, returns (0, 0).
    ///
    /// # Returns
    /// A tuple containing (source_port, destination_port). For protocols without
    /// port numbers, both values will be 0.
    #[inline]
    pub fn ports(&self) -> (u16, u16) {
        match self {
            TransportLayer::Tcp(h) => {
                (h.source().unwrap_or_default(), h.dest().unwrap_or_default())
            }
            TransportLayer::Udp(h) => {
                (h.source().unwrap_or_default(), h.dest().unwrap_or_default())
            }
            TransportLayer::Sctp(h) => {
                (h.source().unwrap_or_default(), h.dest().unwrap_or_default())
            }
            TransportLayer::Icmp(_) => (0, 0),
            TransportLayer::Icmp6(_) => (0, 0),
        }
    }
}

impl SourceDestLayer<u16> for TcpHeaderOpt<'_> {
    /// Extracts the source port from the TCP header.
    ///
    /// TCP headers always contain both source and destination ports,
    /// so this method always returns `Some(port)`.
    #[inline]
    fn source(&self) -> Option<u16> {
        Some(self.header.src_port())
    }

    /// Extracts the destination port from the TCP header.
    ///
    /// TCP headers always contain both source and destination ports,
    /// so this method always returns `Some(port)`.
    #[inline]
    fn dest(&self) -> Option<u16> {
        Some(self.header.dst_port())
    }
}

impl SourceDestLayer<u16> for UdpHeader {
    /// Extracts the source port from the UDP header.
    ///
    /// UDP headers always contain both source and destination ports,
    /// so this method always returns `Some(port)`.
    #[inline]
    fn source(&self) -> Option<u16> {
        Some(self.src_port())
    }

    /// Extracts the destination port from the UDP header.
    ///
    /// UDP headers always contain both source and destination ports,
    /// so this method always returns `Some(port)`.
    #[inline]
    fn dest(&self) -> Option<u16> {
        Some(self.dst_port())
    }
}

impl SourceDestLayer<u16> for SctpHeader {
    /// Extracts the source port from the SCTP header.
    ///
    /// SCTP headers always contain both source and destination ports,
    /// so this method always returns `Some(port)`.
    #[inline]
    fn source(&self) -> Option<u16> {
        Some(self.src_port())
    }

    /// Extracts the destination port from the SCTP header.
    ///
    /// SCTP headers always contain both source and destination ports,
    /// so this method always returns `Some(port)`.
    #[inline]
    fn dest(&self) -> Option<u16> {
        Some(self.dst_port())
    }
}

impl SourceDestLayer<u16> for TransportLayer<'_> {
    /// Extracts the source port from the transport layer header.
    ///
    /// Returns the source port for TCP, UDP, and SCTP headers.
    /// Returns `None` for ICMP and ICMPv6 headers, which don't have port numbers.
    #[inline]
    fn source(&self) -> Option<u16> {
        match self {
            TransportLayer::Tcp(h) => Some(h.src_port()),
            TransportLayer::Udp(h) => Some(h.src_port()),
            TransportLayer::Sctp(h) => Some(h.src_port()),
            TransportLayer::Icmp(_) => None,
            TransportLayer::Icmp6(_) => None,
        }
    }

    /// Extracts the destination port from the transport layer header.
    ///
    /// Returns the destination port for TCP, UDP, and SCTP headers.
    /// Returns `None` for ICMP and ICMPv6 headers, which don't have port numbers.
    #[inline]
    fn dest(&self) -> Option<u16> {
        match self {
            TransportLayer::Tcp(h) => Some(h.dst_port()),
            TransportLayer::Udp(h) => Some(h.dst_port()),
            TransportLayer::Sctp(h) => Some(h.dst_port()),
            TransportLayer::Icmp(_) => None,
            TransportLayer::Icmp6(_) => None,
        }
    }
}

impl std::fmt::Display for TransportLayer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportLayer::Tcp(h) => write!(f, "{}", h),
            TransportLayer::Udp(h) => write!(f, "{}", h),
            TransportLayer::Sctp(h) => write!(f, "{}", h),
            TransportLayer::Icmp(h) => write!(f, "{}", h),
            TransportLayer::Icmp6(h) => write!(f, "{}", h),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TunnelLayer<'a> {
    Vxlan(&'a VxlanHeader),
    Geneve(GeneveHeaderOpt<'a>),
    Gre(GreHeaderOpt<'a>),
    Teredo(Box<TeredoPacket<'a>>),
    Gtpv1(Gtpv1HeaderOpt<'a>),
    Gtpv2(Gtpv2HeaderOpt<'a>),
    L2tpv2(L2tpv2HeaderOpt<'a>),
    L2tpv3(L2tpv3SessionHeaderCookie<'a>),
    Nvgre(&'a NvgreHeader),
    Pbb(PbbHeader<'a>),
    Stt(SttPacket<'a>),
    Pptp(PptpGreHeaderOpt<'a>),
    Ipip(IpipTunnel<'a>),
}

/// IP Tunnel Layer - combines outer IP encapsulation with tunnel protocol
///
/// Most tunnel protocols are encapsulated in IP (e.g., VXLAN over UDP/IP, GRE over IP).
/// This structure preserves the outer IP header that encapsulates the tunnel.
///
/// Some tunnels like PBB (MAC-in-MAC) operate at layer 2 and don't have an outer IP header,
/// so the `outer` field is optional.
#[derive(Debug, Clone)]
pub struct NetworkTunnelLayer<'a> {
    /// Outer IP header (IPv4 or IPv6) that encapsulates the tunnel.
    /// None for layer 2 tunnels like PBB.
    pub outer: Option<NetworkLayer<'a>>,
    /// The tunnel protocol layer
    pub tunnel: TunnelLayer<'a>,
}

impl<'a> NetworkTunnelLayer<'a> {
    /// Creates a new IP tunnel layer with an outer IP header.
    ///
    /// This constructor is used for tunnel protocols that are encapsulated in IP,
    /// such as VXLAN over UDP/IP, GRE over IP, or GTP over IP.
    ///
    /// # Arguments
    /// * `outer` - The outer IP header (IPv4 or IPv6) that encapsulates the tunnel
    /// * `tunnel` - The tunnel protocol layer
    #[inline]
    pub fn new(outer: NetworkLayer<'a>, tunnel: TunnelLayer<'a>) -> Self {
        Self {
            outer: Some(outer),
            tunnel,
        }
    }

    /// Creates a new tunnel layer without an outer IP header.
    ///
    /// This constructor is used for layer 2 tunnel protocols that don't have
    /// an outer IP header, such as PBB (MAC-in-MAC) or other layer 2 encapsulations.
    ///
    /// # Arguments
    /// * `tunnel` - The tunnel protocol layer
    #[inline]
    pub fn new_l2(tunnel: TunnelLayer<'a>) -> Self {
        Self {
            outer: None,
            tunnel,
        }
    }

    /// Returns a reference to the outer IP header, if present.
    ///
    /// For IP-based tunnels (VXLAN, GRE, GTP, etc.), this returns the outer IP header
    /// that encapsulates the tunnel protocol. For layer 2 tunnels like PBB, this returns `None`.
    ///
    /// # Returns
    /// * `Some(&NetworkLayer)` - The outer IP header for IP-based tunnels
    /// * `None` - No outer IP header for layer 2 tunnels
    #[inline]
    pub fn outer(&self) -> Option<&NetworkLayer<'a>> {
        self.outer.as_ref()
    }

    /// Returns a reference to the tunnel layer.
    ///
    /// This provides access to the actual tunnel protocol header (VXLAN, GRE, GTP, etc.).
    ///
    /// # Returns
    /// A reference to the tunnel protocol layer contained within this network tunnel.
    #[inline]
    pub fn tunnel(&self) -> &TunnelLayer<'a> {
        &self.tunnel
    }
}

impl std::fmt::Display for NetworkTunnelLayer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref outer) = self.outer {
            write!(f, "{} > {}", outer, self.tunnel)
        } else {
            write!(f, "{}", self.tunnel)
        }
    }
}

impl std::fmt::Display for TunnelLayer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelLayer::Vxlan(h) => write!(f, "{}", h),
            TunnelLayer::Geneve(h) => write!(f, "{}", h),
            TunnelLayer::Gre(h) => write!(f, "{}", h),
            TunnelLayer::Teredo(h) => write!(f, "{}", h),
            TunnelLayer::Gtpv1(h) => write!(f, "{}", h),
            TunnelLayer::Gtpv2(h) => write!(f, "{}", h),
            TunnelLayer::L2tpv2(h) => write!(f, "{}", h),
            TunnelLayer::L2tpv3(h) => write!(f, "{}", h),
            TunnelLayer::Nvgre(h) => write!(f, "{}", h),
            TunnelLayer::Pbb(h) => write!(f, "{}", h),
            TunnelLayer::Stt(h) => write!(f, "{}", h),
            TunnelLayer::Pptp(h) => write!(f, "{}", h),
            TunnelLayer::Ipip(h) => write!(f, "{}", h),
        }
    }
}
