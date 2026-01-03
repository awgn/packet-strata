//! Header enum wrapper for all supported packet headers
//!
//! This module provides the [`Header`] enum which wraps all supported protocol headers
//! and [`UnknownProto`] for representing unknown/unsupported protocols.



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

#[derive (Debug, Clone)]
pub enum LinkLayer<'a> {
    Ethernet(EtherHeaderVlan<'a>),
    Sll(&'a SllHeader),
    Sllv2(&'a Sllv2Header),
    Null(&'a NullHeader),
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

#[derive (Debug, Clone)]
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

#[derive (Debug, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpHeaderOpt<'a>),
    Udp(&'a UdpHeader),
    Sctp(&'a SctpHeader),
    Icmp(&'a IcmpHeader),
    Icmp6(&'a Icmp6Header),
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

#[derive (Debug, Clone)]
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
