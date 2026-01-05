use smallvec::SmallVec;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::protocol::IpProto;
use crate::{
    packet::{header::NetworkLayer, Packet},
    tracker::vni::{VniId, VniLayer, VniMapper, VNI_NULL},
};

/// Common trait for all flow key types
///
/// This trait defines the interface for creating flow keys from packets.
/// Different implementations can create keys with different granularities
/// (e.g., 5-tuple with VNI, 3-tuple, MAC-based, etc.)
pub trait FlowKey: Sized + Hash + Eq + Clone {
    /// Create a new flow key from a packet
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self>;
}

/// Helper function to extract VNI from packet tunnels
///
/// This function is shared between all FlowKey implementations to avoid code duplication.
/// Returns `VNI_NULL` if there are no tunnel layers, otherwise extracts and maps the VNI stack.
#[inline]
fn extract_vni(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<VniId> {
    let network_tunnel_layers = pkt.tunnels();

    if network_tunnel_layers.is_empty() {
        return Some(VNI_NULL);
    }

    let vni_stack = network_tunnel_layers
        .iter()
        .map(TryInto::try_into)
        .collect::<Result<SmallVec<[VniLayer; 4]>, _>>()
        .ok()?;

    Some(vni_mapper.get_or_create_vni_id(&vni_stack))
}

/// Helper function to extract transport layer ports
///
/// Returns (src_port, dst_port) or (0, 0) if no transport layer is present.
#[inline]
fn extract_ports(pkt: &Packet<'_>) -> (u16, u16) {
    pkt.transport()
        .map(|t| t.ports())
        .unwrap_or((0, 0))
}

/// IPv4 5-tuple flow key with VNI support
///
/// This key uniquely identifies a network flow using:
/// - Source and destination IPv4 addresses
/// - Source and destination ports
/// - IP protocol number
/// - Virtual Network Identifier (VNI) for tunnel-aware flow tracking
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub struct FlowKeyV4 {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProto,
    pub vni: VniId,
}

impl FlowKeyV4 {
    /// Create a new IPv4 flow key from a packet
    ///
    /// Returns `None` if the packet does not contain an IPv4 header or if VNI extraction fails.
    pub fn new(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        let NetworkLayer::Ipv4(ipv4) = pkt.network()? else {
            return None;
        };

        let src_ip = ipv4.header.src_ip();
        let dst_ip = ipv4.header.dst_ip();
        let protocol = ipv4.header.protocol();
        let (src_port, dst_port) = extract_ports(pkt);
        let vni = extract_vni(pkt, vni_mapper)?;

        Some(Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            vni,
        })
    }
}

impl FlowKey for FlowKeyV4 {
    #[inline]
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt, vni_mapper)
    }
}

/// IPv6 5-tuple flow key with VNI support
///
/// This key uniquely identifies a network flow using:
/// - Source and destination IPv6 addresses
/// - Source and destination ports
/// - IP protocol number (next header)
/// - Virtual Network Identifier (VNI) for tunnel-aware flow tracking
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub struct FlowKeyV6 {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProto,
    pub vni: VniId,
}

impl FlowKeyV6 {
    /// Create a new IPv6 flow key from a packet
    ///
    /// Returns `None` if the packet does not contain an IPv6 header or if VNI extraction fails.
    pub fn new(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        let NetworkLayer::Ipv6(ipv6) = pkt.network()? else {
            return None;
        };

        let src_ip = ipv6.header.src_ip();
        let dst_ip = ipv6.header.dst_ip();
        let protocol = ipv6.header.next_header();
        let (src_port, dst_port) = extract_ports(pkt);
        let vni = extract_vni(pkt, vni_mapper)?;

        Some(Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            vni,
        })
    }
}

impl FlowKey for FlowKeyV6 {
    #[inline]
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt, vni_mapper)
    }
}
