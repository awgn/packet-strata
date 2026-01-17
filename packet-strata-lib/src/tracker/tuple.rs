use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::ether::EthAddr;
use crate::packet::protocol::{EtherProto, IpProto};
use crate::{
    packet::{
        header::{LinkLayer, NetworkLayer},
        Packet,
    },
    tracker::vni::{VniId, VniLayer, VniMapper},
};

/// Common trait for all flow tuple types
///
/// This trait defines the interface for creating flow tuples from packets.
/// (e.g., 5-tuple with VNI, 3-tuple, MAC-based, etc.)
pub trait Tuple: Sized + Hash + Eq + Clone + Copy {
    type Addr: Eq;

    /// Create a new flow tuple from a packet
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self>;

    /// Flip the source and destination fields of the flow tuple
    fn flip(&self) -> Self;

    /// Hashes the tuple in a canonical (symmetric) way without creating a new instance.
    /// Used by `Symmetric` wrapper to ensure `Hash(A->B) == Hash(B->A)`.
    fn hash_canonical<H: Hasher>(&self, state: &mut H);

    /// Checks equality in a canonical (symmetric) way without creating a new instance.
    /// Used by `Symmetric` wrapper to ensure `Eq(A->B, B->A)`.
    fn eq_canonical(&self, other: &Self) -> bool;

    /// Checks if the tuple is symmetric (source equals destination).
    ///
    /// A tuple is considered symmetric when both the source address equals the destination
    /// address and the source port equals the destination port. This is useful for
    /// identifying self-referential connections.
    #[inline]
    fn is_symmetric(&self) -> bool {
        self.source_port() == self.dest_port() && self.source() == self.dest()
    }

    /// Returns the source address of the flow tuple.
    fn source(&self) -> Self::Addr;

    /// Returns the destination address of the flow tuple.
    fn dest(&self) -> Self::Addr;

    /// Returns the source port of the flow tuple.
    fn source_port(&self) -> u16;

    /// Returns the destination port of the flow tuple.
    fn dest_port(&self) -> u16;

    /// Returns the IP protocol of the flow tuple.
    fn protocol(&self) -> IpProto;

    /// Returns the VNI (VXLAN Network Identifier) of the flow tuple.
    fn vni(&self) -> VniId;
}

/// Helper function to extract VNI from packet tunnels
///
/// This function is shared between all Tuple implementations to avoid code duplication.
/// Returns `VNI_NULL` if there are no tunnel layers, otherwise extracts and maps the VNI stack.
#[inline]
fn extract_vni(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<VniId> {
    let network_tunnel_layers = pkt.tunnels();

    if network_tunnel_layers.is_empty() {
        return Some(VniId::default());
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
    pkt.transport().map(|t| t.ports()).unwrap_or((0, 0))
}

#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct Symmetric<T: Tuple>(pub T);

impl<T: Tuple> PartialEq for Symmetric<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_canonical(&other.0)
    }
}

impl<T: Tuple> Eq for Symmetric<T> {}

impl<T: Tuple> Hash for Symmetric<T> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash_canonical(state);
    }
}

impl<T: Tuple> From<T> for Symmetric<T> {
    fn from(t: T) -> Self {
        Self(t)
    }
}

/// IPv4 5-tuple flow with VNI support
///
/// This tuple uniquely identifies a network flow using:
/// - Source and destination IPv4 addresses
/// - Source and destination ports
/// - IP protocol number
/// - Virtual Network Identifier (VNI) for tunnel-aware flow tracking
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TupleV4 {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProto,
    pub vni: VniId,
}

impl Default for TupleV4 {
    fn default() -> Self {
        Self {
            src_ip: Ipv4Addr::UNSPECIFIED,
            dst_ip: Ipv4Addr::UNSPECIFIED,
            src_port: 0,
            dst_port: 0,
            protocol: IpProto::default(),
            vni: VniId::default(),
        }
    }
}

impl TupleV4 {
    /// Create a new IPv4 flow tuple from a packet
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

impl Tuple for TupleV4 {
    type Addr = Ipv4Addr;

    #[inline]
    fn source(&self) -> Self::Addr {
        self.src_ip
    }

    #[inline]
    fn dest(&self) -> Self::Addr {
        self.dst_ip
    }

    #[inline]
    fn source_port(&self) -> u16 {
        self.src_port
    }

    #[inline]
    fn dest_port(&self) -> u16 {
        self.dst_port
    }

    #[inline]
    fn protocol(&self) -> IpProto {
        self.protocol
    }

    #[inline]
    fn vni(&self) -> VniId {
        self.vni
    }

    #[inline]
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt, vni_mapper)
    }

    #[inline]
    fn flip(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
            vni: self.vni,
        }
    }

    #[inline]
    fn hash_canonical<H: Hasher>(&self, state: &mut H) {
        // Hash invariant fields
        self.protocol.hash(state);
        self.vni.hash(state);

        // Hash variant fields in sorted order (src < dst)
        // This avoids creating a new struct or flipping
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port) {
            self.src_ip.hash(state);
            self.src_port.hash(state);
            self.dst_ip.hash(state);
            self.dst_port.hash(state);
        } else {
            self.dst_ip.hash(state);
            self.dst_port.hash(state);
            self.src_ip.hash(state);
            self.src_port.hash(state);
        }
    }

    #[inline]
    fn eq_canonical(&self, other: &Self) -> bool {
        if self.protocol != other.protocol || self.vni != other.vni {
            return false;
        }

        // Check direct equality OR crossed equality
        // This is much cheaper than constructing a new struct
        (self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port)
            || (self.src_ip == other.dst_ip
                && self.dst_ip == other.src_ip
                && self.src_port == other.dst_port
                && self.dst_port == other.src_port)
    }
}

/// IPv6 5-tuple flow tuple with VNI support
///
/// This tuple uniquely identifies a network flow using:
/// - Source and destination IPv6 addresses
/// - Source and destination ports
/// - IP protocol number (next header)
/// - Virtual Network Identifier (VNI) for tunnel-aware flow tracking
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TupleV6 {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProto,
    pub vni: VniId,
}

impl Default for TupleV6 {
    fn default() -> Self {
        Self {
            src_ip: Ipv6Addr::UNSPECIFIED,
            dst_ip: Ipv6Addr::UNSPECIFIED,
            src_port: 0,
            dst_port: 0,
            protocol: IpProto::default(),
            vni: VniId::default(),
        }
    }
}

impl TupleV6 {
    /// Create a new IPv6 flow tuple from a packet
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

impl Tuple for TupleV6 {
    type Addr = Ipv6Addr;

    #[inline]
    fn source(&self) -> Self::Addr {
        self.src_ip
    }

    #[inline]
    fn dest(&self) -> Self::Addr {
        self.dst_ip
    }

    #[inline]
    fn source_port(&self) -> u16 {
        self.src_port
    }

    #[inline]
    fn dest_port(&self) -> u16 {
        self.dst_port
    }

    #[inline]
    fn protocol(&self) -> IpProto {
        self.protocol
    }

    #[inline]
    fn vni(&self) -> VniId {
        self.vni
    }

    #[inline]
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt, vni_mapper)
    }

    #[inline]
    fn flip(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
            vni: self.vni,
        }
    }

    #[inline]
    fn hash_canonical<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
        self.vni.hash(state);

        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port) {
            self.src_ip.hash(state);
            self.src_port.hash(state);
            self.dst_ip.hash(state);
            self.dst_port.hash(state);
        } else {
            self.dst_ip.hash(state);
            self.dst_port.hash(state);
            self.src_ip.hash(state);
            self.src_port.hash(state);
        }
    }

    #[inline]
    fn eq_canonical(&self, other: &Self) -> bool {
        if self.protocol != other.protocol || self.vni != other.vni {
            return false;
        }

        (self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port)
            || (self.src_ip == other.dst_ip
                && self.dst_ip == other.src_ip
                && self.src_port == other.dst_port
                && self.dst_port == other.src_port)
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TupleEth {
    pub src: EthAddr,
    pub dst: EthAddr,
    pub protocol: EtherProto,
}

impl Default for TupleEth {
    fn default() -> Self {
        Self {
            src: EthAddr::default(),
            dst: EthAddr::default(),
            protocol: EtherProto::default(),
        }
    }
}

impl TupleEth {
    /// Create a new Ethernet flow tuple from a packet
    ///
    /// Returns `None` if the packet is not Ethernet.
    pub fn new(pkt: &Packet<'_>) -> Option<Self> {
        let LinkLayer::Ethernet(eth) = pkt.link() else {
            return None;
        };

        Some(Self {
            src: *eth.source(),
            dst: *eth.dest(),
            protocol: eth.inner_type(),
        })
    }
}

impl Tuple for TupleEth {
    type Addr = EthAddr;

    #[inline]
    fn source(&self) -> Self::Addr {
        self.src
    }

    #[inline]
    fn dest(&self) -> Self::Addr {
        self.dst
    }

    #[inline]
    fn source_port(&self) -> u16 {
        0
    }

    #[inline]
    fn dest_port(&self) -> u16 {
        0
    }

    #[inline]
    fn protocol(&self) -> IpProto {
        IpProto::default()
    }

    #[inline]
    fn vni(&self) -> VniId {
        VniId::default()
    }

    #[inline]
    fn from_packet(pkt: &Packet<'_>, _vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt)
    }

    #[inline]
    fn flip(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
        }
    }

    #[inline]
    fn hash_canonical<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);

        // EthAddr implements Ord so we can compare directly
        if self.src <= self.dst {
            self.src.hash(state);
            self.dst.hash(state);
        } else {
            self.dst.hash(state);
            self.src.hash(state);
        }
    }

    #[inline]
    fn eq_canonical(&self, other: &Self) -> bool {
        if self.protocol != other.protocol {
            return false;
        }

        (self.src == other.src && self.dst == other.dst)
            || (self.src == other.dst && self.dst == other.src)
    }
}
