//! Flow tuples and canonical symmetric hashing
//!
//! This module defines the [`Tuple`] trait and its concrete implementations:
//! - [`TupleV4`]: IPv4 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) + [`VniId`]
//! - [`TupleV6`]: IPv6 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) + [`VniId`]
//! - [`TupleEth`]: Ethernet L2 3-tuple (`src`, `dst`, `protocol`)
//!
//! # Canonical Bidirectional Lookup (`Symmetric<T>`)
//!
//! By default, [`TupleV4`], [`TupleV6`], and [`TupleEth`] implement directional `Hash` and `Eq`
//! (`(A -> B) != (B -> A)`). When tracking bidirectional flows in [`Tracker`](crate::tracker::Tracker),
//! wrapping a tuple in [`Symmetric<T>`] switches `Hash` and `Eq` to [`Tuple::hash_canonical`] and
//! [`Tuple::eq_canonical`], guaranteeing that:
//! - `Hash(Symmetric(A -> B)) == Hash(Symmetric(B -> A))`
//! - `Symmetric(A -> B) == Symmetric(B -> A)`
//!
//! This allows both uplink (`A -> B`) and downlink (`B -> A`) packets to resolve to the exact
//! same flow entry in a single hash table lookup without allocating or mutating the key when
//! [`Flow::flip_direction`](crate::tracker::flow::Flow::flip_direction) is called.
//!
//! # Example
//!
//! ```
//! use std::collections::hash_map::DefaultHasher;
//! use std::hash::{Hash, Hasher};
//! use std::net::Ipv4Addr;
//! use packet_strata::packet::protocol::IpProto;
//! use packet_strata::tracker::tuple::{Symmetric, Tuple, TupleV4};
//! use packet_strata::tracker::vni::VniId;
//!
//! let uplink = TupleV4 {
//!     src_ip: Ipv4Addr::new(10, 0, 0, 1),
//!     dst_ip: Ipv4Addr::new(1, 1, 1, 1),
//!     src_port: 50000,
//!     dst_port: 443,
//!     protocol: IpProto::TCP,
//!     vni: VniId::default(),
//! };
//!
//! let downlink = uplink.flip();
//!
//! // Directional tuples are distinct:
//! assert_ne!(uplink, downlink);
//!
//! // Symmetric wrappers are equal and produce the exact same hash:
//! assert_eq!(Symmetric(uplink), Symmetric(downlink));
//!
//! let mut h1 = DefaultHasher::new();
//! let mut h2 = DefaultHasher::new();
//! Symmetric(uplink).hash(&mut h1);
//! Symmetric(downlink).hash(&mut h2);
//! assert_eq!(h1.finish(), h2.finish());
//! ```

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::ether::EthAddr;
use crate::packet::header::{NetworkTunnelLayer, SourceDestLayer};
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

    /// Checks if the packet travels in the same direction (source -> dest) as this tuple.
    fn is_same_dir(&self, pkt: &Packet<'_>) -> bool;

    /// Checks if the tuple is symmetric (source equals destination).
    ///
    /// A tuple is considered symmetric when both the source address equals the destination
    /// address and the source port equals the destination port. This is useful for
    /// identifying self-referential connections.
    #[inline(always)]
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

#[cold]
#[inline(never)]
fn extract_vni_slow(
    network_tunnel_layers: &[NetworkTunnelLayer<'_>],
    vni_mapper: &mut VniMapper,
) -> Option<VniId> {
    let vni_stack = network_tunnel_layers
        .iter()
        .map(TryInto::try_into)
        .collect::<Result<SmallVec<[VniLayer; 4]>, _>>()
        .ok()?;

    Some(vni_mapper.get_or_create_vni_id(&vni_stack))
}

/// Helper function to extract VNI from packet tunnels
///
/// This function is shared between all Tuple implementations to avoid code duplication.
/// Returns `VNI_NULL` if there are no tunnel layers, otherwise extracts and maps the VNI stack.
#[inline(always)]
fn extract_vni(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<VniId> {
    let network_tunnel_layers = pkt.tunnels();

    if network_tunnel_layers.is_empty() {
        return Some(VniId::default());
    }

    extract_vni_slow(network_tunnel_layers, vni_mapper)
}

/// Helper function to extract transport layer ports
///
/// Returns (src_port, dst_port) or (0, 0) if no transport layer is present.
#[inline(always)]
fn extract_ports(pkt: &Packet<'_>) -> (u16, u16) {
    pkt.transport().map(|t| t.ports()).unwrap_or((0, 0))
}

/// Zero-cost wrapper that switches a [`Tuple`]'s `Hash` and `PartialEq`/`Eq` implementations
/// to [`Tuple::hash_canonical`] and [`Tuple::eq_canonical`] (`Symmetric(A -> B) == Symmetric(B -> A)`).
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct Symmetric<T: Tuple>(pub T);

impl<T: Tuple> PartialEq for Symmetric<T> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_canonical(&other.0)
    }
}

impl<T: Tuple> Eq for Symmetric<T> {}

impl<T: Tuple> Hash for Symmetric<T> {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash_canonical(state);
    }
}

impl<T: Tuple> From<T> for Symmetric<T> {
    #[inline(always)]
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
    #[inline(always)]
    const fn endpoint_u64(ip: Ipv4Addr, port: u16) -> u64 {
        ((u32::from_be_bytes(ip.octets()) as u64) << 16) | (port as u64)
    }

    /// Create a new IPv4 flow tuple from a packet
    ///
    /// Returns `None` if the packet does not contain an IPv4 header or if VNI extraction fails.
    #[inline(always)]
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

    #[inline(always)]
    fn source(&self) -> Self::Addr {
        self.src_ip
    }

    #[inline(always)]
    fn dest(&self) -> Self::Addr {
        self.dst_ip
    }

    #[inline(always)]
    fn source_port(&self) -> u16 {
        self.src_port
    }

    #[inline(always)]
    fn dest_port(&self) -> u16 {
        self.dst_port
    }

    #[inline(always)]
    fn protocol(&self) -> IpProto {
        self.protocol
    }

    #[inline(always)]
    fn vni(&self) -> VniId {
        self.vni
    }

    #[inline(always)]
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt, vni_mapper)
    }

    #[inline(always)]
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

    #[inline(always)]
    fn hash_canonical<H: Hasher>(&self, state: &mut H) {
        let ep1 = Self::endpoint_u64(self.src_ip, self.src_port);
        let ep2 = Self::endpoint_u64(self.dst_ip, self.dst_port);
        let (lo, hi) = if ep1 <= ep2 { (ep1, ep2) } else { (ep2, ep1) };

        let vni_raw = self.vni.as_u32();
        let w0 = lo | ((u8::from(self.protocol) as u64) << 48) | (((vni_raw & 0xFF) as u64) << 56);
        let w1 = hi | (((vni_raw >> 8) as u64) << 48);
        state.write_u128(((w1 as u128) << 64) | (w0 as u128));
    }

    #[inline(always)]
    fn eq_canonical(&self, other: &Self) -> bool {
        if self.protocol != other.protocol || self.vni != other.vni {
            return false;
        }

        let s1 = Self::endpoint_u64(self.src_ip, self.src_port);
        let s2 = Self::endpoint_u64(self.dst_ip, self.dst_port);
        let o1 = Self::endpoint_u64(other.src_ip, other.src_port);
        let o2 = Self::endpoint_u64(other.dst_ip, other.dst_port);

        (s1 == o1 && s2 == o2) || (s1 == o2 && s2 == o1)
    }

    #[inline(always)]
    fn is_same_dir(&self, pkt: &Packet<'_>) -> bool {
        pkt.network()
            .and_then(|net| SourceDestLayer::<Ipv4Addr>::source(net))
            .is_some_and(|src| src == self.src_ip)
            && pkt
                .transport()
                .and_then(|tr| SourceDestLayer::<u16>::source(tr))
                .unwrap_or(0)
                == self.src_port
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
    #[inline(always)]
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

    #[inline(always)]
    fn source(&self) -> Self::Addr {
        self.src_ip
    }

    #[inline(always)]
    fn dest(&self) -> Self::Addr {
        self.dst_ip
    }

    #[inline(always)]
    fn source_port(&self) -> u16 {
        self.src_port
    }

    #[inline(always)]
    fn dest_port(&self) -> u16 {
        self.dst_port
    }

    #[inline(always)]
    fn protocol(&self) -> IpProto {
        self.protocol
    }

    #[inline(always)]
    fn vni(&self) -> VniId {
        self.vni
    }

    #[inline(always)]
    fn from_packet(pkt: &Packet<'_>, vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt, vni_mapper)
    }

    #[inline(always)]
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

    #[inline(always)]
    fn hash_canonical<H: Hasher>(&self, state: &mut H) {
        let ip1 = u128::from_be_bytes(self.src_ip.octets());
        let ip2 = u128::from_be_bytes(self.dst_ip.octets());
        let (lo_ip, lo_port, hi_ip, hi_port) = if (ip1, self.src_port) <= (ip2, self.dst_port) {
            (ip1, self.src_port, ip2, self.dst_port)
        } else {
            (ip2, self.dst_port, ip1, self.src_port)
        };

        state.write_u128(lo_ip);
        state.write_u128(hi_ip);
        let meta = ((self.vni.as_u32() as u64) << 32)
            | ((lo_port as u64) << 16)
            | (hi_port as u64) ^ ((u8::from(self.protocol) as u64) << 56);
        state.write_u64(meta);
    }

    #[inline(always)]
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

    #[inline(always)]
    fn is_same_dir(&self, pkt: &Packet<'_>) -> bool {
        pkt.network()
            .and_then(|net| SourceDestLayer::<Ipv6Addr>::source(net))
            .is_some_and(|src| src == self.src_ip)
            && pkt
                .transport()
                .and_then(|tr| SourceDestLayer::<u16>::source(tr))
                .unwrap_or(0)
                == self.src_port
    }
}

/// Ethernet Layer-2 3-tuple (`src` MAC, `dst` MAC, `protocol` EtherType)
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
    #[inline(always)]
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

    #[inline(always)]
    fn source(&self) -> Self::Addr {
        self.src
    }

    #[inline(always)]
    fn dest(&self) -> Self::Addr {
        self.dst
    }

    #[inline(always)]
    fn source_port(&self) -> u16 {
        0
    }

    #[inline(always)]
    fn dest_port(&self) -> u16 {
        0
    }

    #[inline(always)]
    fn protocol(&self) -> IpProto {
        IpProto::default()
    }

    #[inline(always)]
    fn vni(&self) -> VniId {
        VniId::default()
    }

    #[inline(always)]
    fn from_packet(pkt: &Packet<'_>, _vni_mapper: &mut VniMapper) -> Option<Self> {
        Self::new(pkt)
    }

    #[inline(always)]
    fn flip(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
        }
    }

    #[inline(always)]
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

    #[inline(always)]
    fn eq_canonical(&self, other: &Self) -> bool {
        if self.protocol != other.protocol {
            return false;
        }

        (self.src == other.src && self.dst == other.dst)
            || (self.src == other.dst && self.dst == other.src)
    }

    #[inline(always)]
    fn is_same_dir(&self, pkt: &Packet<'_>) -> bool {
        SourceDestLayer::<EthAddr>::source(pkt.link()).is_some_and(|src| src == self.src)
    }
}
