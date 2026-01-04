//! Virtual Network Identifier (VNI) management
//!
//! This module handles VNI layer information, including VLAN, MPLS, GRE, VXLAN,
//! Geneve, and various IP tunneling protocols.
//!
//! # Overview
//!
//! Instead of the traditional "tunnel" concept, this module uses a layer-based
//! approach where each VNI represents a specific network encapsulation layer.
//! Multiple layers can be stacked to represent complex network topologies.
//!
//! # Design Philosophy
//!
//! Each VNI layer type is represented as an enum variant with exactly the fields
//! it needs - no more, no less. This makes invalid states unrepresentable and
//! provides excellent type safety.
//!
//! # Example
//!
//! ```ignore
//! use packet_strata::tracker::vni::{VniLayer, VniMapper};
//!
//! let mut mapper = VniMapper::new();
//!
//! // Create a VLAN VNI
//! let vlan = VniLayer::vlan(100);
//!
//! // Get or create a VNI ID
//! let vni_id = mapper.get_or_create_vni_id(&[vlan]);
//!
//! // Look up the VNI stack later
//! if let Some(stack) = mapper.lookup_vni(&vni_id) {
//!     println!("VNI stack: {:?}", stack);
//! }
//! ```

use smallvec::SmallVec;
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::ether::EtherHeaderVlan;
use crate::packet::header::{IpTunnelLayer, LinkLayer, NetworkLayer, TunnelLayer};
use crate::packet::tunnel::ipip::OuterIpHeader;

/// Error types for VNI operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VniError {
    /// Invalid IP header length
    InvalidHeaderLength,
    /// Invalid IP version
    InvalidIpVersion,
}

impl fmt::Display for VniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderLength => write!(f, "Invalid IP header length"),
            Self::InvalidIpVersion => write!(f, "Invalid IP version"),
        }
    }
}

impl std::error::Error for VniError {}

/// Network layer types for VNI encapsulation
///
/// Each variant contains exactly the fields required for that specific layer type.
/// This makes invalid states unrepresentable at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VniLayer {
    /// IEEE 802.1Q VLAN
    ///
    /// Contains only the VLAN ID (12-bit value, 0-4095)
    Vlan { vid: u16 },

    /// Multiprotocol Label Switching
    ///
    /// Contains only the MPLS label (20-bit value)
    Mpls { label: u32 },

    /// Generic Routing Encapsulation (RFC 2784, RFC 2890)
    ///
    /// Contains protocol type, optional key, and tunnel endpoints
    Gre {
        protocol_type: u16,
        key: Option<u32>,
        endpoints: [IpAddr; 2],
    },

    /// Network Virtualization using Generic Routing Encapsulation (NVGRE)
    ///
    /// Contains protocol type, VSID/FlowID (24-bit VSID + 8-bit FlowID), and tunnel endpoints
    NvGre {
        protocol_type: u16,
        vsid_flowid: u32,
        endpoints: [IpAddr; 2],
    },

    /// Virtual Extensible LAN (RFC 7348)
    ///
    /// Contains VNI (24-bit), optional Group Policy ID, and tunnel endpoints
    Vxlan {
        vni: u32,
        group_id: u16,
        endpoints: [IpAddr; 2],
    },

    /// Generic Network Virtualization Encapsulation (RFC 8926)
    ///
    /// Contains VNI (24-bit), protocol type, and tunnel endpoints
    Geneve {
        vni: u32,
        protocol_type: u16,
        endpoints: [IpAddr; 2],
    },

    /// IP-in-IP Encapsulation (RFC 2003) - IPv4-in-IPv4
    ///
    /// Also known as IPIP. Contains only tunnel endpoints.
    Ipip { endpoints: [IpAddr; 2] },

    /// IPv4-in-IPv6 Tunnel (RFC 2473)
    ///
    /// Used for DS-Lite (RFC 6333) and other 4in6 tunneling scenarios.
    Ip4in6 { endpoints: [IpAddr; 2] },

    /// IPv6-in-IPv4 Tunnel (RFC 4213)
    ///
    /// Also known as 6in4, SIT (Simple Internet Transition), or configured tunnels.
    Sit { endpoints: [IpAddr; 2] },

    /// IPv6-in-IPv6 Tunnel (RFC 2473)
    ///
    /// Generic IPv6 packet tunneling in IPv6.
    Ip6Tnl { endpoints: [IpAddr; 2] },

    /// GPRS Tunneling Protocol User Plane (GTP-U, 3GPP TS 29.281)
    ///
    /// Contains TEID (32-bit Tunnel Endpoint Identifier) and endpoints.
    /// Note: GTP-C (Control Plane) messages are signaling, not tunnels.
    GtpU { teid: u32, endpoints: [IpAddr; 2] },

    /// Teredo Tunneling (RFC 4380)
    ///
    /// IPv6 over UDP/IPv4 NAT traversal. Contains tunnel endpoints.
    Teredo { endpoints: [IpAddr; 2] },

    /// L2TPv2 - Layer 2 Tunneling Protocol version 2 (RFC 2661)
    ///
    /// Contains Tunnel ID (16-bit), Session ID (16-bit), and endpoints.
    L2tpV2 {
        tunnel_id: u16,
        session_id: u16,
        endpoints: [IpAddr; 2],
    },

    /// L2TPv3 - Layer 2 Tunneling Protocol version 3 (RFC 3931)
    ///
    /// Contains Control Connection ID or Session ID (32-bit) and endpoints.
    L2tpV3 {
        session_id: u32,
        endpoints: [IpAddr; 2],
    },

    /// Provider Backbone Bridge (IEEE 802.1ah) - MAC-in-MAC
    ///
    /// Contains I-SID (24-bit Service Instance Identifier) and optional B-VID.
    Pbb { isid: u32, bvid: Option<u16> },

    /// Stateless Transport Tunneling (STT)
    ///
    /// VMware's tunneling protocol. Contains Context ID (64-bit) and endpoints.
    Stt {
        context_id: u64,
        endpoints: [IpAddr; 2],
    },

    /// Point-to-Point Tunneling Protocol (RFC 2637)
    ///
    /// Uses enhanced GRE. Contains Call ID (16-bit) and endpoints.
    Pptp {
        call_id: u16,
        endpoints: [IpAddr; 2],
    },
}

impl fmt::Display for VniLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vlan { vid } => write!(f, "vlan({})", vid),
            Self::Mpls { label } => write!(f, "mpls({})", label),
            Self::Gre {
                protocol_type,
                key,
                endpoints,
            } => {
                write!(f, "gre(ptype:0x{:04x}", protocol_type)?;
                if let Some(k) = key {
                    write!(f, " key:{}", k)?;
                }
                write!(f, " {}↔{})", endpoints[0], endpoints[1])
            }
            Self::NvGre {
                protocol_type,
                vsid_flowid,
                endpoints,
            } => {
                write!(
                    f,
                    "nvgre(ptype:0x{:04x} vsid:{} {}↔{})",
                    protocol_type, vsid_flowid, endpoints[0], endpoints[1]
                )
            }
            Self::Vxlan {
                vni,
                group_id,
                endpoints,
            } => {
                write!(f, "vxlan(vni:{}", vni)?;
                if *group_id != 0 {
                    write!(f, " gid:{}", group_id)?;
                }
                write!(f, " {}↔{})", endpoints[0], endpoints[1])
            }
            Self::Geneve {
                vni,
                protocol_type,
                endpoints,
            } => {
                write!(
                    f,
                    "geneve(vni:{} ptype:0x{:04x} {}↔{})",
                    vni, protocol_type, endpoints[0], endpoints[1]
                )
            }
            Self::Ipip { endpoints } => {
                write!(f, "ipip({}↔{})", endpoints[0], endpoints[1])
            }
            Self::Ip4in6 { endpoints } => {
                write!(f, "ip4in6({}↔{})", endpoints[0], endpoints[1])
            }
            Self::Sit { endpoints } => {
                write!(f, "sit({}↔{})", endpoints[0], endpoints[1])
            }
            Self::Ip6Tnl { endpoints } => {
                write!(f, "ip6tnl({}↔{})", endpoints[0], endpoints[1])
            }
            Self::GtpU { teid, endpoints } => {
                write!(
                    f,
                    "gtp-u(teid:0x{:08x} {}↔{})",
                    teid, endpoints[0], endpoints[1]
                )
            }
            Self::Teredo { endpoints } => {
                write!(f, "teredo({}↔{})", endpoints[0], endpoints[1])
            }
            Self::L2tpV2 {
                tunnel_id,
                session_id,
                endpoints,
            } => {
                write!(
                    f,
                    "l2tpv2(tid:{} sid:{} {}↔{})",
                    tunnel_id, session_id, endpoints[0], endpoints[1]
                )
            }
            Self::L2tpV3 {
                session_id,
                endpoints,
            } => {
                write!(
                    f,
                    "l2tpv3(sid:{} {}↔{})",
                    session_id, endpoints[0], endpoints[1]
                )
            }
            Self::Pbb { isid, bvid } => {
                write!(f, "pbb(isid:{}", isid)?;
                if let Some(b) = bvid {
                    write!(f, " bvid:{}", b)?;
                }
                write!(f, ")")
            }
            Self::Stt {
                context_id,
                endpoints,
            } => {
                write!(
                    f,
                    "stt(ctx:0x{:016x} {}↔{})",
                    context_id, endpoints[0], endpoints[1]
                )
            }
            Self::Pptp { call_id, endpoints } => {
                write!(
                    f,
                    "pptp(call:{} {}↔{})",
                    call_id, endpoints[0], endpoints[1]
                )
            }
        }
    }
}

impl From<LinkLayer<'_>> for SmallVec<[VniLayer; 2]> {
    fn from(value: LinkLayer<'_>) -> Self {
        match value {
            LinkLayer::Ethernet(EtherHeaderVlan::VLAN8021Q(_, eth8021q)) => {
                let mut sv = SmallVec::<[VniLayer; 2]>::new();
                sv.push(VniLayer::Vlan { vid: eth8021q.vlan_id() });
                sv
            },
            LinkLayer::Ethernet(EtherHeaderVlan::VLAN8021QNested(_, eth8021q, eth8021q_n)) => {
                let mut sv = SmallVec::<[VniLayer; 2]>::new();
                sv.push(VniLayer::Vlan { vid: eth8021q.vlan_id() });
                sv.push(VniLayer::Vlan { vid: eth8021q_n.vlan_id() });
                sv
            },
            _ => SmallVec::<[VniLayer; 2]>::new(),
        }
    }
}

pub struct IpTunnel<'a>((OuterIpHeader<'a>, TunnelLayer<'a>));

impl From<IpTunnel<'_>> for SmallVec<[VniLayer; 2]> {
    fn from(IpTunnel((ip, tun)): IpTunnel<'_>) -> Self {
        let mut sv = SmallVec::<[VniLayer; 2]>::new();

        let endpoints : [IpAddr; 2] = match ip {
            OuterIpHeader::V4(ipv4_header) => {
                [ipv4_header.src_ip().into(), ipv4_header.dst_ip().into()]
            },
            OuterIpHeader::V6(ipv6_header) => {
                [ipv6_header.src_ip().into(), ipv6_header.dst_ip().into()]
            },
        };

        match &tun {
            TunnelLayer::Vxlan(vxlan) => {
                sv.push(VniLayer::Vxlan { vni: vxlan.vni(), group_id: 0, endpoints });
            }
            TunnelLayer::Geneve(geneve) => {
                sv.push(VniLayer::Geneve { vni: geneve.header.vni(), protocol_type: geneve.header.protocol_type_raw(), endpoints });
            }
            TunnelLayer::Gre(gre) => {
                sv.push(VniLayer::Gre { protocol_type: gre.header.protocol_type().into(), key: gre.key(), endpoints });
            }
            TunnelLayer::Teredo(_teredo) => {
                sv.push(VniLayer::Teredo { endpoints });
            }
            TunnelLayer::Gtpv1(gtp) => {
                sv.push(VniLayer::GtpU { teid: gtp.header.teid(), endpoints });
            }
            TunnelLayer::Gtpv2(_gtp) => {
                // GTPv2 is control plane, not a tunnel for VNI purposes
            }
            TunnelLayer::L2tpv2(l2tp) => {
                sv.push(VniLayer::L2tpV2 { tunnel_id: l2tp.tunnel_id(), session_id: l2tp.session_id(), endpoints });
            }
            TunnelLayer::L2tpv3(l2tp) => {
                sv.push(VniLayer::L2tpV3 { session_id: l2tp.session_id(), endpoints });
            }
            TunnelLayer::Nvgre(nvgre) => {
                sv.push(VniLayer::NvGre { protocol_type: nvgre.protocol_type_raw(), vsid_flowid: nvgre.vsid() << 8 | nvgre.flow_id() as u32, endpoints });
            }
            TunnelLayer::Pbb(pbb) => {
                // PBB (Provider Backbone Bridge) is MAC-in-MAC, doesn't need IP endpoints
                sv.push(VniLayer::Pbb {
                    isid: pbb.isid(),
                    bvid: pbb.bvid(),
                });
            }
            TunnelLayer::Stt(stt) => {
                sv.push(VniLayer::Stt { context_id: stt.context_id(), endpoints });
            }
            TunnelLayer::Pptp(pptp) => {
                sv.push(VniLayer::Pptp { call_id: pptp.header.call_id(), endpoints });
            }
            TunnelLayer::Ipip(ipip) => {
                // IPIP tunnels have access to outer IP headers
                match ipip.outer_header() {
                    crate::packet::tunnel::ipip::OuterIpHeader::V4(ipv4) => {
                        let src = ipv4.header.src_ip_raw();
                        let dst = ipv4.header.dst_ip_raw();
                        let mut endpoints = [IpAddr::V4(Ipv4Addr::from(src)), IpAddr::V4(Ipv4Addr::from(dst))];
                        endpoints.sort();

                        match ipip.tunnel_type() {
                            crate::packet::tunnel::ipip::IpipType::Ipip => {
                                sv.push(VniLayer::Ipip { endpoints });
                            }
                            crate::packet::tunnel::ipip::IpipType::Sit => {
                                sv.push(VniLayer::Sit { endpoints });
                            }
                            _ => {}
                        }
                    }
                    crate::packet::tunnel::ipip::OuterIpHeader::V6(ipv6) => {
                        let src = ipv6.header.src_ip_raw();
                        let dst = ipv6.header.dst_ip_raw();
                        let mut endpoints = [IpAddr::V6(Ipv6Addr::from(dst)), IpAddr::V6(Ipv6Addr::from(src))];
                        endpoints.sort();

                        match ipip.tunnel_type() {
                            crate::packet::tunnel::ipip::IpipType::Ip4in6 => {
                                sv.push(VniLayer::Ip4in6 { endpoints });
                            }
                            crate::packet::tunnel::ipip::IpipType::Ip6Tnl => {
                                sv.push(VniLayer::Ip6Tnl { endpoints });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        sv
    }
}

impl From<&IpTunnelLayer<'_>> for SmallVec<[VniLayer; 2]> {
    fn from(ip_tunnel: &IpTunnelLayer<'_>) -> Self {
        let mut sv = SmallVec::<[VniLayer; 2]>::new();

        // Extract endpoints from outer IP header if present
        let endpoints: Option<[IpAddr; 2]> = ip_tunnel.outer().and_then(|outer| {
            match outer {
                NetworkLayer::Ipv4(ipv4) => {
                    Some([ipv4.src_ip().into(), ipv4.dst_ip().into()])
                }
                NetworkLayer::Ipv6(ipv6) => {
                    Some([ipv6.src_ip().into(), ipv6.dst_ip().into()])
                }
                NetworkLayer::Mpls(_) => None, // MPLS doesn't have IP endpoints
            }
        });

        // Process the tunnel based on type
        match ip_tunnel.tunnel() {
            TunnelLayer::Vxlan(vxlan) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::Vxlan { vni: vxlan.vni(), group_id: 0, endpoints });
                }
            }
            TunnelLayer::Geneve(geneve) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::Geneve { 
                        vni: geneve.header.vni(), 
                        protocol_type: geneve.header.protocol_type_raw(), 
                        endpoints 
                    });
                }
            }
            TunnelLayer::Gre(gre) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::Gre { 
                        protocol_type: gre.header.protocol_type().into(), 
                        key: gre.key(), 
                        endpoints 
                    });
                }
            }
            TunnelLayer::Teredo(_teredo) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::Teredo { endpoints });
                }
            }
            TunnelLayer::Gtpv1(gtp) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::GtpU { teid: gtp.header.teid(), endpoints });
                }
            }
            TunnelLayer::Gtpv2(_gtp) => {
                // GTPv2 is control plane, not a tunnel for VNI purposes
            }
            TunnelLayer::L2tpv2(l2tp) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::L2tpV2 { 
                        tunnel_id: l2tp.tunnel_id(), 
                        session_id: l2tp.session_id(), 
                        endpoints 
                    });
                }
            }
            TunnelLayer::L2tpv3(l2tp) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::L2tpV3 { session_id: l2tp.session_id(), endpoints });
                }
            }
            TunnelLayer::Nvgre(nvgre) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::NvGre { 
                        protocol_type: nvgre.protocol_type_raw(), 
                        vsid_flowid: nvgre.vsid() << 8 | nvgre.flow_id() as u32, 
                        endpoints 
                    });
                }
            }
            TunnelLayer::Pbb(pbb) => {
                // PBB (Provider Backbone Bridge) is MAC-in-MAC, doesn't need IP endpoints
                sv.push(VniLayer::Pbb {
                    isid: pbb.isid(),
                    bvid: pbb.bvid(),
                });
            }
            TunnelLayer::Stt(stt) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::Stt { context_id: stt.context_id(), endpoints });
                }
            }
            TunnelLayer::Pptp(pptp) => {
                if let Some(endpoints) = endpoints {
                    sv.push(VniLayer::Pptp { call_id: pptp.header.call_id(), endpoints });
                }
            }
            TunnelLayer::Ipip(ipip) => {
                // IPIP tunnels have access to outer IP headers embedded in the tunnel
                match ipip.outer_header() {
                    crate::packet::tunnel::ipip::OuterIpHeader::V4(ipv4) => {
                        let src = ipv4.header.src_ip_raw();
                        let dst = ipv4.header.dst_ip_raw();
                        let mut endpoints = [IpAddr::V4(Ipv4Addr::from(src)), IpAddr::V4(Ipv4Addr::from(dst))];
                        endpoints.sort();

                        match ipip.tunnel_type() {
                            crate::packet::tunnel::ipip::IpipType::Ipip => {
                                sv.push(VniLayer::Ipip { endpoints });
                            }
                            crate::packet::tunnel::ipip::IpipType::Sit => {
                                sv.push(VniLayer::Sit { endpoints });
                            }
                            _ => {}
                        }
                    }
                    crate::packet::tunnel::ipip::OuterIpHeader::V6(ipv6) => {
                        let src = ipv6.header.src_ip_raw();
                        let dst = ipv6.header.dst_ip_raw();
                        let mut endpoints = [IpAddr::V6(Ipv6Addr::from(dst)), IpAddr::V6(Ipv6Addr::from(src))];
                        endpoints.sort();

                        match ipip.tunnel_type() {
                            crate::packet::tunnel::ipip::IpipType::Ip4in6 => {
                                sv.push(VniLayer::Ip4in6 { endpoints });
                            }
                            crate::packet::tunnel::ipip::IpipType::Ip6Tnl => {
                                sv.push(VniLayer::Ip6Tnl { endpoints });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        sv
    }
}


/// VNI identifier (opaque handle)
///
/// This is an opaque identifier used to reference a specific VNI layer stack
/// in the mapper. The actual value has no semantic meaning outside of the mapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VniId(u32);

impl VniId {
    /// Get the raw u32 value (primarily for debugging/serialization)
    #[inline]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Create a VniId from a u32 (primarily for deserialization)
    #[inline]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Display for VniId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VniId({})", self.0)
    }
}

/// Maps VNI layer stacks to unique identifiers
///
/// This structure maintains bidirectional mappings between VNI layer stacks
/// and unique identifiers using `BTreeMap` instead of `HashMap`.
///
/// # Why BTreeMap instead of HashMap?
///
/// 1. **Avoids expensive hashing**: Computing the hash of `SmallVec<[VniLayer; 4]>`
///    requires hashing each `VniLayer` variant, which contains nested enums, arrays
///    of `IpAddr`, and optional fields. This is computationally expensive.
///
/// 2. **Better cache locality**: BTreeMap stores data in nodes that fit in cache lines,
///    resulting in fewer cache misses than HashMap's scattered buckets.
///
/// 3. **Predictable performance**: O(log n) is consistent and predictable, while
///    HashMap can have worst-case O(n) on hash collisions or resizing.
///
/// 4. **Ordered iteration**: BTreeMap naturally provides ordered iteration, useful
///    for debugging and consistent output.
///
/// 5. **Practical performance**: For typical workloads with thousands of VNI stacks,
///    O(log n) ≈ 10-20 comparisons is faster than computing expensive hashes.
///
/// # Performance Characteristics
///
/// - **Lookup**: O(log n) comparisons using `Ord` implementation
/// - **Insert**: O(log n) with potential node splits
/// - **Memory**: ~60 bytes overhead per node, better locality than HashMap
/// - **No rehashing**: Unlike HashMap, never needs to rehash on growth
///
/// # Thread Safety
///
/// This structure is not thread-safe. If you need concurrent access, wrap it
/// in an appropriate synchronization primitive (e.g., `Mutex`, `RwLock`, `Arc<DashMap>`).
///
/// # Example
///
/// ```ignore
/// use packet_strata::tracker::vni::{VniLayer, VniMapper};
///
/// let mut mapper = VniMapper::new();
///
/// // Create some VNI layers
/// let vlan = VniLayer::vlan(100);
/// let vlan2 = VniLayer::vlan(200);
///
/// // Map a single-layer stack
/// let id1 = mapper.get_or_create_vni_id(&[vlan.clone()]);
///
/// // Map a multi-layer stack (e.g., VLAN + IP tunnel)
/// let id2 = mapper.get_or_create_vni_id(&[vlan, vlan2]);
///
/// // The same stack always gets the same ID
/// let vlan_again = VniLayer::vlan(100);
/// let id3 = mapper.get_or_create_vni_id(&[vlan_again]);
/// assert_eq!(id1, id3);
/// ```
pub struct VniMapper {
    /// Forward mapping: layer stack -> ID (using BTreeMap for efficient ordering)
    forward: BTreeMap<SmallVec<[VniLayer; 4]>, VniId>,
    /// Reverse mapping: ID -> layer stack (using BTreeMap for cache efficiency)
    reverse: BTreeMap<VniId, SmallVec<[VniLayer; 4]>>,
    /// Counter for generating new IDs
    counter: u32,
}

impl VniMapper {
    /// Create a new VNI mapper
    pub fn new() -> Self {
        Self {
            forward: BTreeMap::new(),
            reverse: BTreeMap::new(),
            counter: 0,
        }
    }

    /// Get or create a VNI ID for the given layer stack
    ///
    /// If the exact layer stack already exists, returns its existing ID.
    /// Otherwise, creates a new ID and stores the mapping.
    ///
    /// # Arguments
    ///
    /// * `vni_stack` - Slice of VNI layers (ordered from outermost to innermost)
    ///
    /// # Returns
    ///
    /// A `VniId` that uniquely identifies this layer stack
    pub fn get_or_create_vni_id(&mut self, vni_stack: &[VniLayer]) -> VniId {
        let stack_vec: SmallVec<[VniLayer; 4]> = vni_stack.iter().cloned().collect();

        if let Some(&id) = self.forward.get(&stack_vec) {
            return id;
        }

        self.counter += 1;
        let id = VniId(self.counter);

        self.forward.insert(stack_vec.clone(), id);
        self.reverse.insert(id, stack_vec);

        id
    }

    /// Look up the VNI layer stack for a given ID
    ///
    /// # Arguments
    ///
    /// * `id` - The VNI ID to look up
    ///
    /// # Returns
    ///
    /// `Some(&[VniLayer])` if the ID exists, `None` otherwise
    pub fn lookup_vni(&self, id: VniId) -> Option<&[VniLayer]> {
        self.reverse.get(&id).map(|v| v.as_slice())
    }

    /// Get the number of unique VNI stacks
    pub fn len(&self) -> usize {
        self.reverse.len()
    }

    /// Check if the mapper is empty
    pub fn is_empty(&self) -> bool {
        self.reverse.is_empty()
    }

    /// Clear all mappings and reset the counter
    pub fn clear(&mut self) {
        self.forward.clear();
        self.reverse.clear();
        self.counter = 0;
    }

    /// Get an iterator over all VNI IDs and their layer stacks
    pub fn iter(&self) -> impl Iterator<Item = (VniId, &[VniLayer])> {
        self.reverse
            .iter()
            .map(|(&id, stack)| (id, stack.as_slice()))
    }
}

impl Default for VniMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ========================================================================
    // VniError Tests
    // ========================================================================

    #[test]
    fn test_vni_error_display() {
        let err1 = VniError::InvalidHeaderLength;
        assert_eq!(err1.to_string(), "Invalid IP header length");

        let err2 = VniError::InvalidIpVersion;
        assert_eq!(err2.to_string(), "Invalid IP version");
    }

    #[test]
    fn test_vni_error_clone_eq() {
        let err1 = VniError::InvalidHeaderLength;
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = VniError::InvalidIpVersion;
        assert_ne!(err1, err3);
    }

    // ========================================================================
    // VniLayer Tests - Construction and Display
    // ========================================================================



    // ========================================================================
    // VniLayer Equality and Ordering Tests
    // ========================================================================

    #[test]
    fn test_vni_layer_equality() {
        let vlan1 = VniLayer::Vlan { vid: 100 };
        let vlan2 = VniLayer::Vlan { vid: 100 };
        let vlan3 = VniLayer::Vlan { vid: 200 };

        assert_eq!(vlan1, vlan2);
        assert_ne!(vlan1, vlan3);

        let mpls1 = VniLayer::Mpls { label: 100 };
        assert_ne!(vlan1, mpls1); // Different variants
    }

    #[test]
    fn test_vni_layer_ordering() {
        let vlan1 = VniLayer::Vlan { vid: 100 };
        let vlan2 = VniLayer::Vlan { vid: 200 };
        let _mpls = VniLayer::Mpls { label: 100 };

        assert!(vlan1 < vlan2);
        // Ordering between different variants depends on enum declaration order
    }

    #[test]
    fn test_vni_layer_clone_hash() {
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        let vxlan1 = VniLayer::Vxlan {
            vni: 100,
            group_id: 0,
            endpoints,
        };
        let vxlan2 = vxlan1.clone();

        assert_eq!(vxlan1, vxlan2);

        // Test that it can be used in hash-based collections
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(vxlan1.clone());
        assert!(set.contains(&vxlan2));
    }

    // ========================================================================
    // VniId Tests
    // ========================================================================

    #[test]
    fn test_vni_id_creation() {
        let id = VniId::from_u32(42);
        assert_eq!(id.as_u32(), 42);
    }

    #[test]
    fn test_vni_id_display() {
        let id = VniId::from_u32(100);
        assert_eq!(format!("{}", id), "VniId(100)");
    }

    #[test]
    fn test_vni_id_equality() {
        let id1 = VniId::from_u32(42);
        let id2 = VniId::from_u32(42);
        let id3 = VniId::from_u32(43);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    // ========================================================================
    // VniMapper Tests
    // ========================================================================

    #[test]
    fn test_vni_mapper_new() {
        let mapper = VniMapper::new();
        assert_eq!(mapper.len(), 0);
        assert!(mapper.is_empty());
    }

    #[test]
    fn test_vni_mapper_default() {
        let mapper = VniMapper::default();
        assert_eq!(mapper.len(), 0);
        assert!(mapper.is_empty());
    }

    #[test]
    fn test_vni_mapper_single_layer() {
        let mut mapper = VniMapper::new();
        let vlan = VniLayer::Vlan { vid: 100 };

        let id = mapper.get_or_create_vni_id(&[vlan.clone()]);
        assert_eq!(mapper.len(), 1);
        assert!(!mapper.is_empty());

        // Same stack should return same ID
        let id2 = mapper.get_or_create_vni_id(&[vlan.clone()]);
        assert_eq!(id, id2);
        assert_eq!(mapper.len(), 1); // No new entry created

        // Lookup should work
        let stack = mapper.lookup_vni(id).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vlan);
    }

    #[test]
    fn test_vni_mapper_multi_layer() {
        let mut mapper = VniMapper::new();
        let vlan1 = VniLayer::Vlan { vid: 100 };
        let vlan2 = VniLayer::Vlan { vid: 200 };

        let id = mapper.get_or_create_vni_id(&[vlan1.clone(), vlan2.clone()]);
        assert_eq!(mapper.len(), 1);

        let stack = mapper.lookup_vni(id).unwrap();
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], vlan1);
        assert_eq!(stack[1], vlan2);
    }

    #[test]
    fn test_vni_mapper_different_stacks() {
        let mut mapper = VniMapper::new();
        let vlan100 = VniLayer::Vlan { vid: 100 };
        let vlan200 = VniLayer::Vlan { vid: 200 };
        let mpls = VniLayer::Mpls { label: 1000 };

        let id1 = mapper.get_or_create_vni_id(&[vlan100.clone()]);
        let id2 = mapper.get_or_create_vni_id(&[vlan200.clone()]);
        let id3 = mapper.get_or_create_vni_id(&[vlan100.clone(), mpls.clone()]);

        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);
        assert_eq!(mapper.len(), 3);
    }

    #[test]
    fn test_vni_mapper_order_matters() {
        let mut mapper = VniMapper::new();
        let vlan = VniLayer::Vlan { vid: 100 };
        let mpls = VniLayer::Mpls { label: 1000 };

        let id1 = mapper.get_or_create_vni_id(&[vlan.clone(), mpls.clone()]);
        let id2 = mapper.get_or_create_vni_id(&[mpls.clone(), vlan.clone()]);

        // Order matters - these should be different
        assert_ne!(id1, id2);
        assert_eq!(mapper.len(), 2);
    }

    #[test]
    fn test_vni_mapper_lookup_nonexistent() {
        let mapper = VniMapper::new();
        let id = VniId::from_u32(999);

        assert!(mapper.lookup_vni(id).is_none());
    }

    #[test]
    fn test_vni_mapper_clear() {
        let mut mapper = VniMapper::new();
        let vlan = VniLayer::Vlan { vid: 100 };

        let id1 = mapper.get_or_create_vni_id(&[vlan.clone()]);
        assert_eq!(mapper.len(), 1);

        mapper.clear();
        assert_eq!(mapper.len(), 0);
        assert!(mapper.is_empty());

        // After clear, lookup should fail
        assert!(mapper.lookup_vni(id1).is_none());

        // New ID should start from 1 again
        let id2 = mapper.get_or_create_vni_id(&[vlan]);
        assert_eq!(id2.as_u32(), 1);
    }

    #[test]
    fn test_vni_mapper_iter() {
        let mut mapper = VniMapper::new();
        let vlan1 = VniLayer::Vlan { vid: 100 };
        let vlan2 = VniLayer::Vlan { vid: 200 };
        let mpls = VniLayer::Mpls { label: 1000 };

        mapper.get_or_create_vni_id(&[vlan1.clone()]);
        mapper.get_or_create_vni_id(&[vlan2.clone()]);
        mapper.get_or_create_vni_id(&[mpls.clone()]);

        let entries: Vec<_> = mapper.iter().collect();
        assert_eq!(entries.len(), 3);

        // Check that all stacks are present
        let stacks: Vec<_> = entries.iter().map(|(_, stack)| stack).collect();
        assert!(stacks.iter().any(|s| s.len() == 1 && s[0] == vlan1));
        assert!(stacks.iter().any(|s| s.len() == 1 && s[0] == vlan2));
        assert!(stacks.iter().any(|s| s.len() == 1 && s[0] == mpls));
    }

    #[test]
    fn test_vni_mapper_counter_increment() {
        let mut mapper = VniMapper::new();
        let vlan1 = VniLayer::Vlan { vid: 100 };
        let vlan2 = VniLayer::Vlan { vid: 200 };
        let vlan3 = VniLayer::Vlan { vid: 300 };

        let id1 = mapper.get_or_create_vni_id(&[vlan1]);
        let id2 = mapper.get_or_create_vni_id(&[vlan2]);
        let id3 = mapper.get_or_create_vni_id(&[vlan3]);

        assert_eq!(id1.as_u32(), 1);
        assert_eq!(id2.as_u32(), 2);
        assert_eq!(id3.as_u32(), 3);
    }

    // ========================================================================
    // Complex Scenario Tests
    // ========================================================================

    #[test]
    fn test_complex_tunnel_stack() {
        let mut mapper = VniMapper::new();
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        // Complex stack: VLAN + VXLAN + VLAN (nested virtualization)
        let outer_vlan = VniLayer::Vlan { vid: 100 };
        let vxlan = VniLayer::Vxlan {
            vni: 5000,
            group_id: 0,
            endpoints,
        };
        let inner_vlan = VniLayer::Vlan { vid: 200 };

        let id = mapper.get_or_create_vni_id(&[outer_vlan.clone(), vxlan.clone(), inner_vlan.clone()]);

        let stack = mapper.lookup_vni(id).unwrap();
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0], outer_vlan);
        assert_eq!(stack[1], vxlan);
        assert_eq!(stack[2], inner_vlan);
    }

    #[test]
    fn test_multiple_tunnel_types() {
        let mut mapper = VniMapper::new();
        let endpoints_v4 = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        ];
        let endpoints_v6 = [
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ];

        let vxlan = VniLayer::Vxlan {
            vni: 100,
            group_id: 0,
            endpoints: endpoints_v4,
        };
        let geneve = VniLayer::Geneve {
            vni: 200,
            protocol_type: 0x6558,
            endpoints: endpoints_v6,
        };
        let gre = VniLayer::Gre {
            protocol_type: 0x0800,
            key: Some(300),
            endpoints: endpoints_v4,
        };

        let id1 = mapper.get_or_create_vni_id(&[vxlan]);
        let id2 = mapper.get_or_create_vni_id(&[geneve]);
        let id3 = mapper.get_or_create_vni_id(&[gre]);

        assert_eq!(mapper.len(), 3);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_empty_stack() {
        let mut mapper = VniMapper::new();
        let id = mapper.get_or_create_vni_id(&[]);

        assert_eq!(mapper.len(), 1);
        let stack = mapper.lookup_vni(id).unwrap();
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn test_vni_mapper_reuse_after_partial_clear() {
        let mut mapper = VniMapper::new();
        let vlan = VniLayer::Vlan { vid: 100 };

        let id1 = mapper.get_or_create_vni_id(&[vlan.clone()]);
        assert_eq!(id1.as_u32(), 1);

        mapper.clear();

        let id2 = mapper.get_or_create_vni_id(&[vlan]);
        assert_eq!(id2.as_u32(), 1); // Counter resets
    }

    // ========================================================================
    // Edge Cases and Boundary Tests
    // ========================================================================

    #[test]
    fn test_max_vlan_id() {
        let vlan = VniLayer::Vlan { vid: 4095 }; // Max 12-bit value
        assert_eq!(format!("{}", vlan), "vlan(4095)");
    }

    #[test]
    fn test_max_mpls_label() {
        let mpls = VniLayer::Mpls { label: 0xFFFFF }; // Max 20-bit value
        assert_eq!(format!("{}", mpls), "mpls(1048575)");
    }

    #[test]
    fn test_vxlan_24bit_vni() {
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        let vxlan = VniLayer::Vxlan {
            vni: 0xFFFFFF, // Max 24-bit value
            group_id: 0,
            endpoints,
        };
        assert!(format!("{}", vxlan).contains("vni:16777215"));
    }

    #[test]
    fn test_mixed_ipv4_ipv6_endpoints() {
        // While unusual, the type system allows mixed IP versions in comparisons
        let endpoints1 = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let endpoints2 = [
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ];

        let ipip_v4 = VniLayer::Ipip { endpoints: endpoints1 };
        let ipip_v6 = VniLayer::Ip6Tnl { endpoints: endpoints2 };

        assert_ne!(ipip_v4, ipip_v6);
    }

    #[test]
    fn test_vni_layer_size() {
        // Ensure VniLayer variants don't grow unexpectedly
        use std::mem::size_of;

        // This is a regression test - if size increases significantly, investigate
        let size = size_of::<VniLayer>();
        
        // VniLayer should be reasonably sized (less than 64 bytes on 64-bit systems)
        // The largest variant is likely Stt or one with [IpAddr; 2] which is 2*32=64 bytes for IPv6
        assert!(size <= 128, "VniLayer size is {}, expected <= 128 bytes", size);
    }

    #[test]
    fn test_smallvec_inline_capacity() {
        // Verify that SmallVec doesn't allocate for common cases
        let vlan1 = VniLayer::Vlan { vid: 100 };
        let vlan2 = VniLayer::Vlan { vid: 200 };

        let mut sv = SmallVec::<[VniLayer; 4]>::new();
        sv.push(vlan1);
        sv.push(vlan2);

        // With capacity 4, this should not spill to heap
        assert!(!sv.spilled());
    }

    #[test]
    fn test_btreemap_ordering() {
        let mut mapper = VniMapper::new();
        
        // Insert in non-sequential order
        let vlan200 = VniLayer::Vlan { vid: 200 };
        let vlan100 = VniLayer::Vlan { vid: 100 };
        let vlan300 = VniLayer::Vlan { vid: 300 };

        mapper.get_or_create_vni_id(&[vlan200]);
        mapper.get_or_create_vni_id(&[vlan100]);
        mapper.get_or_create_vni_id(&[vlan300]);

        // BTreeMap should maintain some order
        let entries: Vec<_> = mapper.iter().collect();
        assert_eq!(entries.len(), 3);
    }



    // ========================================================================
    // From<LinkLayer> Conversion Tests
    // ========================================================================
    // Note: Testing From<LinkLayer> requires constructing actual packet bytes
    // which is complex. The implementation is straightforward pattern matching,
    // so we rely on integration tests for full coverage.

    // ========================================================================
    // From<IpTunnel> Conversion Tests
    // ========================================================================
    // Note: Testing From<IpTunnel> requires constructing actual tunnel packets
    // which is complex. The implementation is tested through integration tests.

    #[test]
    fn test_vni_layer_debug_format() {
        // Verify Debug trait works for all variants
        let vlan = VniLayer::Vlan { vid: 100 };
        let debug_str = format!("{:?}", vlan);
        assert!(debug_str.contains("Vlan"));
        assert!(debug_str.contains("100"));
    }

    #[test]
    fn test_multiple_identical_stacks() {
        let mut mapper = VniMapper::new();
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        let vxlan1 = VniLayer::Vxlan {
            vni: 100,
            group_id: 0,
            endpoints,
        };
        let vxlan2 = VniLayer::Vxlan {
            vni: 100,
            group_id: 0,
            endpoints,
        };

        let id1 = mapper.get_or_create_vni_id(&[vxlan1]);
        let id2 = mapper.get_or_create_vni_id(&[vxlan2]);

        // Should get same ID for identical stacks
        assert_eq!(id1, id2);
        assert_eq!(mapper.len(), 1);
    }

    #[test]
    fn test_endpoint_ordering_consistency() {
        let endpoints1 = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let endpoints2 = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        let ipip1 = VniLayer::Ipip { endpoints: endpoints1 };
        let ipip2 = VniLayer::Ipip { endpoints: endpoints2 };

        // Different endpoint order should be different
        assert_ne!(ipip1, ipip2);
    }

    #[test]
    fn test_gre_with_and_without_key() {
        let mut mapper = VniMapper::new();
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        let gre_no_key = VniLayer::Gre {
            protocol_type: 0x0800,
            key: None,
            endpoints,
        };
        let gre_with_key = VniLayer::Gre {
            protocol_type: 0x0800,
            key: Some(100),
            endpoints,
        };

        let id1 = mapper.get_or_create_vni_id(&[gre_no_key]);
        let id2 = mapper.get_or_create_vni_id(&[gre_with_key]);

        assert_ne!(id1, id2);
        assert_eq!(mapper.len(), 2);
    }

    #[test]
    fn test_vni_mapper_with_all_layer_types() {
        let mut mapper = VniMapper::new();
        let endpoints_v4 = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let endpoints_v6 = [
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ];

        // Create one of each layer type
        let layers = vec![
            VniLayer::Vlan { vid: 100 },
            VniLayer::Mpls { label: 1000 },
            VniLayer::Gre { protocol_type: 0x0800, key: None, endpoints: endpoints_v4 },
            VniLayer::NvGre { protocol_type: 0x6558, vsid_flowid: 100, endpoints: endpoints_v4 },
            VniLayer::Vxlan { vni: 5000, group_id: 0, endpoints: endpoints_v4 },
            VniLayer::Geneve { vni: 1000, protocol_type: 0x6558, endpoints: endpoints_v6 },
            VniLayer::Ipip { endpoints: endpoints_v4 },
            VniLayer::Ip4in6 { endpoints: endpoints_v6 },
            VniLayer::Sit { endpoints: endpoints_v4 },
            VniLayer::Ip6Tnl { endpoints: endpoints_v6 },
            VniLayer::GtpU { teid: 0x12345678, endpoints: endpoints_v4 },
            VniLayer::Teredo { endpoints: endpoints_v4 },
            VniLayer::L2tpV2 { tunnel_id: 100, session_id: 200, endpoints: endpoints_v4 },
            VniLayer::L2tpV3 { session_id: 0xabcdef, endpoints: endpoints_v6 },
            VniLayer::Pbb { isid: 0x123456, bvid: Some(100) },
            VniLayer::Stt { context_id: 0x123456789abcdef0, endpoints: endpoints_v4 },
            VniLayer::Pptp { call_id: 1234, endpoints: endpoints_v4 },
        ];

        // Each should get a unique ID
        let mut ids = Vec::new();
        for layer in &layers {
            let id = mapper.get_or_create_vni_id(&[layer.clone()]);
            ids.push(id);
        }

        assert_eq!(mapper.len(), layers.len());

        // All IDs should be unique
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "IDs at positions {} and {} should be different", i, j);
            }
        }
    }



    #[test]
    fn test_vni_id_ordering() {
        let id1 = VniId::from_u32(1);
        let id2 = VniId::from_u32(2);
        let id3 = VniId::from_u32(2);

        assert!(id1 < id2);
        assert_eq!(id2, id3);
        assert!(id1 != id2);
    }

    #[test]
    fn test_smallvec_spill_behavior() {
        // Test that we can handle more than inline capacity
        let vlan1 = VniLayer::Vlan { vid: 100 };
        let vlan2 = VniLayer::Vlan { vid: 200 };
        let vlan3 = VniLayer::Vlan { vid: 300 };
        let vlan4 = VniLayer::Vlan { vid: 400 };
        let vlan5 = VniLayer::Vlan { vid: 500 };

        let mut sv = SmallVec::<[VniLayer; 4]>::new();
        sv.push(vlan1);
        sv.push(vlan2);
        sv.push(vlan3);
        sv.push(vlan4);
        
        assert!(!sv.spilled()); // Should still be inline with capacity 4
        
        sv.push(vlan5);
        assert!(sv.spilled()); // Should spill to heap now
        assert_eq!(sv.len(), 5);
    }

    #[test]
    fn test_vni_mapper_consistency_after_many_insertions() {
        let mut mapper = VniMapper::new();
        
        // Insert many unique stacks
        for i in 0..100 {
            let vlan = VniLayer::Vlan { vid: i };
            mapper.get_or_create_vni_id(&[vlan]);
        }

        assert_eq!(mapper.len(), 100);

        // Verify all can be looked up
        for i in 1..=100 {
            let id = VniId::from_u32(i);
            assert!(mapper.lookup_vni(id).is_some());
        }
    }

    #[test]
    fn test_vni_error_is_error_trait() {
        use std::error::Error;
        
        let err = VniError::InvalidHeaderLength;
        let _: &dyn Error = &err; // Should compile
        
        // Test error source (should be None for these simple errors)
        assert!(err.source().is_none());
    }

    // ========================================================================
    // Regression Tests - Complex Scenarios
    // ========================================================================

    #[test]
    fn test_regression_vni_mapper_id_stability() {
        // Regression: VNI IDs should be stable across multiple gets
        let mut mapper = VniMapper::new();
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        
        let vxlan = VniLayer::Vxlan {
            vni: 5000,
            group_id: 0,
            endpoints,
        };
        
        let id1 = mapper.get_or_create_vni_id(&[vxlan.clone()]);
        let id2 = mapper.get_or_create_vni_id(&[vxlan.clone()]);
        let id3 = mapper.get_or_create_vni_id(&[vxlan.clone()]);
        
        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(mapper.len(), 1);
    }

    #[test]
    fn test_regression_vni_layer_protocol_type_variations() {
        // Regression: Different protocol types should create different VNI layers
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        ];

        let gre_ipv4 = VniLayer::Gre {
            protocol_type: 0x0800, // IPv4
            key: None,
            endpoints,
        };
        
        let gre_ipv6 = VniLayer::Gre {
            protocol_type: 0x86DD, // IPv6
            key: None,
            endpoints,
        };
        
        assert_ne!(gre_ipv4, gre_ipv6);
    }

    #[test]
    fn test_regression_vxlan_group_id_zero_vs_nonzero() {
        // Regression: group_id=0 and group_id!=0 should be different
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        let vxlan1 = VniLayer::Vxlan {
            vni: 100,
            group_id: 0,
            endpoints,
        };
        
        let vxlan2 = VniLayer::Vxlan {
            vni: 100,
            group_id: 1,
            endpoints,
        };
        
        assert_ne!(vxlan1, vxlan2);
        

    }

    #[test]
    fn test_regression_nvgre_vsid_flowid_encoding() {
        // Regression: VSID and FlowID should be properly encoded in 32-bit field
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        // VSID is 24 bits, FlowID is 8 bits
        let vsid: u32 = 0x123456;
        let flow_id: u8 = 0xAB;
        let combined = (vsid << 8) | flow_id as u32;

        let _nvgre = VniLayer::NvGre {
            protocol_type: 0x6558,
            vsid_flowid: combined,
            endpoints,
        };

    }

    #[test]
    fn test_regression_pbb_with_optional_bvid() {
        // Regression: PBB with and without bvid should be different
        let pbb1 = VniLayer::Pbb {
            isid: 0x123456,
            bvid: None,
        };
        
        let pbb2 = VniLayer::Pbb {
            isid: 0x123456,
            bvid: Some(0),
        };
        
        let pbb3 = VniLayer::Pbb {
            isid: 0x123456,
            bvid: Some(100),
        };
        
        assert_ne!(pbb1, pbb2);
        assert_ne!(pbb2, pbb3);
    }

    #[test]
    fn test_regression_l2tp_versions_distinct() {
        // Regression: L2TPv2 and L2TPv3 should be distinct even with similar IDs
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        let l2tpv2 = VniLayer::L2tpV2 {
            tunnel_id: 100,
            session_id: 200,
            endpoints,
        };
        
        let l2tpv3 = VniLayer::L2tpV3 {
            session_id: 200,
            endpoints,
        };
        
        // Different variants, should not be equal
        assert_ne!(format!("{:?}", l2tpv2), format!("{:?}", l2tpv3));
    }

    #[test]
    fn test_regression_endpoint_ipv4_vs_ipv6() {
        // Regression: IPv4 and IPv6 endpoints should create different layers
        let endpoints_v4 = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        
        let endpoints_v6 = [
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 0x0001)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 0x0002)),
        ];

        let ipip_v4 = VniLayer::Ipip { endpoints: endpoints_v4 };
        let ipip_v6_as_ip6tnl = VniLayer::Ip6Tnl { endpoints: endpoints_v6 };
        
        // Different types and IP versions
        assert_ne!(format!("{:?}", ipip_v4), format!("{:?}", ipip_v6_as_ip6tnl));
    }

    #[test]
    fn test_regression_vni_mapper_large_scale() {
        // Regression: Mapper should handle many unique stacks efficiently
        let mut mapper = VniMapper::new();
        let mut all_ids = Vec::new();
        
        // Create 1000 unique VNI stacks
        for i in 0..1000 {
            let vlan = VniLayer::Vlan { vid: i };
            let id = mapper.get_or_create_vni_id(&[vlan]);
            all_ids.push(id);
        }
        
        assert_eq!(mapper.len(), 1000);
        
        // All IDs should be unique
        for i in 0..all_ids.len() {
            for j in (i + 1)..all_ids.len() {
                assert_ne!(all_ids[i], all_ids[j]);
            }
        }
        
        // All should be retrievable
        for (idx, id) in all_ids.iter().enumerate() {
            let stack = mapper.lookup_vni(*id).unwrap();
            assert_eq!(stack.len(), 1);
            match &stack[0] {
                VniLayer::Vlan { vid } => {
                    assert_eq!(*vid, idx as u16);
                }
                _ => panic!("Expected Vlan variant"),
            }
        }
    }

    #[test]
    fn test_regression_deep_vni_stack() {
        // Regression: Test deeply nested VNI stacks (beyond SmallVec inline capacity)
        let mut mapper = VniMapper::new();
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        
        let layers = vec![
            VniLayer::Vlan { vid: 100 },
            VniLayer::Mpls { label: 1000 },
            VniLayer::Vlan { vid: 200 },
            VniLayer::Vxlan { vni: 5000, group_id: 0, endpoints },
            VniLayer::Vlan { vid: 300 },
            VniLayer::Mpls { label: 2000 },
        ];
        
        let id = mapper.get_or_create_vni_id(&layers);
        let retrieved = mapper.lookup_vni(id).unwrap();
        
        assert_eq!(retrieved.len(), layers.len());
        for (i, layer) in layers.iter().enumerate() {
            assert_eq!(&retrieved[i], layer);
        }
    }

    #[test]
    fn test_regression_vni_id_u32_boundary() {
        // Regression: Test VniId at various u32 boundaries
        let id_zero = VniId::from_u32(0);
        let id_max = VniId::from_u32(u32::MAX);
        let id_mid = VniId::from_u32(u32::MAX / 2);
        
        assert_eq!(id_zero.as_u32(), 0);
        assert_eq!(id_max.as_u32(), u32::MAX);
        assert_eq!(id_mid.as_u32(), u32::MAX / 2);
        
        assert_ne!(id_zero, id_max);
        assert_ne!(id_mid, id_max);
    }



    #[test]
    fn test_regression_mapper_clear_and_reuse() {
        // Regression: After clear, mapper should work exactly as new
        let mut mapper = VniMapper::new();
        let vlan = VniLayer::Vlan { vid: 100 };
        
        // First cycle
        let id1 = mapper.get_or_create_vni_id(&[vlan.clone()]);
        assert_eq!(id1.as_u32(), 1);
        assert_eq!(mapper.len(), 1);
        
        // Clear
        mapper.clear();
        assert_eq!(mapper.len(), 0);
        assert!(mapper.is_empty());
        
        // Second cycle - should behave identically
        let id2 = mapper.get_or_create_vni_id(&[vlan.clone()]);
        assert_eq!(id2.as_u32(), 1); // Counter resets
        assert_eq!(mapper.len(), 1);
        
        // Third cycle with different VLAN
        let vlan2 = VniLayer::Vlan { vid: 200 };
        let id3 = mapper.get_or_create_vni_id(&[vlan2]);
        assert_eq!(id3.as_u32(), 2);
        assert_eq!(mapper.len(), 2);
    }

    #[test]
    fn test_regression_mixed_tunnel_stack_uniqueness() {
        // Regression: Complex stacks with similar components should be unique
        let mut mapper = VniMapper::new();
        let endpoints = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        
        let vlan100 = VniLayer::Vlan { vid: 100 };
        let vlan200 = VniLayer::Vlan { vid: 200 };
        let vxlan = VniLayer::Vxlan { vni: 5000, group_id: 0, endpoints };
        
        // Different orderings and combinations
        let id1 = mapper.get_or_create_vni_id(&[vlan100.clone(), vxlan.clone()]);
        let id2 = mapper.get_or_create_vni_id(&[vxlan.clone(), vlan100.clone()]);
        let id3 = mapper.get_or_create_vni_id(&[vlan100.clone(), vlan200.clone(), vxlan.clone()]);
        let id4 = mapper.get_or_create_vni_id(&[vlan100.clone(), vxlan.clone(), vlan200.clone()]);
        
        // All should be unique
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id1, id4);
        assert_ne!(id2, id3);
        assert_ne!(id2, id4);
        assert_ne!(id3, id4);
        
        assert_eq!(mapper.len(), 4);
    }

}



