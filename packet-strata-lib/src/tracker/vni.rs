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

/// IP address representation (IPv4 or IPv6)
///
/// Uses byte arrays for efficient storage and comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpAddr {
    /// IPv4 address (4 bytes, network byte order)
    V4([u8; 4]),
    /// IPv6 address (16 bytes, network byte order)
    V6([u8; 16]),
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(bytes) => {
                write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            }
            Self::V6(bytes) => {
                // Simple IPv6 formatting (could be improved with :: compression)
                write!(
                    f,
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                    bytes[8], bytes[9], bytes[10], bytes[11],
                    bytes[12], bytes[13], bytes[14], bytes[15]
                )
            }
        }
    }
}

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

impl VniLayer {
    /// Create a VLAN layer
    ///
    /// # Arguments
    ///
    /// * `vid` - VLAN ID (12-bit value, 0-4095)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let vlan = VniLayer::vlan(100);
    /// ```
    #[inline]
    pub const fn vlan(vid: u16) -> Self {
        Self::Vlan { vid }
    }

    /// Create an MPLS layer
    ///
    /// # Arguments
    ///
    /// * `label` - MPLS label (20-bit value)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mpls = VniLayer::mpls(12345);
    /// ```
    #[inline]
    pub const fn mpls(label: u32) -> Self {
        Self::Mpls { label }
    }

    /// Create a GRE or NVGRE layer
    ///
    /// Automatically determines whether this is NVGRE or standard GRE based on
    /// the protocol type (0x6558 = Transparent Ethernet Bridging).
    ///
    /// # Type Parameters
    ///
    /// * `V` - IP version (4 or 6)
    ///
    /// # Arguments
    ///
    /// * `protocol_type` - GRE protocol type field
    /// * `key` - Optional GRE key field
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ip_header = &[/* IPv4 header bytes */];
    /// let gre = VniLayer::gre::<4>(0x0800, Some(12345), ip_header)?;
    /// ```
    pub fn gre<const V: usize>(
        protocol_type: u16,
        key: Option<u32>,
        ip_header: &[u8],
    ) -> Result<Self, VniError> {
        const ETH_P_TEB: u16 = 0x6558; // Transparent Ethernet Bridging

        let [e1, e2] = get_endpoints::<V>(ip_header)?;

        if protocol_type == ETH_P_TEB {
            // NVGRE uses the key as VSID/FlowID
            Ok(Self::NvGre {
                protocol_type,
                vsid_flowid: key.unwrap_or(0),
                endpoints: [e1, e2],
            })
        } else {
            Ok(Self::Gre {
                protocol_type,
                key,
                endpoints: [e1, e2],
            })
        }
    }

    /// Create a VXLAN layer
    ///
    /// # Type Parameters
    ///
    /// * `V` - IP version (4 or 6)
    ///
    /// # Arguments
    ///
    /// * `group_id` - VXLAN Group Policy ID (0 if not using Group Policy extension)
    /// * `vni` - VXLAN Network Identifier (24-bit value)
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ip_header = &[/* IPv4 header bytes */];
    /// let vxlan = VniLayer::vxlan::<4>(0, 5000, ip_header)?;
    /// ```
    pub fn vxlan<const V: usize>(
        group_id: u16,
        vni: u32,
        ip_header: &[u8],
    ) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;

        Ok(Self::Vxlan {
            vni,
            group_id,
            endpoints: [e1, e2],
        })
    }

    /// Create a Geneve layer
    ///
    /// # Type Parameters
    ///
    /// * `V` - IP version (4 or 6)
    ///
    /// # Arguments
    ///
    /// * `protocol_type` - Geneve protocol type
    /// * `vni` - Virtual Network Identifier (24-bit value)
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ip_header = &[/* IPv4 header bytes */];
    /// let geneve = VniLayer::geneve::<4>(0x6558, 5000, ip_header)?;
    /// ```
    pub fn geneve<const V: usize>(
        protocol_type: u16,
        vni: u32,
        ip_header: &[u8],
    ) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;

        Ok(Self::Geneve {
            vni,
            protocol_type,
            endpoints: [e1, e2],
        })
    }

    /// Create an IPIP (IP-in-IP) layer - IPv4 encapsulated in IPv4 (RFC 2003)
    ///
    /// # Type Parameters
    ///
    /// * `V` - IP version of outer header (should be 4)
    ///
    /// # Arguments
    ///
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ip_header = &[/* IPv4 header bytes */];
    /// let ipip = VniLayer::ipip::<4>(ip_header)?;
    /// ```
    pub fn ipip<const V: usize>(ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::Ipip {
            endpoints: [e1, e2],
        })
    }

    /// Create an IPv4-in-IPv6 layer (RFC 2473)
    ///
    /// Used in DS-Lite (RFC 6333) and other 4in6 scenarios.
    pub fn ip4in6<const V: usize>(ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::Ip4in6 {
            endpoints: [e1, e2],
        })
    }

    /// Create a SIT (Simple Internet Transition) layer - IPv6-in-IPv4 (RFC 4213)
    ///
    /// Also known as 6in4 or configured tunnels.
    pub fn sit<const V: usize>(ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::Sit {
            endpoints: [e1, e2],
        })
    }

    /// Create an IPv6-in-IPv6 tunnel layer (RFC 2473)
    pub fn ip6tnl<const V: usize>(ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::Ip6Tnl {
            endpoints: [e1, e2],
        })
    }

    /// Create a GTP-U (User Plane) layer
    ///
    /// # Type Parameters
    ///
    /// * `V` - IP version (4 or 6)
    ///
    /// # Arguments
    ///
    /// * `teid` - Tunnel Endpoint Identifier (32-bit)
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ip_header = &[/* IPv4 header bytes */];
    /// let gtp = VniLayer::gtp_u::<4>(0x12345678, ip_header)?;
    /// ```
    pub fn gtp_u<const V: usize>(teid: u32, ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::GtpU {
            teid,
            endpoints: [e1, e2],
        })
    }

    /// Create a Teredo layer
    pub fn teredo<const V: usize>(ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::Teredo {
            endpoints: [e1, e2],
        })
    }

    /// Create an L2TPv2 layer
    ///
    /// # Arguments
    ///
    /// * `tunnel_id` - Tunnel ID (16-bit)
    /// * `session_id` - Session ID (16-bit)
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    pub fn l2tp_v2<const V: usize>(
        tunnel_id: u16,
        session_id: u16,
        ip_header: &[u8],
    ) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::L2tpV2 {
            tunnel_id,
            session_id,
            endpoints: [e1, e2],
        })
    }

    /// Create an L2TPv3 layer
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session ID (32-bit)
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    pub fn l2tp_v3<const V: usize>(session_id: u32, ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::L2tpV3 {
            session_id,
            endpoints: [e1, e2],
        })
    }

    /// Create a PBB (Provider Backbone Bridge) layer
    ///
    /// # Arguments
    ///
    /// * `isid` - I-SID (Service Instance Identifier, 24-bit)
    /// * `bvid` - Optional B-VID (Backbone VLAN ID, 12-bit)
    #[inline]
    pub const fn pbb(isid: u32, bvid: Option<u16>) -> Self {
        Self::Pbb { isid, bvid }
    }

    /// Create an STT (Stateless Transport Tunneling) layer
    ///
    /// # Arguments
    ///
    /// * `context_id` - Context ID (64-bit)
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    pub fn stt<const V: usize>(context_id: u64, ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::Stt {
            context_id,
            endpoints: [e1, e2],
        })
    }

    /// Create a PPTP layer
    ///
    /// # Arguments
    ///
    /// * `call_id` - Call ID (16-bit)
    /// * `ip_header` - Raw IP header bytes containing tunnel endpoints
    pub fn pptp<const V: usize>(call_id: u16, ip_header: &[u8]) -> Result<Self, VniError> {
        let [e1, e2] = get_endpoints::<V>(ip_header)?;
        Ok(Self::Pptp {
            call_id,
            endpoints: [e1, e2],
        })
    }

    /// Get the layer type name
    pub fn layer_name(&self) -> &'static str {
        match self {
            Self::Vlan { .. } => "vlan",
            Self::Mpls { .. } => "mpls",
            Self::Gre { .. } => "gre",
            Self::NvGre { .. } => "nvgre",
            Self::Vxlan { .. } => "vxlan",
            Self::Geneve { .. } => "geneve",
            Self::Ipip { .. } => "ipip",
            Self::Ip4in6 { .. } => "ip4in6",
            Self::Sit { .. } => "sit",
            Self::Ip6Tnl { .. } => "ip6tnl",
            Self::GtpU { .. } => "gtp-u",
            Self::Teredo { .. } => "teredo",
            Self::L2tpV2 { .. } => "l2tpv2",
            Self::L2tpV3 { .. } => "l2tpv3",
            Self::Pbb { .. } => "pbb",
            Self::Stt { .. } => "stt",
            Self::Pptp { .. } => "pptp",
        }
    }
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

/// Extracts and orders tunnel endpoints from IP header
///
/// Returns an array of [lower_ip, higher_ip] to ensure consistent ordering
/// for bidirectional flow identification.
///
/// # Type Parameters
///
/// * `V` - IP version (4 or 6)
///
/// # Arguments
///
/// * `ip_header` - Raw IP header bytes
///
/// # Returns
///
/// An array of two IP addresses in canonical order (lower first)
fn get_endpoints<const V: usize>(ip_header: &[u8]) -> Result<[IpAddr; 2], VniError> {
    match V {
        4 => {
            if ip_header.len() < 20 {
                return Err(VniError::InvalidHeaderLength);
            }
            let mut src_bytes = [0u8; 4];
            let mut dst_bytes = [0u8; 4];
            src_bytes.copy_from_slice(&ip_header[12..16]);
            dst_bytes.copy_from_slice(&ip_header[16..20]);

            let src = IpAddr::V4(src_bytes);
            let dst = IpAddr::V4(dst_bytes);

            Ok(if src < dst { [src, dst] } else { [dst, src] })
        }
        6 => {
            if ip_header.len() < 40 {
                return Err(VniError::InvalidHeaderLength);
            }
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&ip_header[8..24]);
            dst_bytes.copy_from_slice(&ip_header[24..40]);

            let src = IpAddr::V6(src_bytes);
            let dst = IpAddr::V6(dst_bytes);

            Ok(if src < dst { [src, dst] } else { [dst, src] })
        }
        _ => Err(VniError::InvalidIpVersion),
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
    use std::slice::from_ref;

    use super::*;

    #[test]
    fn test_vlan_creation() {
        let vlan = VniLayer::vlan(100);
        match vlan {
            VniLayer::Vlan { vid } => assert_eq!(vid, 100),
            _ => panic!("Expected VLAN variant"),
        }
    }

    #[test]
    fn test_mpls_creation() {
        let mpls = VniLayer::mpls(12345);
        match mpls {
            VniLayer::Mpls { label } => assert_eq!(label, 12345),
            _ => panic!("Expected MPLS variant"),
        }
    }

    #[test]
    fn test_mapper_basic() {
        let mut mapper = VniMapper::new();
        let vlan1 = VniLayer::vlan(100);
        let vlan2 = VniLayer::vlan(200);

        let id1 = mapper.get_or_create_vni_id(from_ref(&vlan1));
        let id2 = mapper.get_or_create_vni_id(from_ref(&vlan2));
        let id3 = mapper.get_or_create_vni_id(from_ref(&vlan1));

        assert_eq!(id1, id3); // Same VNI should get same ID
        assert_ne!(id1, id2); // Different VNIs should get different IDs

        assert_eq!(mapper.len(), 2);
    }

    #[test]
    fn test_mapper_lookup() {
        let mut mapper = VniMapper::new();
        let vlan = VniLayer::vlan(100);

        let id = mapper.get_or_create_vni_id(from_ref(&vlan));
        let lookup = mapper.lookup_vni(id);

        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap()[0], vlan);
    }

    #[test]
    fn test_layer_display() {
        let vlan = VniLayer::vlan(100);
        assert_eq!(format!("{}", vlan), "vlan(100)");

        let mpls = VniLayer::mpls(999);
        assert_eq!(format!("{}", mpls), "mpls(999)");
    }

    #[test]
    fn test_ip_addr_ordering() {
        let ip1 = IpAddr::V4([192, 168, 1, 1]);
        let ip2 = IpAddr::V4([192, 168, 1, 2]);

        assert!(ip1 < ip2);
    }

    #[test]
    fn test_vxlan_ipv4() {
        // Create a minimal IPv4 header
        let mut header = vec![0u8; 20];
        header[0] = 0x45; // Version 4, IHL 5
        header[12..16].copy_from_slice(&[192, 168, 1, 1]); // src
        header[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst

        let vxlan = VniLayer::vxlan::<4>(0, 5000, &header).unwrap();

        match vxlan {
            VniLayer::Vxlan {
                vni,
                group_id,
                endpoints,
            } => {
                assert_eq!(vni, 5000);
                assert_eq!(group_id, 0);
                assert_eq!(endpoints[0], IpAddr::V4([10, 0, 0, 1]));
                assert_eq!(endpoints[1], IpAddr::V4([192, 168, 1, 1]));
            }
            _ => panic!("Expected VXLAN variant"),
        }
    }

    #[test]
    fn test_endpoint_ordering() {
        let mut header1 = vec![0u8; 20];
        header1[0] = 0x45;
        header1[12..16].copy_from_slice(&[192, 168, 1, 1]); // src
        header1[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst

        let mut header2 = vec![0u8; 20];
        header2[0] = 0x45;
        header2[12..16].copy_from_slice(&[10, 0, 0, 1]); // src (swapped)
        header2[16..20].copy_from_slice(&[192, 168, 1, 1]); // dst (swapped)

        let vxlan1 = VniLayer::vxlan::<4>(0, 5000, &header1).unwrap();
        let vxlan2 = VniLayer::vxlan::<4>(0, 5000, &header2).unwrap();

        // Both should have endpoints in the same order
        assert_eq!(vxlan1, vxlan2);
    }

    #[test]
    fn test_ipip_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let ipip = VniLayer::ipip::<4>(&header).unwrap();
        match ipip {
            VniLayer::Ipip { ref endpoints } => {
                assert_eq!(endpoints[0], IpAddr::V4([10, 0, 0, 1]));
                assert_eq!(endpoints[1], IpAddr::V4([192, 168, 1, 1]));
            }
            _ => panic!("Expected Ipip variant"),
        }
        assert_eq!(ipip.layer_name(), "ipip");
    }

    #[test]
    fn test_sit_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let sit = VniLayer::sit::<4>(&header).unwrap();
        match sit {
            VniLayer::Sit { ref endpoints } => {
                assert_eq!(endpoints[0], IpAddr::V4([10, 0, 0, 1]));
                assert_eq!(endpoints[1], IpAddr::V4([192, 168, 1, 1]));
            }
            _ => panic!("Expected Sit variant"),
        }
        assert_eq!(sit.layer_name(), "sit");
    }

    #[test]
    fn test_gtp_u_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let gtp = VniLayer::gtp_u::<4>(0x12345678, &header).unwrap();
        match gtp {
            VniLayer::GtpU {
                teid,
                ref endpoints,
            } => {
                assert_eq!(teid, 0x12345678);
                assert_eq!(endpoints[0], IpAddr::V4([10, 0, 0, 1]));
            }
            _ => panic!("Expected GtpU variant"),
        }
        assert_eq!(gtp.layer_name(), "gtp-u");
        assert!(format!("{}", gtp).contains("gtp-u"));
        assert!(format!("{}", gtp).contains("teid:0x12345678"));
    }

    #[test]
    fn test_l2tp_v2_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let l2tp = VniLayer::l2tp_v2::<4>(100, 200, &header).unwrap();
        match l2tp {
            VniLayer::L2tpV2 {
                tunnel_id,
                session_id,
                ..
            } => {
                assert_eq!(tunnel_id, 100);
                assert_eq!(session_id, 200);
            }
            _ => panic!("Expected L2tpV2 variant"),
        }
        assert_eq!(l2tp.layer_name(), "l2tpv2");
        let display = format!("{}", l2tp);
        assert!(display.contains("l2tpv2"));
        assert!(display.contains("tid:100"));
        assert!(display.contains("sid:200"));
    }

    #[test]
    fn test_l2tp_v3_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let l2tp = VniLayer::l2tp_v3::<4>(0x12345678, &header).unwrap();
        match l2tp {
            VniLayer::L2tpV3 { session_id, .. } => {
                assert_eq!(session_id, 0x12345678);
            }
            _ => panic!("Expected L2tpV3 variant"),
        }
        assert_eq!(l2tp.layer_name(), "l2tpv3");
    }

    #[test]
    fn test_pbb_creation() {
        let pbb = VniLayer::pbb(0x123456, Some(100));
        match pbb {
            VniLayer::Pbb { isid, bvid } => {
                assert_eq!(isid, 0x123456);
                assert_eq!(bvid, Some(100));
            }
            _ => panic!("Expected Pbb variant"),
        }
        assert_eq!(pbb.layer_name(), "pbb");
        let display = format!("{}", pbb);
        assert!(display.contains("pbb"));
        assert!(display.contains("isid:1193046")); // 0x123456
        assert!(display.contains("bvid:100"));

        // Test without B-VID
        let pbb_no_bvid = VniLayer::pbb(5000, None);
        match pbb_no_bvid {
            VniLayer::Pbb { isid, bvid } => {
                assert_eq!(isid, 5000);
                assert_eq!(bvid, None);
            }
            _ => panic!("Expected Pbb variant"),
        }
        let display2 = format!("{}", pbb_no_bvid);
        assert!(!display2.contains("bvid"));
    }

    #[test]
    fn test_stt_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let stt = VniLayer::stt::<4>(0xDEADBEEFCAFEBABE, &header).unwrap();
        match stt {
            VniLayer::Stt { context_id, .. } => {
                assert_eq!(context_id, 0xDEADBEEFCAFEBABE);
            }
            _ => panic!("Expected Stt variant"),
        }
        assert_eq!(stt.layer_name(), "stt");
        let display = format!("{}", stt);
        assert!(display.contains("stt"));
        assert!(display.contains("ctx:0xdeadbeefcafebabe"));
    }

    #[test]
    fn test_pptp_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let pptp = VniLayer::pptp::<4>(12345, &header).unwrap();
        match pptp {
            VniLayer::Pptp { call_id, .. } => {
                assert_eq!(call_id, 12345);
            }
            _ => panic!("Expected Pptp variant"),
        }
        assert_eq!(pptp.layer_name(), "pptp");
        let display = format!("{}", pptp);
        assert!(display.contains("pptp"));
        assert!(display.contains("call:12345"));
    }

    #[test]
    fn test_teredo_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let teredo = VniLayer::teredo::<4>(&header).unwrap();
        match teredo {
            VniLayer::Teredo { ref endpoints } => {
                assert_eq!(endpoints[0], IpAddr::V4([10, 0, 0, 1]));
                assert_eq!(endpoints[1], IpAddr::V4([192, 168, 1, 1]));
            }
            _ => panic!("Expected Teredo variant"),
        }
        assert_eq!(teredo.layer_name(), "teredo");
    }

    #[test]
    fn test_geneve_creation() {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let geneve = VniLayer::geneve::<4>(0x6558, 100000, &header).unwrap();
        match geneve {
            VniLayer::Geneve {
                vni, protocol_type, ..
            } => {
                assert_eq!(vni, 100000);
                assert_eq!(protocol_type, 0x6558);
            }
            _ => panic!("Expected Geneve variant"),
        }
        assert_eq!(geneve.layer_name(), "geneve");
    }

    #[test]
    fn test_layer_names() {
        // Test all layer_name() return values
        assert_eq!(VniLayer::vlan(1).layer_name(), "vlan");
        assert_eq!(VniLayer::mpls(1).layer_name(), "mpls");
        assert_eq!(VniLayer::pbb(1, None).layer_name(), "pbb");

        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[12..16].copy_from_slice(&[1, 1, 1, 1]);
        header[16..20].copy_from_slice(&[2, 2, 2, 2]);

        assert_eq!(
            VniLayer::gre::<4>(0x0800, None, &header)
                .unwrap()
                .layer_name(),
            "gre"
        );
        assert_eq!(
            VniLayer::gre::<4>(0x6558, Some(1), &header)
                .unwrap()
                .layer_name(),
            "nvgre"
        );
        assert_eq!(
            VniLayer::vxlan::<4>(0, 1, &header).unwrap().layer_name(),
            "vxlan"
        );
        assert_eq!(
            VniLayer::geneve::<4>(0, 1, &header).unwrap().layer_name(),
            "geneve"
        );
        assert_eq!(VniLayer::ipip::<4>(&header).unwrap().layer_name(), "ipip");
        assert_eq!(
            VniLayer::ip4in6::<4>(&header).unwrap().layer_name(),
            "ip4in6"
        );
        assert_eq!(VniLayer::sit::<4>(&header).unwrap().layer_name(), "sit");
        assert_eq!(
            VniLayer::ip6tnl::<4>(&header).unwrap().layer_name(),
            "ip6tnl"
        );
        assert_eq!(
            VniLayer::gtp_u::<4>(1, &header).unwrap().layer_name(),
            "gtp-u"
        );
        assert_eq!(
            VniLayer::teredo::<4>(&header).unwrap().layer_name(),
            "teredo"
        );
        assert_eq!(
            VniLayer::l2tp_v2::<4>(1, 1, &header).unwrap().layer_name(),
            "l2tpv2"
        );
        assert_eq!(
            VniLayer::l2tp_v3::<4>(1, &header).unwrap().layer_name(),
            "l2tpv3"
        );
        assert_eq!(VniLayer::stt::<4>(1, &header).unwrap().layer_name(), "stt");
        assert_eq!(
            VniLayer::pptp::<4>(1, &header).unwrap().layer_name(),
            "pptp"
        );
    }
}
