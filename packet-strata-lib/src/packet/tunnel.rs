//! Network tunnel protocol parsers
//!
//! This module provides parsers for various network tunneling and encapsulation protocols.
//! Each parser implements the [`HeaderParser`](crate::packet::HeaderParser) trait for
//! zero-copy parsing of packet headers.
//!
//! # Supported Protocols
//!
//! ## Virtualization and Overlay Networks
//!
//! | Protocol | Module | Description |
//! |----------|--------|-------------|
//! | [VXLAN](vxlan) | `vxlan` | Virtual Extensible LAN (RFC 7348) - UDP port 4789 |
//! | [Geneve](geneve) | `geneve` | Generic Network Virtualization Encapsulation (RFC 8926) - UDP port 6081 |
//! | [NVGRE](nvgre) | `nvgre` | Network Virtualization using GRE (RFC 7637) |
//! | [STT](stt) | `stt` | Stateless Transport Tunneling (VMware) - TCP port 7471 |
//!
//! ## Generic Encapsulation
//!
//! | Protocol | Module | Description |
//! |----------|--------|-------------|
//! | [GRE](gre) | `gre` | Generic Routing Encapsulation (RFC 2784, RFC 2890) - IP protocol 47 |
//! | [MPLS](mpls) | `mpls` | Multiprotocol Label Switching (RFC 3032) - EtherType 0x8847/0x8848 |
//! | [PBB](pbb) | `pbb` | Provider Backbone Bridge / MAC-in-MAC (IEEE 802.1ah) - EtherType 0x88E7/0x88A8 |
//!
//! ## Mobile and Carrier Tunnels
//!
//! | Protocol | Module | Description |
//! |----------|--------|-------------|
//! | [GTPv1-U](gtpv1) | `gtpv1` | GPRS Tunneling Protocol v1 User Plane (3GPP TS 29.060) - UDP port 2152 |
//! | [GTPv1-C](gtpv1) | `gtpv1` | GPRS Tunneling Protocol v1 Control Plane (3GPP TS 29.060) - UDP port 2123 |
//! | [GTPv2-C](gtpv2) | `gtpv2` | GPRS Tunneling Protocol v2 Control Plane (3GPP TS 29.274) - UDP port 2123 |
//!
//! ## VPN and Access Tunnels
//!
//! | Protocol | Module | Description |
//! |----------|--------|-------------|
//! | [L2TPv2](l2tp) | `l2tp` | Layer 2 Tunneling Protocol v2 (RFC 2661) - UDP port 1701 |
//! | [L2TPv3](l2tp) | `l2tp` | Layer 2 Tunneling Protocol v3 (RFC 3931) - IP protocol 115 |
//! | [PPTP](pptp) | `pptp` | Point-to-Point Tunneling Protocol (RFC 2637) - Enhanced GRE version 1 |
//! | [Teredo](teredo) | `teredo` | IPv6 over UDP/IPv4 tunneling (RFC 4380) - UDP port 3544 |
//!
//! ## IP-in-IP Tunnels
//!
//! | Protocol | Module | Description |
//! |----------|--------|-------------|
//! | [IPIP](ipip) | `ipip` | IPv4-in-IPv4 (RFC 2003) - IP protocol 4 |
//! | [SIT/6in4](ipip) | `ipip` | IPv6-in-IPv4 (RFC 4213) - IP protocol 41 |
//! | [IP4in6](ipip) | `ipip` | IPv4-in-IPv6 (RFC 2473) - IPv6 next header 4 |
//! | [IP6Tnl](ipip) | `ipip` | IPv6-in-IPv6 (RFC 2473) - IPv6 next header 41 |
//!
//! # Usage Example
//!
//! All tunnel parsers follow the same pattern using the `HeaderParser` trait:
//!
//! ```
//! use packet_strata::packet::tunnel::vxlan::VxlanHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! let packet = vec![
//!     0x08, 0x00, 0x00, 0x00,  // VXLAN Flags (I=1)
//!     0x00, 0x00, 0x64, 0x00,  // VNI = 100
//!     // Inner Ethernet frame would follow...
//! ];
//!
//! let (header, payload) = VxlanHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.vni(), 100);
//! ```
//!
//! # Tunnel Detection
//!
//! Tunnel protocols are detected by the [`PacketIter`](crate::packet::iter::PacketIter)
//! based on the following criteria:
//!
//! ## By UDP/TCP Port
//!
//! | Port | Protocol |
//! |------|----------|
//! | UDP 4789 | VXLAN |
//! | UDP 6081 | Geneve |
//! | UDP 2152 | GTPv1-U |
//! | UDP 2123 | GTPv1-C / GTPv2-C |
//! | UDP 1701 | L2TPv2 |
//! | UDP 3544 | Teredo |
//! | TCP 7471 | STT |
//!
//! ## By IP Protocol Number
//!
//! | Protocol | Tunnel Type |
//! |----------|-------------|
//! | 4 (IP-ENCAP) | IPIP (IPv4-in-IPv4) or IP4in6 (IPv4-in-IPv6) |
//! | 41 (IPv6) | SIT (IPv6-in-IPv4) or IP6Tnl (IPv6-in-IPv6) |
//! | 47 (GRE) | GRE, NVGRE, or PPTP (based on GRE header flags) |
//! | 115 (L2TP) | L2TPv3 |
//!
//! ## By EtherType
//!
//! | EtherType | Protocol |
//! |-----------|----------|
//! | 0x8847/0x8848 | MPLS |
//! | 0x88E7/0x88A8 | PBB |

pub mod geneve;
pub mod gre;
pub mod gtpv1;
pub mod gtpv2;
pub mod ipip;
pub mod l2tp;
pub mod mpls;
pub mod nvgre;
pub mod pbb;
pub mod pptp;
pub mod stt;
pub mod teredo;
pub mod vxlan;
