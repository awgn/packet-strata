//! Tunnel detection and protocol identification utilities.
//!
//! This module provides shared logic for detecting tunnel protocols and determining
//! the next layer to parse. Used by both `Packet` and `PacketIter`.

use super::ipv6::Ipv6HeaderExt;
use super::iter::LinkType;
use super::protocol::{EtherProto, IpProto};
use super::tunnel::{
    geneve::GENEVE_PORT,
    gtpv1::{GTPV1_C_PORT, GTPV1_U_PORT},
    l2tp::L2TP_PORT,
    stt::STT_PORT,
    teredo::TEREDO_PORT,
    vxlan::VXLAN_PORT,
};

/// Internal state machine for determining the next layer to parse
#[derive(Debug, Clone, Copy)]
pub(crate) enum NextLayer {
    /// Parse link layer based on LinkType
    Link(LinkType),
    /// Parse network layer based on EtherProto
    Network(EtherProto),
    /// Parse transport layer based on IpProto
    Transport(IpProto),
    /// Parse tunnel based on tunnel type detected from UDP ports or GRE
    Tunnel(TunnelType),
    /// Parsing complete, no more headers
    Done,
}

/// Types of tunnels that can be detected
#[derive(Debug, Clone, Copy)]
pub(crate) enum TunnelType {
    /// VXLAN tunnel (detected from UDP dst port 4789)
    Vxlan,
    /// Geneve tunnel (detected from UDP dst port 6081)
    Geneve,
    /// GRE tunnel (detected from IP protocol 47)
    Gre,
    /// MPLS tunnel (detected from EtherType or UDP port 6635)
    Mpls,
    /// Teredo tunnel (detected from UDP port 3544)
    Teredo,
    /// GTPv1 tunnel (detected from UDP ports 2123/2152)
    Gtpv1,
    /// GTPv2 tunnel (detected from UDP port 2123 + version check)
    Gtpv2,
    /// L2TPv2 tunnel (detected from UDP port 1701)
    L2tpv2,
    /// L2TPv3 tunnel (detected from IP protocol 115)
    L2tpv3,
    /// NVGRE tunnel (detected from GRE with TEB protocol and key)
    Nvgre,
    /// PBB tunnel (detected from EtherType 0x88E7 I-Tag or 0x88A8 B-Tag)
    Pbb,
    /// STT tunnel (detected from TCP port 7471)
    Stt,
    /// PPTP tunnel (detected from GRE version 1)
    Pptp,
}

/// Detect tunnel type from UDP ports
///
/// Checks destination port first (most common case), then source port
/// for bidirectional protocols like Teredo and L2TP.
#[inline]
pub(crate) fn detect_udp_tunnel(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<TunnelType> {
    // Check destination port first (most common case)
    match dst_port {
        VXLAN_PORT => return Some(TunnelType::Vxlan),
        GENEVE_PORT => return Some(TunnelType::Geneve),
        TEREDO_PORT => return Some(TunnelType::Teredo),
        6635 => return Some(TunnelType::Mpls), // MPLS over UDP
        L2TP_PORT => return Some(TunnelType::L2tpv2), // L2TPv2 over UDP
        GTPV1_U_PORT => {
            // GTPv1-U user plane
            if let Some(gtp_type) = detect_gtp_version(payload) {
                return Some(gtp_type);
            }
        }
        GTPV1_C_PORT => {
            // GTP control plane (port 2123 shared by GTPv1-C and GTPv2-C)
            // Need to check version byte to distinguish
            if let Some(gtp_type) = detect_gtp_version(payload) {
                return Some(gtp_type);
            }
        }
        3386 => {
            // GTP' (GTP Prime)
            if let Some(gtp_type) = detect_gtp_version(payload) {
                return Some(gtp_type);
            }
        }
        _ => {}
    }

    // Check source port for Teredo (can be either direction)
    if src_port == TEREDO_PORT {
        return Some(TunnelType::Teredo);
    }

    // Check source port for L2TP (can be either direction)
    if src_port == L2TP_PORT {
        return Some(TunnelType::L2tpv2);
    }

    None
}

/// Detect GTP version from first byte of payload
#[inline]
pub(crate) fn detect_gtp_version(payload: &[u8]) -> Option<TunnelType> {
    if payload.is_empty() {
        return None;
    }

    let version_byte = payload[0];
    match version_byte & 0xF0 {
        0x10 | 0x20 => Some(TunnelType::Gtpv1), // GTP' (versions 0, 1)
        0x30 => Some(TunnelType::Gtpv1),        // GTPv1
        0x40 => Some(TunnelType::Gtpv2),        // GTPv2
        _ => None,
    }
}

/// Detect GRE variant from the first bytes of the GRE header
///
/// Distinguishes between:
/// - PPTP: GRE version 1 (Enhanced GRE per RFC 2637)
/// - NVGRE: GRE version 0 with Key flag and TEB (0x6558) protocol
/// - Standard GRE: GRE version 0
#[inline]
pub(crate) fn detect_gre_variant(payload: &[u8]) -> TunnelType {
    if payload.len() < 4 {
        return TunnelType::Gre;
    }

    let flags_version = u16::from_be_bytes([payload[0], payload[1]]);
    let version = flags_version & 0x0007;
    let has_key = (flags_version & 0x2000) != 0;
    let protocol_type = u16::from_be_bytes([payload[2], payload[3]]);

    // Version 1 = Enhanced GRE (PPTP)
    if version == 1 {
        return TunnelType::Pptp;
    }

    // Version 0 with Key flag and TEB protocol = NVGRE
    if version == 0 && has_key && protocol_type == 0x6558 {
        return TunnelType::Nvgre;
    }

    // Default to standard GRE
    TunnelType::Gre
}

/// Detect next protocol after MPLS based on first nibble
///
/// Returns the appropriate NextLayer based on the version nibble:
/// - 0: Ethernet after MPLS
/// - 4: IPv4
/// - 6: IPv6
#[inline]
pub(crate) fn detect_mpls_inner_protocol(payload: &[u8]) -> Option<NextLayer> {
    if payload.is_empty() {
        return None;
    }

    let version_nibble = (payload[0] & 0xF0) >> 4;
    match version_nibble {
        0 => Some(NextLayer::Link(LinkType::Ethernet)), // Ethernet after MPLS
        4 => Some(NextLayer::Network(EtherProto::IPV4)),
        6 => Some(NextLayer::Network(EtherProto::IPV6)),
        _ => None,
    }
}

/// Find the upper layer protocol for an IPv6 packet by parsing extension headers
///
/// Walks through the extension header chain and returns the final next_header
/// value which indicates the transport protocol.
#[inline]
pub(crate) fn find_ipv6_upper_protocol(ipv6: &Ipv6HeaderExt<'_>) -> IpProto {
    // If there are no extension headers, the next_header is the transport protocol
    if ipv6.raw_extensions.is_empty() {
        return ipv6.next_header();
    }

    // Walk through extension headers to find the last next_header value
    let mut remaining = ipv6.raw_extensions;
    let mut next_header = ipv6.next_header();

    while !remaining.is_empty() {
        // Extension headers have next_header at offset 0 and length at offset 1
        // Length is in 8-byte units, not including the first 8 bytes
        if remaining.len() < 2 {
            break;
        }

        next_header = IpProto(remaining[0]);
        let ext_len = match next_header {
            // Fragment header is fixed 8 bytes (no length field used)
            IpProto::IPV6_FRAG => 8,
            // Other extension headers: (hdr_ext_len + 1) * 8
            _ => ((remaining[1] as usize) + 1) * 8,
        };

        if remaining.len() < ext_len {
            break;
        }

        remaining = &remaining[ext_len..];
    }

    next_header
}

/// Check if a TCP port indicates an STT tunnel
#[inline]
pub(crate) fn is_stt_port(port: u16) -> bool {
    port == STT_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_udp_tunnel_vxlan() {
        assert!(matches!(
            detect_udp_tunnel(12345, VXLAN_PORT, &[]),
            Some(TunnelType::Vxlan)
        ));
    }

    #[test]
    fn test_detect_udp_tunnel_geneve() {
        assert!(matches!(
            detect_udp_tunnel(12345, GENEVE_PORT, &[]),
            Some(TunnelType::Geneve)
        ));
    }

    #[test]
    fn test_detect_udp_tunnel_teredo_dst() {
        assert!(matches!(
            detect_udp_tunnel(12345, TEREDO_PORT, &[]),
            Some(TunnelType::Teredo)
        ));
    }

    #[test]
    fn test_detect_udp_tunnel_teredo_src() {
        assert!(matches!(
            detect_udp_tunnel(TEREDO_PORT, 12345, &[]),
            Some(TunnelType::Teredo)
        ));
    }

    #[test]
    fn test_detect_udp_tunnel_l2tp() {
        assert!(matches!(
            detect_udp_tunnel(12345, L2TP_PORT, &[]),
            Some(TunnelType::L2tpv2)
        ));
    }

    #[test]
    fn test_detect_udp_tunnel_none() {
        assert!(detect_udp_tunnel(12345, 80, &[]).is_none());
    }

    #[test]
    fn test_detect_gtp_version_v1() {
        // GTPv1 version byte: 0x30
        assert!(matches!(
            detect_gtp_version(&[0x30]),
            Some(TunnelType::Gtpv1)
        ));
    }

    #[test]
    fn test_detect_gtp_version_v2() {
        // GTPv2 version byte: 0x40
        assert!(matches!(
            detect_gtp_version(&[0x40]),
            Some(TunnelType::Gtpv2)
        ));
    }

    #[test]
    fn test_detect_gtp_version_empty() {
        assert!(detect_gtp_version(&[]).is_none());
    }

    #[test]
    fn test_detect_gre_standard() {
        // Standard GRE: version 0, no special flags
        let gre = [0x00, 0x00, 0x08, 0x00]; // IPv4 inner
        assert!(matches!(detect_gre_variant(&gre), TunnelType::Gre));
    }

    #[test]
    fn test_detect_gre_pptp() {
        // PPTP: GRE version 1
        let gre = [0x00, 0x01, 0x88, 0x0B]; // version 1
        assert!(matches!(detect_gre_variant(&gre), TunnelType::Pptp));
    }

    #[test]
    fn test_detect_gre_nvgre() {
        // NVGRE: version 0, key flag set, TEB protocol
        let gre = [0x20, 0x00, 0x65, 0x58]; // Key flag + TEB
        assert!(matches!(detect_gre_variant(&gre), TunnelType::Nvgre));
    }

    #[test]
    fn test_detect_gre_too_short() {
        assert!(matches!(detect_gre_variant(&[0x00]), TunnelType::Gre));
    }

    #[test]
    fn test_detect_mpls_inner_ipv4() {
        // First nibble 4 = IPv4
        let payload = [0x45, 0x00, 0x00, 0x28];
        assert!(matches!(
            detect_mpls_inner_protocol(&payload),
            Some(NextLayer::Network(EtherProto::IPV4))
        ));
    }

    #[test]
    fn test_detect_mpls_inner_ipv6() {
        // First nibble 6 = IPv6
        let payload = [0x60, 0x00, 0x00, 0x00];
        assert!(matches!(
            detect_mpls_inner_protocol(&payload),
            Some(NextLayer::Network(EtherProto::IPV6))
        ));
    }

    #[test]
    fn test_detect_mpls_inner_ethernet() {
        // First nibble 0 = Ethernet
        let payload = [0x00, 0x11, 0x22, 0x33];
        assert!(matches!(
            detect_mpls_inner_protocol(&payload),
            Some(NextLayer::Link(LinkType::Ethernet))
        ));
    }

    #[test]
    fn test_detect_mpls_inner_empty() {
        assert!(detect_mpls_inner_protocol(&[]).is_none());
    }

    #[test]
    fn test_is_stt_port() {
        assert!(is_stt_port(STT_PORT));
        assert!(!is_stt_port(80));
    }
}
