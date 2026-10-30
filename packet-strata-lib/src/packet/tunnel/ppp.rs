//! PPP (Point-to-Point Protocol) header parser
//!
//! This module implements parsing for Point-to-Point Protocol (PPP) headers as defined
//! in RFC 1661 and PPP in HDLC-like Framing as defined in RFC 1662.
//!
//! PPP is commonly encapsulated inside:
//! - PPTP Enhanced GRE (`EtherProto::PPP` = `0x880B`, RFC 2637)
//! - Standard GRE / Geneve (`EtherProto::PPP` = `0x880B`)
//! - PPPoE Session Data (`EtherProto::PPP_SES` = `0x8864`, RFC 2516)
//! - L2TPv2 Data Messages (UDP port 1701, RFC 2661)
//!
//! # PPP Header Format (RFC 1661 / RFC 1662)
//!
//! ```text
//! +-------------------+-------------------+-------------------------------+
//! | Address (0xFF)    | Control (0x03)    | Protocol (8 or 16 bits)       |
//! |   (optional)      |   (optional)      |                               |
//! +-------------------+-------------------+-------------------------------+
//! ```
//!
//! - **Address and Control Field Compression (ACFC)**: The 2-byte `0xFF 0x03` HDLC-like
//!   framing header may be omitted (always omitted in PPPoE per RFC 2516, optional in PPTP/L2TP).
//! - **Protocol Field Compression (PFC)**: When the first byte of the PPP Protocol field has
//!   its least significant bit (LSB) set to `1`, the protocol field is compressed to 1 byte
//!   (equivalent to `0x00XX`). Otherwise, it is a 2-byte big-endian field.
//!
//! # Examples
//!
//! ```
//! use packet_strata::packet::tunnel::ppp::{PppHeader, PPP_PROTO_IPV4};
//! use packet_strata::packet::protocol::EtherProto;
//!
//! // PPP with HDLC-like framing (0xFF 0x03) + 2-byte IPv4 protocol (0x0021)
//! let buf = [0xFF, 0x03, 0x00, 0x21, 0x45, 0x00];
//! let (hdr, payload) = PppHeader::from_bytes(&buf).unwrap();
//! assert_eq!(hdr.protocol(), PPP_PROTO_IPV4);
//! assert!(hdr.has_hdlc_framing());
//! assert_eq!(hdr.header_len(), 4);
//! assert_eq!(hdr.inner_ether_proto(), Some(EtherProto::IPV4));
//! assert_eq!(payload, &[0x45, 0x00]);
//! ```

use std::fmt::{self, Formatter};

use crate::packet::protocol::EtherProto;
use crate::packet::PacketHeaderError;

/// HDLC All-Stations Address byte (`0xFF`) per RFC 1662
pub const PPP_HDLC_ADDRESS: u8 = 0xFF;

/// HDLC Unnumbered Information (UI) Control byte (`0x03`) per RFC 1662
pub const PPP_HDLC_CONTROL: u8 = 0x03;

// PPP Network Layer Protocol numbers (RFC 1661 / IANA PPP DLL Protocol Numbers)
/// Padding Protocol
pub const PPP_PROTO_PADDING: u16 = 0x0001;
/// IPv4 (Internet Protocol version 4)
pub const PPP_PROTO_IPV4: u16 = 0x0021;
/// OSI Network Layer
pub const PPP_PROTO_OSI: u16 = 0x0023;
/// Novell IPX
pub const PPP_PROTO_IPX: u16 = 0x002B;
/// Van Jacobson Compressed TCP/IP
pub const PPP_PROTO_VJ_COMP: u16 = 0x002D;
/// Van Jacobson Uncompressed TCP/IP
pub const PPP_PROTO_VJ_UNCOMP: u16 = 0x002F;
/// Bridging PDU (Ethernet over PPP, RFC 3518)
pub const PPP_PROTO_BPDU: u16 = 0x0031;
/// Multilink PPP (RFC 1990)
pub const PPP_PROTO_MP: u16 = 0x003D;
/// IPv6 (Internet Protocol version 6, RFC 5072)
pub const PPP_PROTO_IPV6: u16 = 0x0057;
/// PPP Multiplexing (RFC 3153)
pub const PPP_PROTO_MUX: u16 = 0x0059;
/// Compressed datagram (CCP data, RFC 1962)
pub const PPP_PROTO_COMP: u16 = 0x00FD;
/// MPLS Unicast (RFC 3032)
pub const PPP_PROTO_MPLS_UC: u16 = 0x0281;
/// MPLS Multicast (RFC 3032)
pub const PPP_PROTO_MPLS_MC: u16 = 0x0283;

// PPP Network Control Protocols (NCPs: 0x8000..=0xBFFF)
/// IP Control Protocol (IPCP, RFC 1332)
pub const PPP_PROTO_IPCP: u16 = 0x8021;
/// Encryption Control Protocol (ECP, RFC 1968)
pub const PPP_PROTO_ECP: u16 = 0x8053;
/// IPv6 Control Protocol (IPv6CP, RFC 5072)
pub const PPP_PROTO_IPV6CP: u16 = 0x8057;
/// Compression Control Protocol (CCP, RFC 1962)
pub const PPP_PROTO_CCP: u16 = 0x80FD;
/// MPLS Control Protocol (MPLSCP, RFC 3032)
pub const PPP_PROTO_MPLSCP: u16 = 0x8281;

// PPP Link Control & Authentication Protocols (0xC000..=0xFFFF)
/// Link Control Protocol (LCP, RFC 1661)
pub const PPP_PROTO_LCP: u16 = 0xC021;
/// Password Authentication Protocol (PAP, RFC 1334)
pub const PPP_PROTO_PAP: u16 = 0xC023;
/// Link Quality Report (LQR, RFC 1989)
pub const PPP_PROTO_LQR: u16 = 0xC025;
/// Challenge Handshake Authentication Protocol (CHAP, RFC 1994)
pub const PPP_PROTO_CHAP: u16 = 0xC223;
/// Extensible Authentication Protocol (EAP, RFC 2284)
pub const PPP_PROTO_EAP: u16 = 0xC227;

/// Parsed Point-to-Point Protocol (PPP) header (1 to 4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PppHeader {
    protocol: u16,
    header_len: u8,
    hdlc_framing: bool,
    compressed_proto: bool,
}

impl PppHeader {
    /// Parse a PPP header from a byte slice.
    ///
    /// Automatically handles optional HDLC-like framing (`0xFF 0x03`) and
    /// 1-byte (PFC) or 2-byte PPP Protocol fields.
    #[inline]
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), PacketHeaderError> {
        if buf.is_empty() {
            return Err(PacketHeaderError::TooShort("PppHeader"));
        }

        let (hdlc_framing, after_hdlc) =
            if buf.len() >= 2 && buf[0] == PPP_HDLC_ADDRESS && buf[1] == PPP_HDLC_CONTROL {
                (true, &buf[2..])
            } else {
                (false, buf)
            };

        if after_hdlc.is_empty() {
            return Err(PacketHeaderError::TooShort("PppHeader"));
        }

        // Per RFC 1661 Section 2:
        // If LSB of the first protocol octet is 1, the Protocol field is compressed (1 byte).
        // Otherwise, it is 2 bytes (big-endian), and the LSB of the second octet MUST be 1.
        let (protocol, compressed_proto, rest) = if (after_hdlc[0] & 0x01) != 0 {
            (after_hdlc[0] as u16, true, &after_hdlc[1..])
        } else if after_hdlc.len() >= 2 {
            let proto = u16::from_be_bytes([after_hdlc[0], after_hdlc[1]]);
            if (proto & 0x0001) == 0 {
                return Err(PacketHeaderError::Invalid("PppHeader"));
            }
            (proto, false, &after_hdlc[2..])
        } else {
            return Err(PacketHeaderError::TooShort("PppHeader"));
        };

        let header_len = (if hdlc_framing { 2 } else { 0 }) + (if compressed_proto { 1 } else { 2 });

        Ok((
            Self {
                protocol,
                header_len,
                hdlc_framing,
                compressed_proto,
            },
            rest,
        ))
    }

    /// Alias for [`PppHeader::parse`] for consistency with [`HeaderParser`](crate::packet::HeaderParser)
    #[inline]
    pub fn from_bytes(buf: &[u8]) -> Result<(Self, &[u8]), PacketHeaderError> {
        Self::parse(buf)
    }

    /// Returns the 16-bit PPP protocol number (e.g., `0x0021` for IPv4, `0x0057` for IPv6)
    #[inline]
    pub fn protocol(&self) -> u16 {
        self.protocol
    }

    /// Returns the human-readable name of the encapsulated PPP protocol
    #[inline]
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            PPP_PROTO_PADDING => "Padding",
            PPP_PROTO_IPV4 => "IPv4",
            PPP_PROTO_OSI => "OSI",
            PPP_PROTO_IPX => "IPX",
            PPP_PROTO_VJ_COMP => "VJ-Comp",
            PPP_PROTO_VJ_UNCOMP => "VJ-Uncomp",
            PPP_PROTO_BPDU => "BPDU",
            PPP_PROTO_MP => "Multilink",
            PPP_PROTO_IPV6 => "IPv6",
            PPP_PROTO_MUX => "PPP-Mux",
            PPP_PROTO_COMP => "Compressed",
            PPP_PROTO_MPLS_UC => "MPLS-UC",
            PPP_PROTO_MPLS_MC => "MPLS-MC",
            PPP_PROTO_IPCP => "IPCP",
            PPP_PROTO_ECP => "ECP",
            PPP_PROTO_IPV6CP => "IPv6CP",
            PPP_PROTO_CCP => "CCP",
            PPP_PROTO_MPLSCP => "MPLSCP",
            PPP_PROTO_LCP => "LCP",
            PPP_PROTO_PAP => "PAP",
            PPP_PROTO_LQR => "LQR",
            PPP_PROTO_CHAP => "CHAP",
            PPP_PROTO_EAP => "EAP",
            _ => "Unknown",
        }
    }

    /// Returns the total length of the PPP header in bytes (1 to 4 bytes)
    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len as usize
    }

    /// Returns `true` if the `0xFF 0x03` HDLC-like Address/Control bytes were present
    #[inline]
    pub fn has_hdlc_framing(&self) -> bool {
        self.hdlc_framing
    }

    /// Returns `true` if Protocol-Field-Compression (1-byte protocol field) was used
    #[inline]
    pub fn is_protocol_compressed(&self) -> bool {
        self.compressed_proto
    }

    /// Returns `true` if the protocol is a network-layer data protocol (`0x0001..=0x3FFF`)
    #[inline]
    pub fn is_network_data(&self) -> bool {
        (0x0001..=0x3FFF).contains(&self.protocol)
    }

    /// Returns `true` if the protocol is a Network Control Protocol (`0x8001..=0xBFFF`)
    #[inline]
    pub fn is_ncp(&self) -> bool {
        (0x8001..=0xBFFF).contains(&self.protocol)
    }

    /// Returns `true` if the protocol is a Link Control or Authentication Protocol (`0xC001..=0xFFFF`)
    #[inline]
    pub fn is_lcp_or_auth(&self) -> bool {
        self.protocol >= 0xC001
    }

    /// Maps the PPP protocol number to an equivalent [`EtherProto`] for inner layer parsing,
    /// or `None` if it is a control protocol (LCP, IPCP, CHAP, PAP, etc.) or unsupported.
    #[inline]
    pub fn inner_ether_proto(&self) -> Option<EtherProto> {
        match self.protocol {
            PPP_PROTO_IPV4 => Some(EtherProto::IPV4),
            PPP_PROTO_IPV6 => Some(EtherProto::IPV6),
            PPP_PROTO_MPLS_UC => Some(EtherProto::MPLS_UC),
            PPP_PROTO_MPLS_MC => Some(EtherProto::MPLS_MC),
            PPP_PROTO_IPX => Some(EtherProto::IPX),
            PPP_PROTO_BPDU => Some(EtherProto::TEB),
            _ => None,
        }
    }
}

impl fmt::Display for PppHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PPP proto=0x{:04x} ({}){}{}",
            self.protocol,
            self.protocol_name(),
            if self.hdlc_framing { " [HDLC]" } else { "" },
            if self.compressed_proto { " [PFC]" } else { "" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ppp_hdlc_ipv4() {
        let data = [0xFF, 0x03, 0x00, 0x21, 0x45, 0x00];
        let (hdr, rest) = PppHeader::from_bytes(&data).unwrap();
        assert_eq!(hdr.protocol(), PPP_PROTO_IPV4);
        assert_eq!(hdr.protocol_name(), "IPv4");
        assert!(hdr.has_hdlc_framing());
        assert!(!hdr.is_protocol_compressed());
        assert_eq!(hdr.header_len(), 4);
        assert!(hdr.is_network_data());
        assert_eq!(hdr.inner_ether_proto(), Some(EtherProto::IPV4));
        assert_eq!(rest, &[0x45, 0x00]);
        assert_eq!(format!("{}", hdr), "PPP proto=0x0021 (IPv4) [HDLC]");
    }

    #[test]
    fn test_ppp_acfc_ipv6() {
        // No 0xFF 0x03 (e.g. inside PPPoE)
        let data = [0x00, 0x57, 0x60, 0x00];
        let (hdr, rest) = PppHeader::from_bytes(&data).unwrap();
        assert_eq!(hdr.protocol(), PPP_PROTO_IPV6);
        assert_eq!(hdr.protocol_name(), "IPv6");
        assert!(!hdr.has_hdlc_framing());
        assert!(!hdr.is_protocol_compressed());
        assert_eq!(hdr.header_len(), 2);
        assert_eq!(hdr.inner_ether_proto(), Some(EtherProto::IPV6));
        assert_eq!(rest, &[0x60, 0x00]);
        assert_eq!(format!("{}", hdr), "PPP proto=0x0057 (IPv6)");
    }

    #[test]
    fn test_ppp_pfc_compressed() {
        // ACFC + PFC (1 byte total)
        let data = [0x21, 0x45, 0x00];
        let (hdr, rest) = PppHeader::from_bytes(&data).unwrap();
        assert_eq!(hdr.protocol(), PPP_PROTO_IPV4);
        assert!(!hdr.has_hdlc_framing());
        assert!(hdr.is_protocol_compressed());
        assert_eq!(hdr.header_len(), 1);
        assert_eq!(hdr.inner_ether_proto(), Some(EtherProto::IPV4));
        assert_eq!(rest, &[0x45, 0x00]);
        assert_eq!(format!("{}", hdr), "PPP proto=0x0021 (IPv4) [PFC]");

        // HDLC + PFC (3 bytes total)
        let data_hdlc = [0xFF, 0x03, 0x21, 0x45, 0x00];
        let (hdr2, rest2) = PppHeader::from_bytes(&data_hdlc).unwrap();
        assert_eq!(hdr2.protocol(), PPP_PROTO_IPV4);
        assert!(hdr2.has_hdlc_framing());
        assert!(hdr2.is_protocol_compressed());
        assert_eq!(hdr2.header_len(), 3);
        assert_eq!(rest2, &[0x45, 0x00]);
    }

    #[test]
    fn test_ppp_control_protocols() {
        // LCP
        let lcp = [0xFF, 0x03, 0xC0, 0x21, 0x01, 0x02];
        let (hdr, rest) = PppHeader::from_bytes(&lcp).unwrap();
        assert_eq!(hdr.protocol(), PPP_PROTO_LCP);
        assert_eq!(hdr.protocol_name(), "LCP");
        assert!(hdr.is_lcp_or_auth());
        assert!(!hdr.is_network_data());
        assert_eq!(hdr.inner_ether_proto(), None);
        assert_eq!(rest, &[0x01, 0x02]);

        // IPCP
        let ipcp = [0x80, 0x21, 0x01, 0x01];
        let (hdr_ipcp, _) = PppHeader::from_bytes(&ipcp).unwrap();
        assert_eq!(hdr_ipcp.protocol(), PPP_PROTO_IPCP);
        assert!(hdr_ipcp.is_ncp());
        assert_eq!(hdr_ipcp.inner_ether_proto(), None);
    }

    #[test]
    fn test_ppp_errors() {
        assert!(PppHeader::from_bytes(&[]).is_err());
        assert!(PppHeader::from_bytes(&[0xFF, 0x03]).is_err());
        assert!(PppHeader::from_bytes(&[0x00]).is_err());
        // Invalid protocol with LSB of second octet == 0
        assert!(PppHeader::from_bytes(&[0x00, 0x20]).is_err());
    }
}
