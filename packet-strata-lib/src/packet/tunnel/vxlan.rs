//! VXLAN (Virtual Extensible LAN) protocol parser
//!
//! This module implements parsing for VXLAN tunnels as defined in RFC 7348.
//! VXLAN allows Layer 2 Ethernet frames to be encapsulated in UDP datagrams
//! for transport across Layer 3 networks.
//!
//! # VXLAN Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |R|R|R|R|I|R|R|R|            Reserved                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                VXLAN Network Identifier (VNI) |   Reserved    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - UDP destination port: 4789 (IANA assigned)
//! - VNI (VXLAN Network Identifier): 24 bits, supports up to 16 million virtual networks
//! - I flag (bit 4): MUST be 1 to indicate valid VNI
//! - Encapsulates complete Ethernet frames
//!
//! # Examples
//!
//! ## Basic VXLAN parsing
//!
//! ```
//! use packet_strata::packet::tunnel::vxlan::VxlanHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::{HeaderParser, PacketHeader};
//!
//! // VXLAN packet with VNI = 100
//! let packet = vec![
//!     0x08, 0x00, 0x00, 0x00,  // Flags (I=1) + Reserved
//!     0x00, 0x00, 0x64, 0x00,  // VNI = 100, Reserved
//!     // ... Ethernet frame follows ...
//! ];
//!
//! let (header, payload) = VxlanHeader::from_bytes(&packet).unwrap();
//! assert!(header.is_vni_valid());
//! assert_eq!(header.vni(), 100);
//! assert_eq!(header.inner_type(), EtherProto::TEB);
//! ```
//!
//! ## VXLAN with specific VNI
//!
//! ```
//! use packet_strata::packet::tunnel::vxlan::VxlanHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // VXLAN with VNI = 0x123456
//! let packet = vec![
//!     0x08, 0x00, 0x00, 0x00,  // Flags (I=1) + Reserved
//!     0x12, 0x34, 0x56, 0x00,  // VNI = 0x123456, Reserved
//!     // ... Ethernet frame follows ...
//! ];
//!
//! let (header, _) = VxlanHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.vni(), 0x123456);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// VXLAN UDP destination port (IANA assigned)
pub const VXLAN_PORT: u16 = 4789;

/// Maximum VNI value (24-bit field)
pub const VXLAN_MAX_VNI: u32 = 0xFFFFFF;

/// VXLAN Header structure as defined in RFC 7348
///
/// The VXLAN header is 8 bytes and contains flags and the VNI.
///
/// Header format (8 bytes):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|R|R|R|I|R|R|R|            Reserved                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                VXLAN Network Identifier (VNI) |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, KnownLayout, Immutable)]
pub struct VxlanHeader {
    flags_reserved: U32<BigEndian>,
    vni_reserved: U32<BigEndian>,
}

impl VxlanHeader {
    // VNI field masks
    const VNI_MASK: u32 = 0xFFFFFF00;
    const VNI_SHIFT: u32 = 8;

    // Flags masks (in the first byte of flags_reserved)
    const FLAGS_MASK: u32 = 0xFF000000;
    const FLAG_I_MASK: u32 = 0x08000000;

    // Reserved bits mask (should be 0)
    const RESERVED1_MASK: u32 = 0x00FFFFFF;
    const RESERVED2_MASK: u32 = 0x000000FF;

    #[allow(unused)]
    const NAME: &'static str = "VxlanHeader";

    /// Returns the flags byte
    #[inline]
    pub fn flags(&self) -> u8 {
        ((self.flags_reserved.get() & Self::FLAGS_MASK) >> 24) as u8
    }

    /// Check if the I flag is set (VNI is valid)
    ///
    /// According to RFC 7348, the I flag MUST be set to 1 for a valid VXLAN packet.
    #[inline]
    pub fn is_vni_valid(&self) -> bool {
        self.flags_reserved.get() & Self::FLAG_I_MASK != 0
    }

    /// Returns the VXLAN Network Identifier (VNI) - 24 bits
    ///
    /// The VNI identifies the individual VXLAN segment. Valid values are 0 to 16,777,215.
    #[inline]
    pub fn vni(&self) -> u32 {
        (self.vni_reserved.get() & Self::VNI_MASK) >> Self::VNI_SHIFT
    }

    /// Returns the raw 32-bit VNI field (VNI + reserved byte)
    #[inline]
    pub fn vni_raw(&self) -> u32 {
        self.vni_reserved.get()
    }

    /// Returns the first reserved field (24 bits after flags)
    #[inline]
    pub fn reserved1(&self) -> u32 {
        self.flags_reserved.get() & Self::RESERVED1_MASK
    }

    /// Returns the second reserved field (8 bits after VNI)
    #[inline]
    pub fn reserved2(&self) -> u8 {
        (self.vni_reserved.get() & Self::RESERVED2_MASK) as u8
    }

    /// Validates the VXLAN header according to RFC 7348
    ///
    /// A valid VXLAN header must have the I flag set.
    /// Reserved bits should be 0 but we don't enforce this strictly.
    #[inline]
    fn is_valid(&self) -> bool {
        // I flag MUST be set
        self.is_vni_valid()
    }

    /// Validates the VXLAN header strictly
    ///
    /// Checks that I flag is set and all reserved bits are 0.
    #[inline]
    pub fn is_valid_strict(&self) -> bool {
        self.is_vni_valid() && self.reserved1() == 0 && self.reserved2() == 0
    }
}

impl PacketHeader for VxlanHeader {
    const NAME: &'static str = "VxlanHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        // VXLAN always encapsulates Ethernet frames
        EtherProto::TEB
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::FIXED_LEN
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for VxlanHeader {
    type Output<'a> = &'a VxlanHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _raw_options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for VxlanHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VXLAN vni={} flags=0x{:02x}{}",
            self.vni(),
            self.flags(),
            if self.is_vni_valid() { " [I]" } else { "" }
        )
    }
}

/// Check if a UDP packet might be VXLAN based on destination port
#[inline]
pub fn is_vxlan_port(dst_port: u16) -> bool {
    dst_port == VXLAN_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_header_size() {
        assert_eq!(std::mem::size_of::<VxlanHeader>(), 8);
        assert_eq!(VxlanHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_vxlan_basic_header() {
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000), // I flag set
            vni_reserved: U32::new(0x00006400),   // VNI = 100
        };

        assert!(header.is_vni_valid());
        assert_eq!(header.vni(), 100);
        assert_eq!(header.flags(), 0x08);
        assert!(header.is_valid());
        assert!(header.is_valid_strict());
    }

    #[test]
    fn test_vxlan_vni_values() {
        // VNI = 0x123456
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000),
            vni_reserved: U32::new(0x12345600),
        };

        assert_eq!(header.vni(), 0x123456);
        assert!(header.is_valid());
    }

    #[test]
    fn test_vxlan_max_vni() {
        // VNI = 0xFFFFFF (max)
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000),
            vni_reserved: U32::new(0xFFFFFF00),
        };

        assert_eq!(header.vni(), VXLAN_MAX_VNI);
        assert!(header.is_valid());
    }

    #[test]
    fn test_vxlan_zero_vni() {
        // VNI = 0
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000),
            vni_reserved: U32::new(0x00000000),
        };

        assert_eq!(header.vni(), 0);
        assert!(header.is_valid());
    }

    #[test]
    fn test_vxlan_invalid_no_i_flag() {
        // I flag not set
        let header = VxlanHeader {
            flags_reserved: U32::new(0x00000000), // No I flag
            vni_reserved: U32::new(0x00006400),
        };

        assert!(!header.is_vni_valid());
        assert!(!header.is_valid());
    }

    #[test]
    fn test_vxlan_reserved_bits() {
        // Header with reserved bits set (not strictly valid)
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08123456), // I flag + reserved bits set
            vni_reserved: U32::new(0x00006401),   // VNI + reserved byte set
        };

        assert!(header.is_vni_valid());
        assert!(header.is_valid()); // Basic validation passes
        assert!(!header.is_valid_strict()); // Strict validation fails
        assert_eq!(header.reserved1(), 0x123456);
        assert_eq!(header.reserved2(), 0x01);
    }

    #[test]
    fn test_vxlan_parsing_basic() {
        let mut packet = Vec::new();

        // VXLAN header
        packet.extend_from_slice(&0x08000000u32.to_be_bytes()); // Flags (I=1)
        packet.extend_from_slice(&0x00006400u32.to_be_bytes()); // VNI = 100

        // Add some payload (Ethernet frame would follow)
        packet.extend_from_slice(b"ethernet");

        let result = VxlanHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert!(header.is_vni_valid());
        assert_eq!(header.vni(), 100);
        assert_eq!(payload, b"ethernet");
    }

    #[test]
    fn test_vxlan_parsing_with_vni() {
        let mut packet = Vec::new();

        packet.extend_from_slice(&0x08000000u32.to_be_bytes()); // Flags
        packet.extend_from_slice(&0xABCDEF00u32.to_be_bytes()); // VNI = 0xABCDEF

        let result = VxlanHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert_eq!(header.vni(), 0xABCDEF);
    }

    #[test]
    fn test_vxlan_parsing_too_small() {
        let packet = vec![0u8; 7]; // Only 7 bytes, need 8

        let result = VxlanHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_vxlan_parsing_invalid_no_i_flag() {
        let mut packet = Vec::new();

        packet.extend_from_slice(&0x00000000u32.to_be_bytes()); // No I flag
        packet.extend_from_slice(&0x00006400u32.to_be_bytes()); // VNI

        let result = VxlanHeader::from_bytes(&packet);
        assert!(result.is_err()); // Should fail validation
    }

    #[test]
    fn test_vxlan_inner_type() {
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000),
            vni_reserved: U32::new(0x00006400),
        };

        // VXLAN encapsulates Ethernet (TEB)
        assert_eq!(header.inner_type(), EtherProto::TEB);
    }

    #[test]
    fn test_vxlan_display() {
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000),
            vni_reserved: U32::new(0x00006400),
        };

        let display = format!("{}", header);
        assert!(display.contains("VXLAN"));
        assert!(display.contains("vni=100"));
        assert!(display.contains("[I]"));
    }

    #[test]
    fn test_vxlan_display_no_i_flag() {
        let header = VxlanHeader {
            flags_reserved: U32::new(0x00000000), // No I flag
            vni_reserved: U32::new(0x00006400),
        };

        let display = format!("{}", header);
        assert!(display.contains("VXLAN"));
        assert!(!display.contains("[I]"));
    }

    #[test]
    fn test_vxlan_port_check() {
        assert!(is_vxlan_port(4789));
        assert!(!is_vxlan_port(4788));
        assert!(!is_vxlan_port(80));
    }

    #[test]
    fn test_vxlan_flags_byte() {
        // Test various flag combinations
        let header1 = VxlanHeader {
            flags_reserved: U32::new(0x08000000), // Only I flag
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(header1.flags(), 0x08);

        let header2 = VxlanHeader {
            flags_reserved: U32::new(0xFF000000), // All flag bits set
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(header2.flags(), 0xFF);
        assert!(header2.is_vni_valid()); // I flag is set
    }

    #[test]
    fn test_vxlan_multicast_vni() {
        // Test with typical multicast scenario VNI
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000),
            vni_reserved: U32::new(0x000FA000), // VNI = 4000 (common test value)
        };

        assert_eq!(header.vni(), 4000);
        assert!(header.is_valid());
    }

    #[test]
    fn test_vxlan_real_world_scenario() {
        // Simulate a real VXLAN packet as captured from network
        let mut packet = Vec::new();

        // VXLAN header: I flag set, VNI = 5000
        packet.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // Flags
        packet.extend_from_slice(&[0x00, 0x13, 0x88, 0x00]); // VNI = 5000

        // Simulated Ethernet frame header (14 bytes)
        packet.extend_from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dst MAC (broadcast)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
            0x08, 0x00, // EtherType (IPv4)
        ]);

        let (header, payload) = VxlanHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.vni(), 5000);
        assert!(header.is_vni_valid());
        assert_eq!(payload.len(), 14); // Ethernet header
    }

    #[test]
    fn test_vxlan_header_length() {
        let header = VxlanHeader {
            flags_reserved: U32::new(0x08000000),
            vni_reserved: U32::new(0x00006400),
        };

        // VXLAN always has fixed 8-byte header
        assert_eq!(header.total_len(&[]), 8);
    }
}
