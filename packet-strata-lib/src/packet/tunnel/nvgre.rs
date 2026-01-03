//! NVGRE (Network Virtualization using GRE) protocol parser
//!
//! This module implements parsing for NVGRE as defined in RFC 7637.
//! NVGRE uses GRE version 0 with the Key field to carry the Virtual Subnet ID (VSID)
//! and FlowID for network virtualization.
//!
//! # NVGRE Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0|0|1|0|0|00000|000|00000|  Ver |   Protocol Type (0x6558)     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Virtual Subnet ID (VSID)        |    FlowID     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Ethernet Frame...                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key differences from standard GRE
//!
//! - Version field MUST be 0
//! - Key flag (K) MUST be set
//! - Checksum flag (C) SHOULD NOT be set
//! - Sequence flag (S) SHOULD NOT be set
//! - Protocol type MUST be 0x6558 (Transparent Ethernet Bridging)
//! - Key field is split into VSID (24 bits) and FlowID (8 bits)
//!
//! # Examples
//!
//! ## Basic NVGRE parsing
//!
//! ```
//! use packet_strata::packet::tunnel::nvgre::NvgreHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // NVGRE packet
//! let packet = vec![
//!     0x20, 0x00,  // flags_version (K flag set, version 0)
//!     0x65, 0x58,  // protocol_type (TEB - Transparent Ethernet Bridging)
//!     0x00, 0x01, 0x00,  // VSID = 256
//!     0x01,  // FlowID = 1
//!     // ... Ethernet frame follows ...
//! ];
//!
//! let (header, payload) = NvgreHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 0);
//! assert_eq!(header.protocol_type(), EtherProto::TEB);
//! assert_eq!(header.vsid(), 256);
//! assert_eq!(header.flow_id(), 1);
//! ```
//!
//! ## NVGRE with specific VSID
//!
//! ```
//! use packet_strata::packet::tunnel::nvgre::NvgreHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // NVGRE with VSID = 0x123456, FlowID = 0
//! let packet = vec![
//!     0x20, 0x00,  // flags_version
//!     0x65, 0x58,  // protocol_type (TEB)
//!     0x12, 0x34, 0x56,  // VSID = 0x123456
//!     0x00,  // FlowID = 0
//!     // ... Ethernet frame follows ...
//! ];
//!
//! let (header, _) = NvgreHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.vsid(), 0x123456);
//! assert_eq!(header.flow_id(), 0);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// NVGRE Protocol Type (Transparent Ethernet Bridging)
pub const NVGRE_PROTOCOL_TEB: u16 = 0x6558;

/// Maximum VSID value (24-bit field)
pub const NVGRE_MAX_VSID: u32 = 0xFFFFFF;

/// Reserved VSID values according to RFC 7637
pub const NVGRE_VSID_RESERVED_MIN: u32 = 0xFFFFF0;
pub const NVGRE_VSID_RESERVED_MAX: u32 = 0xFFFFFF;

/// NVGRE Header structure as defined in RFC 7637
///
/// This is the fixed 8-byte NVGRE header. The Key field is interpreted
/// as VSID (24 bits) + FlowID (8 bits).
///
/// Header format (8 bytes):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0|0|1|0|0|00000|000|00000| Ver |   Protocol Type (0x6558)      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Virtual Subnet ID (VSID)        |    FlowID     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct NvgreHeader {
    flags_version: U16<BigEndian>,
    protocol_type: U16<BigEndian>,
    vsid_flowid: U32<BigEndian>,
}

impl NvgreHeader {
    // GRE Flags (in the high byte of flags_version)
    pub const FLAG_CHECKSUM: u16 = 0x8000; // Checksum Present (C bit) - SHOULD be 0
    pub const FLAG_ROUTING: u16 = 0x4000; // Routing Present (R bit) - MUST be 0
    pub const FLAG_KEY: u16 = 0x2000; // Key Present (K bit) - MUST be 1
    pub const FLAG_SEQUENCE: u16 = 0x1000; // Sequence Number Present (S bit) - SHOULD be 0
    pub const FLAG_STRICT_ROUTE: u16 = 0x0800; // Strict Source Route (s bit) - MUST be 0

    pub const VERSION_MASK: u16 = 0x0007; // Version field (bits 13-15)
    pub const RECUR_MASK: u16 = 0x0700; // Recursion control (bits 5-7) - MUST be 0
    pub const FLAGS_MASK: u16 = 0x00F8; // Reserved flags (bits 8-12) - MUST be 0

    pub const VERSION_NVGRE: u16 = 0x0000; // NVGRE uses GRE version 0

    // VSID/FlowID masks
    const VSID_MASK: u32 = 0xFFFFFF00;
    const VSID_SHIFT: u32 = 8;
    const FLOWID_MASK: u32 = 0x000000FF;

    #[allow(unused)]
    const NAME: &'static str = "NvgreHeader";

    /// Returns the flags and version field
    #[inline]
    pub fn flags_version(&self) -> u16 {
        self.flags_version.get()
    }

    /// Returns the GRE version number (should be 0 for NVGRE)
    #[inline]
    pub fn version(&self) -> u8 {
        (self.flags_version() & Self::VERSION_MASK) as u8
    }

    /// Returns the protocol type field (should be 0x6558 for NVGRE)
    #[inline]
    pub fn protocol_type(&self) -> EtherProto {
        self.protocol_type.get().into()
    }

    /// Returns the raw protocol type value
    #[inline]
    pub fn protocol_type_raw(&self) -> u16 {
        self.protocol_type.get()
    }

    /// Returns the Virtual Subnet ID (VSID) - 24 bits
    ///
    /// The VSID identifies the virtual network/segment. Valid values are 0 to 0xFFFFEF.
    /// Values 0xFFFFF0 to 0xFFFFFF are reserved.
    #[inline]
    pub fn vsid(&self) -> u32 {
        (self.vsid_flowid.get() & Self::VSID_MASK) >> Self::VSID_SHIFT
    }

    /// Returns the FlowID - 8 bits
    ///
    /// The FlowID is used for load balancing purposes. When not used, it SHOULD be set to 0.
    #[inline]
    pub fn flow_id(&self) -> u8 {
        (self.vsid_flowid.get() & Self::FLOWID_MASK) as u8
    }

    /// Returns the raw 32-bit key field (VSID + FlowID combined)
    #[inline]
    pub fn key(&self) -> u32 {
        self.vsid_flowid.get()
    }

    /// Check if Checksum Present flag is set (should be 0 for NVGRE)
    #[inline]
    pub fn has_checksum(&self) -> bool {
        self.flags_version() & Self::FLAG_CHECKSUM != 0
    }

    /// Check if Routing Present flag is set (should be 0 for NVGRE)
    #[inline]
    pub fn has_routing(&self) -> bool {
        self.flags_version() & Self::FLAG_ROUTING != 0
    }

    /// Check if Key Present flag is set (should always be 1 for NVGRE)
    #[inline]
    pub fn has_key(&self) -> bool {
        self.flags_version() & Self::FLAG_KEY != 0
    }

    /// Check if Sequence Number Present flag is set (should be 0 for NVGRE)
    #[inline]
    pub fn has_sequence(&self) -> bool {
        self.flags_version() & Self::FLAG_SEQUENCE != 0
    }

    /// Check if Strict Source Route flag is set (should be 0 for NVGRE)
    #[inline]
    pub fn has_strict_route(&self) -> bool {
        self.flags_version() & Self::FLAG_STRICT_ROUTE != 0
    }

    /// Returns the recursion control value (should be 0 for NVGRE)
    #[inline]
    pub fn recursion_control(&self) -> u8 {
        ((self.flags_version() & Self::RECUR_MASK) >> 8) as u8
    }

    /// Check if the VSID is in the reserved range (0xFFFFF0 - 0xFFFFFF)
    #[inline]
    pub fn is_vsid_reserved(&self) -> bool {
        let vsid = self.vsid();
        (NVGRE_VSID_RESERVED_MIN..=NVGRE_VSID_RESERVED_MAX).contains(&vsid)
    }

    /// Validates the NVGRE header according to RFC 7637
    ///
    /// Strict validation requires:
    /// - Version MUST be 0
    /// - Key flag MUST be set
    /// - Routing flag MUST be 0
    /// - Strict Source Route flag MUST be 0
    /// - Recursion control MUST be 0
    /// - Protocol type MUST be 0x6558 (TEB)
    #[inline]
    fn is_valid(&self) -> bool {
        // Version MUST be 0
        if self.version() != 0 {
            return false;
        }

        // Key flag MUST be set
        if !self.has_key() {
            return false;
        }

        // Routing flag MUST be 0
        if self.has_routing() {
            return false;
        }

        // Strict Source Route flag MUST be 0
        if self.has_strict_route() {
            return false;
        }

        // Recursion control MUST be 0
        if self.recursion_control() != 0 {
            return false;
        }

        // Protocol type MUST be TEB (0x6558)
        if self.protocol_type_raw() != NVGRE_PROTOCOL_TEB {
            return false;
        }

        true
    }

    /// Validates the NVGRE header with relaxed rules
    ///
    /// This is less strict and only checks:
    /// - Version is 0
    /// - Key flag is set
    #[inline]
    pub fn is_valid_relaxed(&self) -> bool {
        self.version() == 0 && self.has_key()
    }

    /// Returns a string representation of active flags
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();

        if self.has_checksum() {
            flags.push("C");
        }
        if self.has_routing() {
            flags.push("R");
        }
        if self.has_key() {
            flags.push("K");
        }
        if self.has_sequence() {
            flags.push("S");
        }
        if self.has_strict_route() {
            flags.push("s");
        }

        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join("")
        }
    }
}

impl PacketHeader for NvgreHeader {
    const NAME: &'static str = "NvgreHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.protocol_type()
    }

    /// Returns the total header length in bytes (always 8 for NVGRE)
    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::FIXED_LEN
    }

    /// Validates the NVGRE header
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for NvgreHeader {
    type Output<'a> = &'a NvgreHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _raw_options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for NvgreHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NVGRE vsid={} flow_id={} proto={}(0x{:04x}) flags={}",
            self.vsid(),
            self.flow_id(),
            self.protocol_type(),
            self.protocol_type().0,
            self.flags_string()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvgre_header_size() {
        assert_eq!(std::mem::size_of::<NvgreHeader>(), 8);
        assert_eq!(NvgreHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_nvgre_basic_header() {
        let header = NvgreHeader {
            flags_version: U16::new(0x2000), // Key present, version 0
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000), // VSID = 256, FlowID = 0
        };

        assert_eq!(header.version(), 0);
        assert_eq!(header.protocol_type(), EtherProto::TEB);
        assert!(header.has_key());
        assert!(!header.has_checksum());
        assert!(!header.has_sequence());
        assert!(header.is_valid());
        assert_eq!(header.vsid(), 256);
        assert_eq!(header.flow_id(), 0);
    }

    #[test]
    fn test_nvgre_vsid_flowid() {
        // VSID = 0x123456, FlowID = 0xAB
        let header = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x123456AB),
        };

        assert_eq!(header.vsid(), 0x123456);
        assert_eq!(header.flow_id(), 0xAB);
        assert_eq!(header.key(), 0x123456AB);
    }

    #[test]
    fn test_nvgre_max_vsid() {
        // VSID = 0xFFFFFF (max), FlowID = 0xFF
        let header = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0xFFFFFFFF),
        };

        assert_eq!(header.vsid(), 0xFFFFFF);
        assert_eq!(header.flow_id(), 0xFF);
        assert!(header.is_vsid_reserved());
    }

    #[test]
    fn test_nvgre_reserved_vsid_range() {
        // VSID = 0xFFFFF0 (first reserved)
        let header1 = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0xFFFFF000),
        };
        assert!(header1.is_vsid_reserved());

        // VSID = 0xFFFFEF (last non-reserved)
        let header2 = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0xFFFFEF00),
        };
        assert!(!header2.is_vsid_reserved());
    }

    #[test]
    fn test_nvgre_version_validation() {
        // Invalid: version 1
        let header = NvgreHeader {
            flags_version: U16::new(0x2001), // Key present, but version 1
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert!(!header.is_valid());
        assert!(!header.is_valid_relaxed());
    }

    #[test]
    fn test_nvgre_key_flag_required() {
        // Invalid: Key flag not set
        let header = NvgreHeader {
            flags_version: U16::new(0x0000), // version 0, but no key
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert!(!header.is_valid());
        assert!(!header.is_valid_relaxed());
    }

    #[test]
    fn test_nvgre_routing_forbidden() {
        // Invalid: Routing flag set
        let header = NvgreHeader {
            flags_version: U16::new(0x6000), // Key + Routing
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert!(!header.is_valid());
        // But relaxed validation passes
        assert!(header.is_valid_relaxed());
    }

    #[test]
    fn test_nvgre_wrong_protocol_type() {
        // Invalid: Wrong protocol type (IPv4 instead of TEB)
        let header = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(0x0800), // IPv4 instead of TEB
            vsid_flowid: U32::new(0x00010000),
        };
        assert!(!header.is_valid());
        // But relaxed validation passes
        assert!(header.is_valid_relaxed());
    }

    #[test]
    fn test_nvgre_with_checksum_flag() {
        // Checksum flag set (SHOULD NOT, but not MUST NOT)
        let header = NvgreHeader {
            flags_version: U16::new(0xA000), // Key + Checksum
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert!(header.has_checksum());
        // Still valid according to RFC (SHOULD NOT, not MUST NOT)
        assert!(header.is_valid());
    }

    #[test]
    fn test_nvgre_with_sequence_flag() {
        // Sequence flag set (SHOULD NOT, but not MUST NOT)
        let header = NvgreHeader {
            flags_version: U16::new(0x3000), // Key + Sequence
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert!(header.has_sequence());
        // Still valid according to RFC (SHOULD NOT, not MUST NOT)
        assert!(header.is_valid());
    }

    #[test]
    fn test_nvgre_parsing_basic() {
        let mut packet = Vec::new();

        // NVGRE header
        packet.extend_from_slice(&0x2000u16.to_be_bytes()); // flags_version (K, v0)
        packet.extend_from_slice(&NVGRE_PROTOCOL_TEB.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x00010001u32.to_be_bytes()); // VSID=256, FlowID=1

        // Add some payload (Ethernet frame would follow)
        packet.extend_from_slice(b"payload");

        let result = NvgreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.version(), 0);
        assert_eq!(header.protocol_type(), EtherProto::TEB);
        assert_eq!(header.vsid(), 256);
        assert_eq!(header.flow_id(), 1);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn test_nvgre_parsing_with_vsid() {
        let mut packet = Vec::new();

        packet.extend_from_slice(&0x2000u16.to_be_bytes()); // flags_version
        packet.extend_from_slice(&NVGRE_PROTOCOL_TEB.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x12345600u32.to_be_bytes()); // VSID=0x123456, FlowID=0

        let result = NvgreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert_eq!(header.vsid(), 0x123456);
        assert_eq!(header.flow_id(), 0);
    }

    #[test]
    fn test_nvgre_parsing_too_small() {
        let packet = vec![0u8; 7]; // Only 7 bytes, need 8

        let result = NvgreHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_nvgre_parsing_invalid_version() {
        let mut packet = Vec::new();

        // Invalid: version 1
        packet.extend_from_slice(&0x2001u16.to_be_bytes()); // flags_version (K, v1)
        packet.extend_from_slice(&NVGRE_PROTOCOL_TEB.to_be_bytes());
        packet.extend_from_slice(&0x00010000u32.to_be_bytes());

        let result = NvgreHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_nvgre_parsing_missing_key() {
        let mut packet = Vec::new();

        // Invalid: no key flag
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // flags_version (no K)
        packet.extend_from_slice(&NVGRE_PROTOCOL_TEB.to_be_bytes());
        packet.extend_from_slice(&0x00010000u32.to_be_bytes());

        let result = NvgreHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_nvgre_flags_string() {
        let header1 = NvgreHeader {
            flags_version: U16::new(0x2000), // K only
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert_eq!(header1.flags_string(), "K");

        let header2 = NvgreHeader {
            flags_version: U16::new(0xA000), // K + C
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert_eq!(header2.flags_string(), "CK");

        let header3 = NvgreHeader {
            flags_version: U16::new(0x3000), // K + S
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };
        assert_eq!(header3.flags_string(), "KS");
    }

    #[test]
    fn test_nvgre_display() {
        let header = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010001),
        };

        let display = format!("{}", header);
        assert!(display.contains("NVGRE"));
        assert!(display.contains("vsid=256"));
        assert!(display.contains("flow_id=1"));
    }

    #[test]
    fn test_nvgre_zero_vsid() {
        let header = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00000000), // VSID=0, FlowID=0
        };

        assert_eq!(header.vsid(), 0);
        assert_eq!(header.flow_id(), 0);
        assert!(header.is_valid());
        assert!(!header.is_vsid_reserved());
    }

    #[test]
    fn test_nvgre_inner_type() {
        let header = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00010000),
        };

        // inner_type should return TEB for encapsulated Ethernet
        assert_eq!(header.inner_type(), EtherProto::TEB);
    }

    #[test]
    fn test_nvgre_multicast_vsid() {
        // Test with a typical multicast VSID scenario
        let header = NvgreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(NVGRE_PROTOCOL_TEB),
            vsid_flowid: U32::new(0x00ABCD00), // VSID=0xABCD (common test value)
        };

        assert_eq!(header.vsid(), 0x00ABCD);
        assert!(!header.is_vsid_reserved());
    }
}
