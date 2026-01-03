//! GRE (Generic Routing Encapsulation) protocol parser
//!
//! This module implements parsing for GRE tunnels as defined in:
//! - RFC 2784: Generic Routing Encapsulation (GRE)
//! - RFC 2890: Key and Sequence Number Extensions to GRE
//! - RFC 2637: Point-to-Point Tunneling Protocol (PPTP) - Enhanced GRE
//!
//! # GRE Header Format (RFC 2784 + RFC 2890)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Checksum (optional)      |       Offset (optional)       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Key (optional)                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  Sequence Number (optional)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Minimum header size: 4 bytes (no optional fields)
//! - Maximum header size: 16 bytes (all optional fields present)
//! - C flag: Checksum present
//! - K flag: Key present
//! - S flag: Sequence number present
//! - Version: 0 for standard GRE, 1 for Enhanced GRE (PPTP)
//! - Protocol Type: EtherType of encapsulated payload
//!
//! # Examples
//!
//! ## GRE with key field
//!
//! ```
//! use packet_strata::packet::tunnel::gre::GreHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // GRE packet with key field
//! let packet = vec![
//!     0x20, 0x00,  // flags_version (Key present, version 0)
//!     0x08, 0x00,  // protocol_type (IPv4)
//!     0x00, 0x00, 0x00, 0x2A,  // key = 42
//!     // ... encapsulated payload follows ...
//! ];
//!
//! let (header, payload) = GreHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 0);
//! assert_eq!(header.protocol_type(), EtherProto::IPV4);
//! assert!(header.has_key());
//! assert_eq!(header.key().unwrap(), 42);
//! ```
//!
//! ## GRE with checksum and sequence number
//!
//! ```
//! use packet_strata::packet::tunnel::gre::GreHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // GRE packet with checksum and sequence number
//! let packet = vec![
//!     0xB0, 0x00,  // flags_version (C=1, K=1, S=1, version 0)
//!     0x08, 0x00,  // protocol_type (IPv4)
//!     0x12, 0x34,  // checksum
//!     0x00, 0x00,  // offset (reserved)
//!     0x00, 0x00, 0x00, 0x64,  // key = 100
//!     0x00, 0x00, 0x00, 0x01,  // sequence number = 1
//!     // ... encapsulated payload follows ...
//! ];
//!
//! let (header, payload) = GreHeader::from_bytes(&packet).unwrap();
//! assert!(header.has_checksum());
//! assert!(header.has_key());
//! assert!(header.has_sequence());
//! assert_eq!(header.checksum().unwrap(), 0x1234);
//! assert_eq!(header.key().unwrap(), 100);
//! assert_eq!(header.sequence_number().unwrap(), 1);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// GRE Header structure as defined in RFC 2784 and RFC 2890
///
/// Basic GRE header format (4 bytes minimum):
/// ```text
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |C|R|K|S|s|Recur|A| Flags | Ver |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Checksum (optional)      |       Offset (optional)       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Key (optional)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Sequence Number (optional)                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct GreHeader {
    flags_version: U16<BigEndian>,
    protocol_type: U16<BigEndian>,
}

impl GreHeader {
    // GRE Flags (in the high byte of flags_version)
    pub const FLAG_CHECKSUM: u16 = 0x8000; // Checksum Present (C bit)
    pub const FLAG_ROUTING: u16 = 0x4000; // Routing Present (R bit) - deprecated
    pub const FLAG_KEY: u16 = 0x2000; // Key Present (K bit)
    pub const FLAG_SEQUENCE: u16 = 0x1000; // Sequence Number Present (S bit)
    pub const FLAG_STRICT_ROUTE: u16 = 0x0800; // Strict Source Route (s bit) - deprecated
    pub const FLAG_ACK: u16 = 0x0080; // Acknowledgment Present (A bit) - PPTP extension

    pub const VERSION_MASK: u16 = 0x0007; // Version field (bits 13-15)
    pub const RECUR_MASK: u16 = 0x0700; // Recursion control (bits 5-7) - deprecated
    pub const FLAGS_MASK: u16 = 0x00F8; // Reserved flags (bits 8-12)

    pub const VERSION_0: u16 = 0x0000; // GRE version 0 (RFC 2784)
    pub const VERSION_1: u16 = 0x0001; // Enhanced GRE (RFC 2637 - PPTP)

    #[allow(unused)]
    const NAME: &'static str = "GreHeader";

    /// Returns the flags and version field
    #[inline]
    pub fn flags_version(&self) -> u16 {
        self.flags_version.get()
    }

    /// Returns the GRE version number (0 or 1)
    #[inline]
    pub fn version(&self) -> u8 {
        (self.flags_version() & Self::VERSION_MASK) as u8
    }

    /// Returns the protocol type field (indicates the protocol type of the payload)
    #[inline]
    pub fn protocol_type(&self) -> EtherProto {
        self.protocol_type.get().into()
    }

    /// Check if Checksum Present flag is set
    #[inline]
    pub fn has_checksum(&self) -> bool {
        self.flags_version() & Self::FLAG_CHECKSUM != 0
    }

    /// Check if Routing Present flag is set (deprecated)
    #[inline]
    pub fn has_routing(&self) -> bool {
        self.flags_version() & Self::FLAG_ROUTING != 0
    }

    /// Check if Key Present flag is set
    #[inline]
    pub fn has_key(&self) -> bool {
        self.flags_version() & Self::FLAG_KEY != 0
    }

    /// Check if Sequence Number Present flag is set
    #[inline]
    pub fn has_sequence(&self) -> bool {
        self.flags_version() & Self::FLAG_SEQUENCE != 0
    }

    /// Check if Strict Source Route flag is set (deprecated)
    #[inline]
    pub fn has_strict_route(&self) -> bool {
        self.flags_version() & Self::FLAG_STRICT_ROUTE != 0
    }

    /// Check if Acknowledgment flag is set (PPTP extension)
    #[inline]
    pub fn has_ack(&self) -> bool {
        self.flags_version() & Self::FLAG_ACK != 0
    }

    /// Returns the recursion control value (deprecated)
    #[inline]
    pub fn recursion_control(&self) -> u8 {
        ((self.flags_version() & Self::RECUR_MASK) >> 8) as u8
    }

    /// Validates the GRE header
    #[inline]
    fn is_valid(&self) -> bool {
        let version = self.version();

        // Only version 0 and 1 are defined
        if version > 1 {
            return false;
        }

        // Version 0 (RFC 2784) - standard GRE
        // Version 1 (RFC 2637) - Enhanced GRE (PPTP)
        // Reserved flags must be zero for version 0
        if version == 0 {
            let reserved = self.flags_version() & Self::FLAGS_MASK;
            if reserved != 0 {
                return false;
            }
        }

        true
    }

    /// Calculate the total header length including optional fields
    #[inline]
    pub fn header_length(&self) -> usize {
        let mut len = Self::FIXED_LEN; // 4 bytes for basic header

        // Add 4 bytes for checksum + offset (if present)
        if self.has_checksum() || self.has_routing() {
            len += 4;
        }

        // Add 4 bytes for key (if present)
        if self.has_key() {
            len += 4;
        }

        // Add 4 bytes for sequence number (if present)
        if self.has_sequence() {
            len += 4;
        }

        // Enhanced GRE (version 1) has acknowledgment number
        if self.version() == 1 && self.has_ack() {
            len += 4;
        }

        len
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
        if self.has_ack() {
            flags.push("A");
        }

        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join("")
        }
    }
}

/// GRE Header with optional fields parsed
#[derive (Debug, Clone)]
pub struct GreHeaderOpt<'a> {
    pub header: &'a GreHeader,
    pub raw_options: &'a [u8],
}

impl<'a> GreHeaderOpt<'a> {
    /// Get the checksum value if present
    pub fn checksum(&self) -> Option<u16> {
        if !self.header.has_checksum() && !self.header.has_routing() {
            return None;
        }

        if self.raw_options.len() < 2 {
            return None;
        }

        Some(u16::from_be_bytes([
            self.raw_options[0],
            self.raw_options[1],
        ]))
    }

    /// Get the offset value if present (only meaningful if routing is present)
    pub fn offset(&self) -> Option<u16> {
        if !self.header.has_checksum() && !self.header.has_routing() {
            return None;
        }

        if self.raw_options.len() < 4 {
            return None;
        }

        Some(u16::from_be_bytes([
            self.raw_options[2],
            self.raw_options[3],
        ]))
    }

    /// Get the key value if present
    pub fn key(&self) -> Option<u32> {
        if !self.header.has_key() {
            return None;
        }

        let mut offset = 0;
        if self.header.has_checksum() || self.header.has_routing() {
            offset += 4;
        }

        if self.raw_options.len() < offset + 4 {
            return None;
        }

        let key_bytes = &self.raw_options[offset..offset + 4];
        Some(u32::from_be_bytes([
            key_bytes[0],
            key_bytes[1],
            key_bytes[2],
            key_bytes[3],
        ]))
    }

    /// Get the sequence number if present
    pub fn sequence_number(&self) -> Option<u32> {
        if !self.header.has_sequence() {
            return None;
        }

        let mut offset = 0;
        if self.header.has_checksum() || self.header.has_routing() {
            offset += 4;
        }
        if self.header.has_key() {
            offset += 4;
        }

        if self.raw_options.len() < offset + 4 {
            return None;
        }

        let seq_bytes = &self.raw_options[offset..offset + 4];
        Some(u32::from_be_bytes([
            seq_bytes[0],
            seq_bytes[1],
            seq_bytes[2],
            seq_bytes[3],
        ]))
    }

    /// Get the acknowledgment number if present (Enhanced GRE - version 1 only)
    pub fn acknowledgment_number(&self) -> Option<u32> {
        if self.header.version() != 1 || !self.header.has_ack() {
            return None;
        }

        let mut offset = 0;
        if self.header.has_checksum() || self.header.has_routing() {
            offset += 4;
        }
        if self.header.has_key() {
            offset += 4;
        }
        if self.header.has_sequence() {
            offset += 4;
        }

        if self.raw_options.len() < offset + 4 {
            return None;
        }

        let ack_bytes = &self.raw_options[offset..offset + 4];
        Some(u32::from_be_bytes([
            ack_bytes[0],
            ack_bytes[1],
            ack_bytes[2],
            ack_bytes[3],
        ]))
    }
}

impl std::ops::Deref for GreHeaderOpt<'_> {
    type Target = GreHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for GreHeader {
    const NAME: &'static str = "GreHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.protocol_type()
    }

    /// Returns the total header length in bytes (including optional fields)
    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        self.header_length()
    }

    /// Validates the GRE header
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for GreHeader {
    type Output<'a> = GreHeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, raw_options: &'a [u8]) -> Self::Output<'a> {
        GreHeaderOpt {
            header,
            raw_options,
        }
    }
}

impl fmt::Display for GreHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GRE v{} proto={}(0x{:04x}) flags={}",
            self.version(),
            self.protocol_type(),
            self.protocol_type().0,
            self.flags_string()
        )
    }
}

impl fmt::Display for GreHeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GRE v{} proto={} flags={}",
            self.version(),
            self.protocol_type(),
            self.flags_string()
        )?;

        if let Some(key) = self.key() {
            write!(f, " key={}", key)?;
        }

        if let Some(seq) = self.sequence_number() {
            write!(f, " seq={}", seq)?;
        }

        if let Some(ack) = self.acknowledgment_number() {
            write!(f, " ack={}", ack)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_header_size() {
        assert_eq!(std::mem::size_of::<GreHeader>(), 4);
        assert_eq!(GreHeader::FIXED_LEN, 4);
    }

    #[test]
    fn test_gre_basic_header() {
        let header = GreHeader {
            flags_version: U16::new(0x0000), // No flags, version 0
            protocol_type: U16::new(0x0800), // IPv4
        };

        assert_eq!(header.version(), 0);
        assert_eq!(header.protocol_type(), EtherProto::IPV4);
        assert!(!header.has_checksum());
        assert!(!header.has_key());
        assert!(!header.has_sequence());
        assert!(header.is_valid());
        assert_eq!(header.header_length(), 4);
    }

    #[test]
    fn test_gre_with_key() {
        let header = GreHeader {
            flags_version: U16::new(0x2000), // Key present
            protocol_type: U16::new(0x0800), // IPv4
        };

        assert!(header.has_key());
        assert!(!header.has_checksum());
        assert!(!header.has_sequence());
        assert_eq!(header.header_length(), 8); // 4 + 4 for key
    }

    #[test]
    fn test_gre_with_sequence() {
        let header = GreHeader {
            flags_version: U16::new(0x1000), // Sequence present
            protocol_type: U16::new(0x0800), // IPv4
        };

        assert!(header.has_sequence());
        assert!(!header.has_checksum());
        assert!(!header.has_key());
        assert_eq!(header.header_length(), 8); // 4 + 4 for sequence
    }

    #[test]
    fn test_gre_with_checksum() {
        let header = GreHeader {
            flags_version: U16::new(0x8000), // Checksum present
            protocol_type: U16::new(0x0800), // IPv4
        };

        assert!(header.has_checksum());
        assert!(!header.has_key());
        assert!(!header.has_sequence());
        assert_eq!(header.header_length(), 8); // 4 + 4 for checksum+offset
    }

    #[test]
    fn test_gre_all_flags() {
        let header = GreHeader {
            flags_version: U16::new(0xB000), // Checksum + Key + Sequence
            protocol_type: U16::new(0x0800), // IPv4
        };

        assert!(header.has_checksum());
        assert!(header.has_key());
        assert!(header.has_sequence());
        assert_eq!(header.header_length(), 16); // 4 + 4 + 4 + 4
    }

    #[test]
    fn test_gre_version_validation() {
        // Valid version 0
        let header_v0 = GreHeader {
            flags_version: U16::new(0x0000),
            protocol_type: U16::new(0x0800),
        };
        assert!(header_v0.is_valid());
        assert_eq!(header_v0.version(), 0);

        // Valid version 1 (Enhanced GRE)
        let header_v1 = GreHeader {
            flags_version: U16::new(0x0001),
            protocol_type: U16::new(0x880B), // PPP
        };
        assert!(header_v1.is_valid());
        assert_eq!(header_v1.version(), 1);

        // Invalid version
        let header_invalid = GreHeader {
            flags_version: U16::new(0x0002), // Version 2 - invalid
            protocol_type: U16::new(0x0800),
        };
        assert!(!header_invalid.is_valid());
    }

    #[test]
    fn test_gre_parsing_basic() {
        let mut packet = Vec::new();

        // GRE header: no flags, version 0, protocol IPv4
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // flags_version
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol_type

        // Add some payload
        packet.extend_from_slice(b"payload");

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.version(), 0);
        assert_eq!(header.protocol_type(), EtherProto::IPV4);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn test_gre_parsing_with_key() {
        let mut packet = Vec::new();

        // GRE header with key
        packet.extend_from_slice(&0x2000u16.to_be_bytes()); // flags_version (key present)
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x12345678u32.to_be_bytes()); // key

        // Add payload
        packet.extend_from_slice(b"test");

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert!(header.has_key());
        assert_eq!(header.key().unwrap(), 0x12345678);
        assert_eq!(payload, b"test");
    }

    #[test]
    fn test_gre_parsing_with_sequence() {
        let mut packet = Vec::new();

        // GRE header with sequence
        packet.extend_from_slice(&0x1000u16.to_be_bytes()); // flags_version (sequence present)
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x00000042u32.to_be_bytes()); // sequence number

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert!(header.has_sequence());
        assert_eq!(header.sequence_number().unwrap(), 0x42);
    }

    #[test]
    fn test_gre_parsing_with_checksum() {
        let mut packet = Vec::new();

        // GRE header with checksum
        packet.extend_from_slice(&0x8000u16.to_be_bytes()); // flags_version (checksum present)
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0xABCDu16.to_be_bytes()); // checksum
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // offset

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert!(header.has_checksum());
        assert_eq!(header.checksum().unwrap(), 0xABCD);
    }

    #[test]
    fn test_gre_parsing_all_options() {
        let mut packet = Vec::new();

        // GRE header with all options
        packet.extend_from_slice(&0xB000u16.to_be_bytes()); // C + K + S flags
        packet.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // checksum
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // offset
        packet.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // key
        packet.extend_from_slice(&0x00000100u32.to_be_bytes()); // sequence

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert!(header.has_checksum());
        assert!(header.has_key());
        assert!(header.has_sequence());
        assert_eq!(header.checksum().unwrap(), 0x1234);
        assert_eq!(header.key().unwrap(), 0xDEADBEEF);
        assert_eq!(header.sequence_number().unwrap(), 0x100);
    }

    #[test]
    fn test_gre_parsing_too_small() {
        let packet = vec![0u8; 3]; // Only 3 bytes, need 4

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_gre_flags_string() {
        let header1 = GreHeader {
            flags_version: U16::new(0x0000),
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(header1.flags_string(), "none");

        let header2 = GreHeader {
            flags_version: U16::new(0x8000), // C
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(header2.flags_string(), "C");

        let header3 = GreHeader {
            flags_version: U16::new(0xB000), // C + K + S
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(header3.flags_string(), "CKS");
    }

    #[test]
    fn test_gre_nvgre_scenario() {
        // NVGRE uses protocol type 0x6558 (Transparent Ethernet Bridging)
        let mut packet = Vec::new();

        packet.extend_from_slice(&0x2000u16.to_be_bytes()); // Key present
        packet.extend_from_slice(&0x6558u16.to_be_bytes()); // TEB protocol
        packet.extend_from_slice(&0x00010001u32.to_be_bytes()); // VSID in key field

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert_eq!(header.protocol_type(), EtherProto::TEB);
        assert!(header.has_key());
        assert_eq!(header.key().unwrap(), 0x00010001);
    }

    #[test]
    fn test_gre_enhanced_version_1() {
        // Enhanced GRE (PPTP) - version 1
        let mut packet = Vec::new();

        packet.extend_from_slice(&0x3081u16.to_be_bytes()); // K + S + A flags, version 1
        packet.extend_from_slice(&0x880Bu16.to_be_bytes()); // PPP protocol
        packet.extend_from_slice(&0x0004u16.to_be_bytes()); // Payload length (in key field)
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Call ID
        packet.extend_from_slice(&0x00000001u32.to_be_bytes()); // Sequence number
        packet.extend_from_slice(&0x00000000u32.to_be_bytes()); // Acknowledgment number

        let result = GreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert_eq!(header.version(), 1);
        assert!(header.has_key());
        assert!(header.has_sequence());
        assert!(header.has_ack());
    }

    #[test]
    fn test_gre_protocol_types() {
        // Test various protocol types
        let protocols = vec![
            (EtherProto::IPV4, "IPv4"),
            (EtherProto::IPV6, "IPv6"),
            (EtherProto::TEB, "TEB"),
            (EtherProto::PPP_MP, "PPP"),
            (EtherProto::MPLS_UC, "MPLS unicast"),
        ];

        for (proto_type, _name) in protocols {
            let header = GreHeader {
                flags_version: U16::new(0x0000),
                protocol_type: U16::new(proto_type.0.get()),
            };

            assert_eq!(header.protocol_type(), proto_type);
            assert!(header.is_valid());
        }
    }

    #[test]
    fn test_gre_header_length_calculation() {
        // No options
        let h1 = GreHeader {
            flags_version: U16::new(0x0000),
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(h1.header_length(), 4);

        // Checksum only
        let h2 = GreHeader {
            flags_version: U16::new(0x8000),
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(h2.header_length(), 8);

        // Key only
        let h3 = GreHeader {
            flags_version: U16::new(0x2000),
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(h3.header_length(), 8);

        // Sequence only
        let h4 = GreHeader {
            flags_version: U16::new(0x1000),
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(h4.header_length(), 8);

        // Checksum + Key
        let h5 = GreHeader {
            flags_version: U16::new(0xA000),
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(h5.header_length(), 12);

        // All options (C + K + S)
        let h6 = GreHeader {
            flags_version: U16::new(0xB000),
            protocol_type: U16::new(0x0800),
        };
        assert_eq!(h6.header_length(), 16);
    }
}
