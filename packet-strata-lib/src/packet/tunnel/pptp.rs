//! PPTP GRE (Enhanced GRE version 1) protocol parser
//!
//! This module implements parsing for Enhanced GRE as defined in RFC 2637
//! (Point-to-Point Tunneling Protocol). Enhanced GRE is version 1 of GRE
//! with specific extensions for PPTP tunneling.
//!
//! # PPTP GRE Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |C|R|K|S|s|Recur|A| Flags | Ver |         Protocol Type         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Key (Payload Length)       |       Key (Call ID)           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  Sequence Number (Optional)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Acknowledgment Number (Optional)                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Differences from standard GRE
//!
//! - Version field MUST be 1
//! - Key flag (K) MUST be set
//! - Protocol type is typically 0x880B (PPP)
//! - Key field is split into Payload Length (16 bits) and Call ID (16 bits)
//! - Acknowledgment number support (A flag)
//! - Checksum and Routing fields MUST NOT be present
//!
//! # Examples
//!
//! ## PPTP GRE with sequence number
//!
//! ```
//! use packet_strata::packet::tunnel::pptp::PptpGreHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // PPTP GRE packet with sequence number
//! let packet = vec![
//!     0x30, 0x01,  // flags_version (K + S, version 1)
//!     0x88, 0x0B,  // protocol_type (PPP)
//!     0x00, 0x10,  // payload_length = 16
//!     0x00, 0x2A,  // call_id = 42
//!     0x00, 0x00, 0x00, 0x01,  // sequence_number = 1
//!     // ... PPP payload follows ...
//! ];
//!
//! let (header, payload) = PptpGreHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 1);
//! assert_eq!(header.call_id(), 42);
//! assert_eq!(header.payload_length(), 16);
//! assert_eq!(header.sequence_number().unwrap(), 1);
//! ```
//!
//! ## PPTP GRE with acknowledgment
//!
//! ```
//! use packet_strata::packet::tunnel::pptp::PptpGreHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // PPTP GRE packet with sequence and acknowledgment
//! let packet = vec![
//!     0x30, 0x81,  // flags_version (K + S + A, version 1)
//!     0x88, 0x0B,  // protocol_type (PPP)
//!     0x00, 0x08,  // payload_length = 8
//!     0x00, 0x01,  // call_id = 1
//!     0x00, 0x00, 0x00, 0x05,  // sequence_number = 5
//!     0x00, 0x00, 0x00, 0x04,  // acknowledgment_number = 4
//!     // ... PPP payload follows ...
//! ];
//!
//! let (header, _) = PptpGreHeader::from_bytes(&packet).unwrap();
//! assert!(header.has_sequence());
//! assert!(header.has_ack());
//! assert_eq!(header.sequence_number().unwrap(), 5);
//! assert_eq!(header.acknowledgment_number().unwrap(), 4);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// PPTP GRE Protocol Type (PPP)
pub const PPTP_PROTOCOL_PPP: u16 = 0x880B;

/// PPTP GRE Header structure as defined in RFC 2637
///
/// This is the fixed portion of the Enhanced GRE header used by PPTP.
/// The header always includes the Key field (split into Payload Length and Call ID).
///
/// Minimum header format (8 bytes):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |C|R|K|S|s|Recur|A| Flags | Ver |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |           Call ID             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct PptpGreHeader {
    flags_version: U16<BigEndian>,
    protocol_type: U16<BigEndian>,
    payload_length: U16<BigEndian>,
    call_id: U16<BigEndian>,
}

impl PptpGreHeader {
    // GRE Flags (in the high byte of flags_version)
    pub const FLAG_CHECKSUM: u16 = 0x8000; // Checksum Present (C bit) - MUST be 0 for PPTP
    pub const FLAG_ROUTING: u16 = 0x4000; // Routing Present (R bit) - MUST be 0 for PPTP
    pub const FLAG_KEY: u16 = 0x2000; // Key Present (K bit) - MUST be 1 for PPTP
    pub const FLAG_SEQUENCE: u16 = 0x1000; // Sequence Number Present (S bit)
    pub const FLAG_STRICT_ROUTE: u16 = 0x0800; // Strict Source Route (s bit) - MUST be 0
    pub const FLAG_ACK: u16 = 0x0080; // Acknowledgment Present (A bit)

    pub const VERSION_MASK: u16 = 0x0007; // Version field (bits 13-15)
    pub const RECUR_MASK: u16 = 0x0700; // Recursion control (bits 5-7) - MUST be 0
    pub const FLAGS_MASK: u16 = 0x0078; // Reserved flags (bits 8-11) - MUST be 0

    pub const VERSION_PPTP: u16 = 0x0001; // Enhanced GRE version (RFC 2637 - PPTP)

    #[allow(unused)]
    const NAME: &'static str = "PptpGreHeader";

    /// Returns the flags and version field
    #[inline]
    pub fn flags_version(&self) -> u16 {
        self.flags_version.get()
    }

    /// Returns the GRE version number (should be 1 for PPTP)
    #[inline]
    pub fn version(&self) -> u8 {
        (self.flags_version() & Self::VERSION_MASK) as u8
    }

    /// Returns the protocol type field (typically 0x880B for PPP)
    #[inline]
    pub fn protocol_type(&self) -> EtherProto {
        self.protocol_type.get().into()
    }

    /// Returns the payload length (size of the PPP payload, not including GRE header)
    #[inline]
    pub fn payload_length(&self) -> u16 {
        self.payload_length.get()
    }

    /// Returns the Call ID used to identify the PPTP session
    #[inline]
    pub fn call_id(&self) -> u16 {
        self.call_id.get()
    }

    /// Check if Checksum Present flag is set (should be 0 for PPTP)
    #[inline]
    pub fn has_checksum(&self) -> bool {
        self.flags_version() & Self::FLAG_CHECKSUM != 0
    }

    /// Check if Routing Present flag is set (should be 0 for PPTP)
    #[inline]
    pub fn has_routing(&self) -> bool {
        self.flags_version() & Self::FLAG_ROUTING != 0
    }

    /// Check if Key Present flag is set (should always be 1 for PPTP)
    #[inline]
    pub fn has_key(&self) -> bool {
        self.flags_version() & Self::FLAG_KEY != 0
    }

    /// Check if Sequence Number Present flag is set
    #[inline]
    pub fn has_sequence(&self) -> bool {
        self.flags_version() & Self::FLAG_SEQUENCE != 0
    }

    /// Check if Strict Source Route flag is set (should be 0 for PPTP)
    #[inline]
    pub fn has_strict_route(&self) -> bool {
        self.flags_version() & Self::FLAG_STRICT_ROUTE != 0
    }

    /// Check if Acknowledgment flag is set
    #[inline]
    pub fn has_ack(&self) -> bool {
        self.flags_version() & Self::FLAG_ACK != 0
    }

    /// Returns the recursion control value (should be 0 for PPTP)
    #[inline]
    pub fn recursion_control(&self) -> u8 {
        ((self.flags_version() & Self::RECUR_MASK) >> 8) as u8
    }

    /// Validates the PPTP GRE header according to RFC 2637
    #[inline]
    fn is_valid(&self) -> bool {
        // Version MUST be 1
        if self.version() != 1 {
            return false;
        }

        // Key flag MUST be set
        if !self.has_key() {
            return false;
        }

        // Checksum flag MUST NOT be set
        if self.has_checksum() {
            return false;
        }

        // Routing flag MUST NOT be set
        if self.has_routing() {
            return false;
        }

        // Strict Source Route flag MUST NOT be set
        if self.has_strict_route() {
            return false;
        }

        // Recursion control MUST be 0
        if self.recursion_control() != 0 {
            return false;
        }

        // Reserved flags MUST be 0
        let reserved = self.flags_version() & Self::FLAGS_MASK;
        if reserved != 0 {
            return false;
        }

        true
    }

    /// Calculate the total header length including optional fields
    #[inline]
    pub fn header_length(&self) -> usize {
        let mut len = Self::FIXED_LEN; // 8 bytes for PPTP GRE fixed header

        // Add 4 bytes for sequence number (if present)
        if self.has_sequence() {
            len += 4;
        }

        // Add 4 bytes for acknowledgment number (if present)
        if self.has_ack() {
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

/// PPTP GRE Header with optional fields parsed
#[derive(Debug, Clone)]
pub struct PptpGreHeaderOpt<'a> {
    pub header: &'a PptpGreHeader,
    pub raw_options: &'a [u8],
}

impl<'a> PptpGreHeaderOpt<'a> {
    /// Get the sequence number if present
    pub fn sequence_number(&self) -> Option<u32> {
        if !self.header.has_sequence() {
            return None;
        }

        if self.raw_options.len() < 4 {
            return None;
        }

        let seq_bytes = &self.raw_options[0..4];
        Some(u32::from_be_bytes([
            seq_bytes[0],
            seq_bytes[1],
            seq_bytes[2],
            seq_bytes[3],
        ]))
    }

    /// Get the acknowledgment number if present
    pub fn acknowledgment_number(&self) -> Option<u32> {
        if !self.header.has_ack() {
            return None;
        }

        let mut offset = 0;
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

impl std::ops::Deref for PptpGreHeaderOpt<'_> {
    type Target = PptpGreHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for PptpGreHeader {
    const NAME: &'static str = "PptpGreHeader";
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

    /// Validates the PPTP GRE header
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for PptpGreHeader {
    type Output<'a> = PptpGreHeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, raw_options: &'a [u8]) -> Self::Output<'a> {
        PptpGreHeaderOpt {
            header,
            raw_options,
        }
    }
}

impl fmt::Display for PptpGreHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PPTP-GRE v{} proto={}(0x{:04x}) call_id={} payload_len={} flags={}",
            self.version(),
            self.protocol_type(),
            self.protocol_type().0,
            self.call_id(),
            self.payload_length(),
            self.flags_string()
        )
    }
}

impl fmt::Display for PptpGreHeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PPTP-GRE v{} proto={} call_id={} payload_len={} flags={}",
            self.version(),
            self.protocol_type(),
            self.call_id(),
            self.payload_length(),
            self.flags_string()
        )?;

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
    fn test_pptp_gre_header_size() {
        assert_eq!(std::mem::size_of::<PptpGreHeader>(), 8);
        assert_eq!(PptpGreHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_pptp_gre_basic_header() {
        let header = PptpGreHeader {
            flags_version: U16::new(0x2001), // Key present, version 1
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(100),
            call_id: U16::new(42),
        };

        assert_eq!(header.version(), 1);
        assert_eq!(header.protocol_type().0.get(), PPTP_PROTOCOL_PPP);
        assert!(header.has_key());
        assert!(!header.has_checksum());
        assert!(!header.has_sequence());
        assert!(!header.has_ack());
        assert!(header.is_valid());
        assert_eq!(header.header_length(), 8);
        assert_eq!(header.payload_length(), 100);
        assert_eq!(header.call_id(), 42);
    }

    #[test]
    fn test_pptp_gre_with_sequence() {
        let header = PptpGreHeader {
            flags_version: U16::new(0x3001), // Key + Sequence, version 1
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(50),
            call_id: U16::new(1),
        };

        assert!(header.has_key());
        assert!(header.has_sequence());
        assert!(!header.has_ack());
        assert!(header.is_valid());
        assert_eq!(header.header_length(), 12); // 8 + 4 for sequence
    }

    #[test]
    fn test_pptp_gre_with_ack() {
        let header = PptpGreHeader {
            flags_version: U16::new(0x2081), // Key + Ack, version 1
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };

        assert!(header.has_key());
        assert!(!header.has_sequence());
        assert!(header.has_ack());
        assert!(header.is_valid());
        assert_eq!(header.header_length(), 12); // 8 + 4 for ack
    }

    #[test]
    fn test_pptp_gre_with_sequence_and_ack() {
        let header = PptpGreHeader {
            flags_version: U16::new(0x3081), // Key + Sequence + Ack, version 1
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(64),
            call_id: U16::new(100),
        };

        assert!(header.has_key());
        assert!(header.has_sequence());
        assert!(header.has_ack());
        assert!(header.is_valid());
        assert_eq!(header.header_length(), 16); // 8 + 4 + 4
    }

    #[test]
    fn test_pptp_gre_version_validation() {
        // Invalid: version 0
        let header_v0 = PptpGreHeader {
            flags_version: U16::new(0x2000), // Key present, but version 0
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert!(!header_v0.is_valid());

        // Invalid: version 2
        let header_v2 = PptpGreHeader {
            flags_version: U16::new(0x2002), // Key present, but version 2
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert!(!header_v2.is_valid());
    }

    #[test]
    fn test_pptp_gre_key_flag_required() {
        // Invalid: Key flag not set
        let header = PptpGreHeader {
            flags_version: U16::new(0x0001), // version 1, but no key
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert!(!header.is_valid());
    }

    #[test]
    fn test_pptp_gre_checksum_forbidden() {
        // Invalid: Checksum flag set
        let header = PptpGreHeader {
            flags_version: U16::new(0xA001), // Key + Checksum, version 1
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert!(!header.is_valid());
    }

    #[test]
    fn test_pptp_gre_routing_forbidden() {
        // Invalid: Routing flag set
        let header = PptpGreHeader {
            flags_version: U16::new(0x6001), // Key + Routing, version 1
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert!(!header.is_valid());
    }

    #[test]
    fn test_pptp_gre_parsing_basic() {
        let mut packet = Vec::new();

        // PPTP GRE header: Key present, version 1
        packet.extend_from_slice(&0x2001u16.to_be_bytes()); // flags_version
        packet.extend_from_slice(&PPTP_PROTOCOL_PPP.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x0007u16.to_be_bytes()); // payload_length
        packet.extend_from_slice(&0x002Au16.to_be_bytes()); // call_id = 42

        // Add some payload
        packet.extend_from_slice(b"payload");

        let result = PptpGreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.version(), 1);
        assert_eq!(header.call_id(), 42);
        assert_eq!(header.payload_length(), 7);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn test_pptp_gre_parsing_with_sequence() {
        let mut packet = Vec::new();

        // PPTP GRE header with sequence
        packet.extend_from_slice(&0x3001u16.to_be_bytes()); // flags_version (K + S, v1)
        packet.extend_from_slice(&PPTP_PROTOCOL_PPP.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x0004u16.to_be_bytes()); // payload_length
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // call_id
        packet.extend_from_slice(&0x12345678u32.to_be_bytes()); // sequence_number

        // Add payload
        packet.extend_from_slice(b"test");

        let result = PptpGreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert!(header.has_sequence());
        assert_eq!(header.sequence_number().unwrap(), 0x12345678);
        assert_eq!(payload, b"test");
    }

    #[test]
    fn test_pptp_gre_parsing_with_ack() {
        let mut packet = Vec::new();

        // PPTP GRE header with ack
        packet.extend_from_slice(&0x2081u16.to_be_bytes()); // flags_version (K + A, v1)
        packet.extend_from_slice(&PPTP_PROTOCOL_PPP.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // payload_length = 0 (ack-only packet)
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // call_id
        packet.extend_from_slice(&0x00000005u32.to_be_bytes()); // acknowledgment_number

        let result = PptpGreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert!(header.has_ack());
        assert!(!header.has_sequence());
        assert_eq!(header.acknowledgment_number().unwrap(), 5);
    }

    #[test]
    fn test_pptp_gre_parsing_with_sequence_and_ack() {
        let mut packet = Vec::new();

        // PPTP GRE header with sequence and ack
        packet.extend_from_slice(&0x3081u16.to_be_bytes()); // flags_version (K + S + A, v1)
        packet.extend_from_slice(&PPTP_PROTOCOL_PPP.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x0008u16.to_be_bytes()); // payload_length
        packet.extend_from_slice(&0x0064u16.to_be_bytes()); // call_id = 100
        packet.extend_from_slice(&0x00000010u32.to_be_bytes()); // sequence_number = 16
        packet.extend_from_slice(&0x0000000Fu32.to_be_bytes()); // acknowledgment_number = 15

        // Add payload
        packet.extend_from_slice(&[0u8; 8]);

        let result = PptpGreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert!(header.has_sequence());
        assert!(header.has_ack());
        assert_eq!(header.call_id(), 100);
        assert_eq!(header.sequence_number().unwrap(), 16);
        assert_eq!(header.acknowledgment_number().unwrap(), 15);
    }

    #[test]
    fn test_pptp_gre_parsing_too_small() {
        let packet = vec![0u8; 7]; // Only 7 bytes, need 8

        let result = PptpGreHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_pptp_gre_parsing_invalid_version() {
        let mut packet = Vec::new();

        // Invalid: version 0
        packet.extend_from_slice(&0x2000u16.to_be_bytes()); // flags_version (K, v0)
        packet.extend_from_slice(&PPTP_PROTOCOL_PPP.to_be_bytes());
        packet.extend_from_slice(&0x0000u16.to_be_bytes());
        packet.extend_from_slice(&0x0001u16.to_be_bytes());

        let result = PptpGreHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_pptp_gre_flags_string() {
        let header1 = PptpGreHeader {
            flags_version: U16::new(0x2001), // K only
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert_eq!(header1.flags_string(), "K");

        let header2 = PptpGreHeader {
            flags_version: U16::new(0x3001), // K + S
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert_eq!(header2.flags_string(), "KS");

        let header3 = PptpGreHeader {
            flags_version: U16::new(0x3081), // K + S + A
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert_eq!(header3.flags_string(), "KSA");
    }

    #[test]
    fn test_pptp_gre_header_length_calculation() {
        // No optional fields (just K)
        let h1 = PptpGreHeader {
            flags_version: U16::new(0x2001),
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert_eq!(h1.header_length(), 8);

        // With sequence
        let h2 = PptpGreHeader {
            flags_version: U16::new(0x3001),
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert_eq!(h2.header_length(), 12);

        // With ack
        let h3 = PptpGreHeader {
            flags_version: U16::new(0x2081),
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert_eq!(h3.header_length(), 12);

        // With sequence and ack
        let h4 = PptpGreHeader {
            flags_version: U16::new(0x3081),
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(0),
            call_id: U16::new(1),
        };
        assert_eq!(h4.header_length(), 16);
    }

    #[test]
    fn test_pptp_gre_display() {
        let header = PptpGreHeader {
            flags_version: U16::new(0x3081),
            protocol_type: U16::new(PPTP_PROTOCOL_PPP),
            payload_length: U16::new(100),
            call_id: U16::new(42),
        };

        let display = format!("{}", header);
        assert!(display.contains("PPTP-GRE"));
        assert!(display.contains("call_id=42"));
        assert!(display.contains("payload_len=100"));
    }

    #[test]
    fn test_pptp_gre_ack_only_packet() {
        // ACK-only packets are common in PPTP for flow control
        let mut packet = Vec::new();

        packet.extend_from_slice(&0x2081u16.to_be_bytes()); // K + A, v1
        packet.extend_from_slice(&PPTP_PROTOCOL_PPP.to_be_bytes());
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // payload_length = 0
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // call_id
        packet.extend_from_slice(&0x00000042u32.to_be_bytes()); // ack number

        let result = PptpGreHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.payload_length(), 0);
        assert!(header.has_ack());
        assert!(!header.has_sequence());
        assert_eq!(header.acknowledgment_number().unwrap(), 0x42);
        assert!(payload.is_empty());
    }
}
