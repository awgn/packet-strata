//! Geneve (Generic Network Virtualization Encapsulation) protocol parser
//!
//! This module implements parsing for Geneve tunnels as defined in RFC 8926.
//! Geneve provides a flexible encapsulation format for network virtualization
//! that supports variable-length options.
//!
//! # Geneve Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Virtual Network Identifier (VNI)       |    Reserved   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! ~                    Variable-Length Options                    ~
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - UDP destination port: 6081 (IANA assigned)
//! - VNI (Virtual Network Identifier): 24 bits
//! - Variable-length options: 0-252 bytes (in 4-byte multiples)
//! - Version: must be 0
//! - Typically encapsulates Ethernet frames (protocol type 0x6558)
//!
//! # Examples
//!
//! ## Basic Geneve parsing (no options)
//!
//! ```
//! use packet_strata::packet::tunnel::geneve::GeneveHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::{HeaderParser, PacketHeader};
//!
//! // Geneve packet with VNI = 100, no options
//! let packet = vec![
//!     0x00, 0x00, 0x65, 0x58,  // Ver=0, OptLen=0, O=0, C=0, Proto=TEB
//!     0x00, 0x00, 0x64, 0x00,  // VNI = 100, Reserved
//!     // ... Ethernet frame follows ...
//! ];
//!
//! let (header, payload) = GeneveHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 0);
//! assert_eq!(header.vni(), 100);
//! assert_eq!(header.options_length(), 0);
//! assert_eq!(header.protocol_type(), EtherProto::TEB);
//! ```
//!
//! ## Geneve with options
//!
//! ```
//! use packet_strata::packet::tunnel::geneve::GeneveHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // Geneve with 8 bytes of options
//! let packet = vec![
//!     0x02, 0x00, 0x65, 0x58,  // Ver=0, OptLen=2 (8 bytes), Proto=TEB
//!     0x00, 0x01, 0x00, 0x00,  // VNI = 256, Reserved
//!     // Options (8 bytes)
//!     0x00, 0x01, 0x80, 0x01,  // Option: Class=1, Type=0x80, Len=1
//!     0x12, 0x34, 0x56, 0x78,  // Option data
//!     // ... Ethernet frame follows ...
//! ];
//!
//! let (header, _) = GeneveHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.options_length(), 8);
//! assert_eq!(header.vni(), 256);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// Geneve UDP destination port (IANA assigned)
pub const GENEVE_PORT: u16 = 6081;

/// Maximum VNI value (24-bit field)
pub const GENEVE_MAX_VNI: u32 = 0xFFFFFF;

/// Maximum options length in bytes (63 * 4 = 252)
pub const GENEVE_MAX_OPTIONS_LEN: usize = 252;

/// Geneve version (must be 0)
pub const GENEVE_VERSION: u8 = 0;

/// Geneve Header structure as defined in RFC 8926
///
/// The fixed Geneve header is 8 bytes. Variable-length options may follow.
///
/// Header format (8 bytes fixed):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Virtual Network Identifier (VNI)       |    Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, KnownLayout, Immutable)]
pub struct GeneveHeader {
    ver_optlen_flags: U16<BigEndian>,
    protocol_type: U16<BigEndian>,
    vni_reserved: U32<BigEndian>,
}

impl GeneveHeader {
    // Field masks and shifts
    const VERSION_MASK: u16 = 0xC000;
    const VERSION_SHIFT: u16 = 14;
    const OPTLEN_MASK: u16 = 0x3F00;
    const OPTLEN_SHIFT: u16 = 8;
    const FLAG_O_MASK: u16 = 0x0080;
    const FLAG_C_MASK: u16 = 0x0040;
    const RESERVED_MASK: u16 = 0x003F;

    const VNI_MASK: u32 = 0xFFFFFF00;
    const VNI_SHIFT: u32 = 8;
    const VNI_RESERVED_MASK: u32 = 0x000000FF;

    #[allow(unused)]
    const NAME: &'static str = "GeneveHeader";

    /// Returns the version field (2 bits, must be 0)
    #[inline]
    pub fn version(&self) -> u8 {
        ((self.ver_optlen_flags.get() & Self::VERSION_MASK) >> Self::VERSION_SHIFT) as u8
    }

    /// Returns the options length in 4-byte units (6 bits)
    #[inline]
    pub fn options_length_units(&self) -> u8 {
        ((self.ver_optlen_flags.get() & Self::OPTLEN_MASK) >> Self::OPTLEN_SHIFT) as u8
    }

    /// Returns the options length in bytes
    #[inline]
    pub fn options_length(&self) -> usize {
        self.options_length_units() as usize * 4
    }

    /// Check if the O (OAM) flag is set
    ///
    /// When set, indicates this is an OAM (Operations, Administration, and Maintenance) frame.
    #[inline]
    pub fn is_oam(&self) -> bool {
        self.ver_optlen_flags.get() & Self::FLAG_O_MASK != 0
    }

    /// Check if the C (Critical) flag is set
    ///
    /// When set, indicates that critical options are present that must be understood.
    #[inline]
    pub fn is_critical(&self) -> bool {
        self.ver_optlen_flags.get() & Self::FLAG_C_MASK != 0
    }

    /// Returns the reserved bits in the first word (should be 0)
    #[inline]
    pub fn reserved_flags(&self) -> u8 {
        (self.ver_optlen_flags.get() & Self::RESERVED_MASK) as u8
    }

    /// Returns the protocol type field
    ///
    /// Typically 0x6558 (TEB - Transparent Ethernet Bridging) for Ethernet frames.
    #[inline]
    pub fn protocol_type(&self) -> EtherProto {
        self.protocol_type.get().into()
    }

    /// Returns the raw protocol type value
    #[inline]
    pub fn protocol_type_raw(&self) -> u16 {
        self.protocol_type.get()
    }

    /// Returns the Virtual Network Identifier (VNI) - 24 bits
    #[inline]
    pub fn vni(&self) -> u32 {
        (self.vni_reserved.get() & Self::VNI_MASK) >> Self::VNI_SHIFT
    }

    /// Returns the reserved byte after VNI (should be 0)
    #[inline]
    pub fn reserved_vni(&self) -> u8 {
        (self.vni_reserved.get() & Self::VNI_RESERVED_MASK) as u8
    }

    /// Returns the total header length including options
    #[inline]
    pub fn header_length(&self) -> usize {
        Self::FIXED_LEN + self.options_length()
    }

    /// Validates the Geneve header according to RFC 8926
    #[inline]
    fn is_valid(&self) -> bool {
        // Version must be 0
        if self.version() != GENEVE_VERSION {
            return false;
        }

        // Options length must not exceed maximum (63 units = 252 bytes)
        if self.options_length() > GENEVE_MAX_OPTIONS_LEN {
            return false;
        }

        true
    }

    /// Validates the Geneve header strictly
    ///
    /// Checks version, options length, and that reserved bits are 0.
    #[inline]
    pub fn is_valid_strict(&self) -> bool {
        self.is_valid() && self.reserved_flags() == 0 && self.reserved_vni() == 0
    }

    /// Returns a string representation of flags
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();

        if self.is_oam() {
            flags.push("O");
        }
        if self.is_critical() {
            flags.push("C");
        }

        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join("")
        }
    }
}

/// Geneve Header with options parsed
#[derive (Debug, Clone)]
pub struct GeneveHeaderOpt<'a> {
    pub header: &'a GeneveHeader,
    pub options: &'a [u8],
}

impl<'a> GeneveHeaderOpt<'a> {
    /// Returns an iterator over the Geneve options
    pub fn options_iter(&self) -> GeneveOptionsIter<'a> {
        GeneveOptionsIter {
            data: self.options,
            offset: 0,
        }
    }

    /// Check if there are any options
    #[inline]
    pub fn has_options(&self) -> bool {
        !self.options.is_empty()
    }
}

impl std::ops::Deref for GeneveHeaderOpt<'_> {
    type Target = GeneveHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for GeneveHeader {
    const NAME: &'static str = "GeneveHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.protocol_type()
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        self.header_length()
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for GeneveHeader {
    type Output<'a> = GeneveHeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, options: &'a [u8]) -> Self::Output<'a> {
        GeneveHeaderOpt { header, options }
    }
}

impl fmt::Display for GeneveHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Geneve v{} vni={} proto={}(0x{:04x}) opt_len={} flags={}",
            self.version(),
            self.vni(),
            self.protocol_type(),
            self.protocol_type().0,
            self.options_length(),
            self.flags_string()
        )
    }
}

impl fmt::Display for GeneveHeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Geneve v{} vni={} proto={} opt_len={} flags={}",
            self.version(),
            self.vni(),
            self.protocol_type(),
            self.options_length(),
            self.flags_string()
        )?;

        if self.has_options() {
            write!(f, " options={}", self.options_iter().count())?;
        }

        Ok(())
    }
}

/// Geneve Option header (4 bytes fixed + variable data)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Option Class         |      Type     |R|R|R| Length  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Variable-Length Option Data                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct GeneveOption<'a> {
    /// Option class (16 bits)
    pub option_class: u16,
    /// Option type (8 bits, high bit indicates critical)
    pub option_type: u8,
    /// Option data length in 4-byte units (5 bits)
    pub length_units: u8,
    /// Option data
    pub data: &'a [u8],
}

impl<'a> GeneveOption<'a> {
    /// Option header size in bytes
    pub const HEADER_SIZE: usize = 4;

    /// Check if this is a critical option (high bit of type set)
    #[inline]
    pub fn is_critical(&self) -> bool {
        self.option_type & 0x80 != 0
    }

    /// Returns the option type without the critical bit
    #[inline]
    pub fn type_value(&self) -> u8 {
        self.option_type & 0x7F
    }

    /// Returns the data length in bytes
    #[inline]
    pub fn data_length(&self) -> usize {
        self.length_units as usize * 4
    }

    /// Returns the total option length (header + data)
    #[inline]
    pub fn total_length(&self) -> usize {
        Self::HEADER_SIZE + self.data_length()
    }
}

impl fmt::Display for GeneveOption<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GeneveOpt class=0x{:04x} type=0x{:02x}{} len={}",
            self.option_class,
            self.option_type,
            if self.is_critical() { "(C)" } else { "" },
            self.data_length()
        )
    }
}

/// Iterator over Geneve options
pub struct GeneveOptionsIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for GeneveOptionsIter<'a> {
    type Item = GeneveOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + GeneveOption::HEADER_SIZE > self.data.len() {
            return None;
        }

        let option_class = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]]);
        let option_type = self.data[self.offset + 2];
        let length_byte = self.data[self.offset + 3];
        let length_units = length_byte & 0x1F; // 5 bits for length

        let data_len = length_units as usize * 4;
        let data_start = self.offset + GeneveOption::HEADER_SIZE;
        let data_end = data_start + data_len;

        if data_end > self.data.len() {
            return None;
        }

        let option = GeneveOption {
            option_class,
            option_type,
            length_units,
            data: &self.data[data_start..data_end],
        };

        self.offset = data_end;
        Some(option)
    }
}

/// Check if a UDP packet might be Geneve based on destination port
#[inline]
pub fn is_geneve_port(dst_port: u16) -> bool {
    dst_port == GENEVE_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_header_size() {
        assert_eq!(std::mem::size_of::<GeneveHeader>(), 8);
        assert_eq!(GeneveHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_geneve_basic_header() {
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x0000), // Ver=0, OptLen=0, O=0, C=0
            protocol_type: U16::new(0x6558),    // TEB
            vni_reserved: U32::new(0x00006400), // VNI = 100
        };

        assert_eq!(header.version(), 0);
        assert_eq!(header.options_length_units(), 0);
        assert_eq!(header.options_length(), 0);
        assert!(!header.is_oam());
        assert!(!header.is_critical());
        assert_eq!(header.protocol_type(), EtherProto::TEB);
        assert_eq!(header.vni(), 100);
        assert!(header.is_valid());
        assert!(header.is_valid_strict());
    }

    #[test]
    fn test_geneve_with_options() {
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x0200), // Ver=0, OptLen=2 (8 bytes)
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00010000), // VNI = 256
        };

        assert_eq!(header.version(), 0);
        assert_eq!(header.options_length_units(), 2);
        assert_eq!(header.options_length(), 8);
        assert_eq!(header.header_length(), 16); // 8 + 8
        assert_eq!(header.vni(), 256);
        assert!(header.is_valid());
    }

    #[test]
    fn test_geneve_flags() {
        // OAM flag set
        let header_oam = GeneveHeader {
            ver_optlen_flags: U16::new(0x0080), // O=1
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert!(header_oam.is_oam());
        assert!(!header_oam.is_critical());

        // Critical flag set
        let header_crit = GeneveHeader {
            ver_optlen_flags: U16::new(0x0040), // C=1
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert!(!header_crit.is_oam());
        assert!(header_crit.is_critical());

        // Both flags set
        let header_both = GeneveHeader {
            ver_optlen_flags: U16::new(0x00C0), // O=1, C=1
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert!(header_both.is_oam());
        assert!(header_both.is_critical());
    }

    #[test]
    fn test_geneve_vni_values() {
        // VNI = 0x123456
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x0000),
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x12345600),
        };

        assert_eq!(header.vni(), 0x123456);
    }

    #[test]
    fn test_geneve_max_vni() {
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x0000),
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0xFFFFFF00),
        };

        assert_eq!(header.vni(), GENEVE_MAX_VNI);
    }

    #[test]
    fn test_geneve_invalid_version() {
        // Version 1 (invalid)
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x4000), // Ver=1
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };

        assert_eq!(header.version(), 1);
        assert!(!header.is_valid());
    }

    #[test]
    fn test_geneve_parsing_basic() {
        let mut packet = Vec::new();

        // Geneve header: Ver=0, OptLen=0, Proto=TEB, VNI=100
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // ver_optlen_flags
        packet.extend_from_slice(&0x6558u16.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x00006400u32.to_be_bytes()); // vni_reserved

        // Payload
        packet.extend_from_slice(b"ethernet");

        let result = GeneveHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.version(), 0);
        assert_eq!(header.vni(), 100);
        assert_eq!(header.options_length(), 0);
        assert!(!header.has_options());
        assert_eq!(payload, b"ethernet");
    }

    #[test]
    fn test_geneve_parsing_with_options() {
        let mut packet = Vec::new();

        // Geneve header: Ver=0, OptLen=2 (8 bytes), Proto=TEB, VNI=256
        packet.extend_from_slice(&0x0200u16.to_be_bytes()); // ver_optlen_flags
        packet.extend_from_slice(&0x6558u16.to_be_bytes()); // protocol_type
        packet.extend_from_slice(&0x00010000u32.to_be_bytes()); // vni_reserved

        // Options (8 bytes)
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Option class
        packet.push(0x80); // Option type (critical)
        packet.push(0x01); // Length = 1 (4 bytes)
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // Option data

        // Payload
        packet.extend_from_slice(b"data");

        let result = GeneveHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.vni(), 256);
        assert_eq!(header.options_length(), 8);
        assert!(header.has_options());
        assert_eq!(payload, b"data");

        // Check options iterator
        let mut opts = header.options_iter();
        let opt1 = opts.next().unwrap();
        assert_eq!(opt1.option_class, 0x0001);
        assert_eq!(opt1.option_type, 0x80);
        assert!(opt1.is_critical());
        assert_eq!(opt1.data_length(), 4);
        assert_eq!(opt1.data, &[0x12, 0x34, 0x56, 0x78]);

        assert!(opts.next().is_none());
    }

    #[test]
    fn test_geneve_parsing_too_small() {
        let packet = vec![0u8; 7]; // Only 7 bytes, need 8

        let result = GeneveHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_geneve_parsing_invalid_version() {
        let mut packet = Vec::new();

        // Invalid version 1
        packet.extend_from_slice(&0x4000u16.to_be_bytes()); // Ver=1
        packet.extend_from_slice(&0x6558u16.to_be_bytes());
        packet.extend_from_slice(&0x00000000u32.to_be_bytes());

        let result = GeneveHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_geneve_inner_type() {
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x0000),
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00006400),
        };

        assert_eq!(header.inner_type(), EtherProto::TEB);
    }

    #[test]
    fn test_geneve_display() {
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x00C0), // O=1, C=1
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00006400),
        };

        let display = format!("{}", header);
        assert!(display.contains("Geneve"));
        assert!(display.contains("vni=100"));
        assert!(display.contains("OC"));
    }

    #[test]
    fn test_geneve_flags_string() {
        let header1 = GeneveHeader {
            ver_optlen_flags: U16::new(0x0000),
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(header1.flags_string(), "none");

        let header2 = GeneveHeader {
            ver_optlen_flags: U16::new(0x0080), // O
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(header2.flags_string(), "O");

        let header3 = GeneveHeader {
            ver_optlen_flags: U16::new(0x00C0), // O + C
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(header3.flags_string(), "OC");
    }

    #[test]
    fn test_geneve_port_check() {
        assert!(is_geneve_port(6081));
        assert!(!is_geneve_port(4789)); // VXLAN
        assert!(!is_geneve_port(80));
    }

    #[test]
    fn test_geneve_option_parsing() {
        let option_data = vec![
            0x00, 0x01, // Option class
            0x01, // Option type (not critical)
            0x02, // Length = 2 (8 bytes data)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Data
        ];

        let mut iter = GeneveOptionsIter {
            data: &option_data,
            offset: 0,
        };

        let opt = iter.next().unwrap();
        assert_eq!(opt.option_class, 0x0001);
        assert_eq!(opt.option_type, 0x01);
        assert!(!opt.is_critical());
        assert_eq!(opt.type_value(), 0x01);
        assert_eq!(opt.length_units, 2);
        assert_eq!(opt.data_length(), 8);
        assert_eq!(opt.total_length(), 12);
    }

    #[test]
    fn test_geneve_multiple_options() {
        let mut packet = Vec::new();

        // Geneve header with 16 bytes of options
        packet.extend_from_slice(&0x0400u16.to_be_bytes()); // OptLen=4 (16 bytes)
        packet.extend_from_slice(&0x6558u16.to_be_bytes());
        packet.extend_from_slice(&0x00000000u32.to_be_bytes());

        // Option 1: 8 bytes
        packet.extend_from_slice(&0x0001u16.to_be_bytes());
        packet.push(0x01);
        packet.push(0x01); // Len=1 (4 bytes)
        packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Option 2: 8 bytes
        packet.extend_from_slice(&0x0002u16.to_be_bytes());
        packet.push(0x82); // Critical
        packet.push(0x01);
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let (header, _) = GeneveHeader::from_bytes(&packet).unwrap();
        let opts: Vec<_> = header.options_iter().collect();

        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].option_class, 0x0001);
        assert!(!opts[0].is_critical());
        assert_eq!(opts[1].option_class, 0x0002);
        assert!(opts[1].is_critical());
    }

    #[test]
    fn test_geneve_max_options_length() {
        // Max options length is 63 units = 252 bytes
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x3F00), // OptLen=63
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };

        assert_eq!(header.options_length_units(), 63);
        assert_eq!(header.options_length(), 252);
        assert!(header.is_valid());
    }

    #[test]
    fn test_geneve_header_length_calculation() {
        // No options
        let h1 = GeneveHeader {
            ver_optlen_flags: U16::new(0x0000),
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(h1.header_length(), 8);

        // 8 bytes options
        let h2 = GeneveHeader {
            ver_optlen_flags: U16::new(0x0200),
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(h2.header_length(), 16);

        // Max options (252 bytes)
        let h3 = GeneveHeader {
            ver_optlen_flags: U16::new(0x3F00),
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x00000000),
        };
        assert_eq!(h3.header_length(), 260);
    }

    #[test]
    fn test_geneve_reserved_bits() {
        let header = GeneveHeader {
            ver_optlen_flags: U16::new(0x003F), // Reserved bits set
            protocol_type: U16::new(0x6558),
            vni_reserved: U32::new(0x000000FF), // VNI reserved byte set
        };

        assert_eq!(header.reserved_flags(), 0x3F);
        assert_eq!(header.reserved_vni(), 0xFF);
        assert!(header.is_valid()); // Basic validation passes
        assert!(!header.is_valid_strict()); // Strict fails
    }
}
