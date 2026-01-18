//! IPv4 (Internet Protocol version 4) packet parser
//!
//! This module implements parsing for IPv4 packets as defined in RFC 791.
//! IPv4 is the fourth version of the Internet Protocol and the first version
//! to be widely deployed.
//!
//! # IPv4 Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version|  IHL  |    DSCP   |ECN|          Total Length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Identification        |Flags|      Fragment Offset    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Time to Live |    Protocol   |         Header Checksum       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Source Address                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Destination Address                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Options (if IHL > 5)                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Version: 4 (always)
//! - IHL: Internet Header Length in 32-bit words (minimum 5, maximum 15)
//! - Minimum header size: 20 bytes (IHL = 5)
//! - Maximum header size: 60 bytes (IHL = 15)
//!
//! # Examples
//!
//! ## Basic IPv4 parsing
//!
//! ```
//! use packet_strata::packet::ipv4::Ipv4Header;
//! use packet_strata::packet::protocol::IpProto;
//! use packet_strata::packet::HeaderParser;
//! use std::net::Ipv4Addr;
//!
//! // IPv4 packet with TCP payload
//! let packet = vec![
//!     0x45,              // Version=4, IHL=5 (20 bytes)
//!     0x00,              // DSCP=0, ECN=0
//!     0x00, 0x28,        // Total length: 40 bytes
//!     0x1c, 0x46,        // Identification
//!     0x40, 0x00,        // Flags=DF, Fragment offset=0
//!     0x40,              // TTL: 64
//!     0x06,              // Protocol: TCP (6)
//!     0x00, 0x00,        // Checksum (not validated here)
//!     0xC0, 0xA8, 0x01, 0x01,  // Source: 192.168.1.1
//!     0xC0, 0xA8, 0x01, 0x02,  // Destination: 192.168.1.2
//!     // TCP payload follows...
//! ];
//!
//! let (header, payload) = Ipv4Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 4);
//! assert_eq!(header.ihl(), 5);
//! assert_eq!(header.ttl(), 64);
//! assert_eq!(header.protocol(), IpProto::TCP);
//! assert_eq!(header.src_ip(), Ipv4Addr::new(192, 168, 1, 1));
//! assert_eq!(header.dst_ip(), Ipv4Addr::new(192, 168, 1, 2));
//! ```
//!
//! ## IPv4 with options
//!
//! ```
//! use packet_strata::packet::ipv4::Ipv4Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // IPv4 packet with options (IHL=6, 24 bytes header)
//! let packet = vec![
//!     0x46,              // Version=4, IHL=6 (24 bytes)
//!     0x00,              // DSCP=0, ECN=0
//!     0x00, 0x20,        // Total length: 32 bytes
//!     0x00, 0x01,        // Identification
//!     0x00, 0x00,        // Flags=0, Fragment offset=0
//!     0x40,              // TTL: 64
//!     0x01,              // Protocol: ICMP (1)
//!     0x00, 0x00,        // Checksum
//!     0x0A, 0x00, 0x00, 0x01,  // Source: 10.0.0.1
//!     0x0A, 0x00, 0x00, 0x02,  // Destination: 10.0.0.2
//!     0x01, 0x01, 0x01, 0x00,  // Options (NOP, NOP, NOP, EOL)
//!     // Payload follows...
//! ];
//!
//! let (header, payload) = Ipv4Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.ihl(), 6);
//! assert_eq!(header.ihl() as usize * 4, 24);  // Header length in bytes
//! assert!(header.has_options());
//! ```

pub mod opt;

use std::fmt::{self, Formatter};
use std::net::Ipv4Addr;
use std::ops::Deref;

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::ipv4::opt::Ipv4OptionsIter;
use crate::packet::protocol::IpProto;
use crate::packet::{HeaderParser, PacketHeader};

/// IPv4 Header structure as defined in RFC 791
///
/// The fixed portion of the IPv4 header is 20 bytes. Additional options
/// may be present if IHL > 5.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct Ipv4Header {
    ver_ihl: u8,
    dscp_ecn: u8,
    total_length: U16<BigEndian>,
    identification: U16<BigEndian>,
    flags_frag_offset: U16<BigEndian>,
    ttl: u8,
    protocol: IpProto,
    checksum: U16<BigEndian>,
    src_ip: U32<BigEndian>,
    dst_ip: U32<BigEndian>,
}

impl Ipv4Header {
    #[inline]
    pub fn dscp(&self) -> u8 {
        self.dscp_ecn >> 2
    }

    #[inline]
    pub fn ecn(&self) -> u8 {
        self.dscp_ecn & 0x03
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.ver_ihl >> 4
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        self.ver_ihl & 0x0F
    }

    const OFFSET_MASK: u16 = 0x1FFF;
    const MF_FLAG_MASK: u16 = 0x2000;
    const DF_FLAG_MASK: u16 = 0x4000;
    const RS_FLAG_MASK: u16 = 0x8000;

    #[inline]
    pub fn flags(&self) -> u8 {
        (self.flags_frag_offset.get() >> 13) as u8
    }

    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        self.flags_frag_offset.get() & Self::OFFSET_MASK
    }

    #[inline]
    pub fn has_dont_fragment(&self) -> bool {
        // Check bit 14 directly (0x4000)
        (self.flags_frag_offset.get() & Self::DF_FLAG_MASK) != 0
    }

    #[inline]
    pub fn has_more_fragment(&self) -> bool {
        // Check bit 14 directly (0x4000)
        (self.flags_frag_offset.get() & Self::MF_FLAG_MASK) != 0
    }

    #[inline]
    pub fn has_reserved_flag(&self) -> bool {
        (self.flags_frag_offset.get() & Self::RS_FLAG_MASK) != 0
    }

    #[inline]
    pub fn is_fragmenting(&self) -> bool {
        // A packet is a fragment if MF is set (0x2000) OR offset is non-zero (0x1FFF).
        (self.flags_frag_offset.get() & Self::MF_FLAG_MASK | Self::OFFSET_MASK) != 0
    }

    #[inline]
    pub fn is_first_fragment(&self) -> bool {
        // First fragment: MF set AND offset is 0
        let raw = self.flags_frag_offset.get();
        (raw & Self::MF_FLAG_MASK) != 0 && (raw & Self::OFFSET_MASK) == 0
    }

    #[inline]
    pub fn is_last_fragment(&self) -> bool {
        // Last fragment: MF NOT set AND offset > 0
        let raw = self.flags_frag_offset.get();
        (raw & Self::MF_FLAG_MASK) == 0 && (raw & Self::OFFSET_MASK) != 0
    }

    #[inline]
    pub fn total_length(&self) -> usize {
        self.total_length.get() as usize
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    #[inline]
    pub fn protocol(&self) -> IpProto {
        self.protocol
    }

    #[inline]
    pub fn src_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src_ip.get())
    }

    #[inline]
    pub fn dst_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst_ip.get())
    }

    #[inline]
    pub fn src_ip_raw(&self) -> [u8; 4] {
        self.src_ip.get().to_be_bytes()
    }

    #[inline]
    pub fn dst_ip_raw(&self) -> [u8; 4] {
        self.dst_ip.get().to_be_bytes()
    }

    /// Returns the options slice if present
    /// Options length = (ihl * 4) - 20
    #[inline]
    pub fn has_options(&self) -> bool {
        self.ihl() > 5
    }

    #[inline]
    pub fn id(&self) -> u16 {
        self.identification.get()
    }
}

/// IPv4 Header with options
#[derive(Debug, Clone)]
pub struct Ipv4HeaderOpt<'a> {
    pub header: &'a Ipv4Header,
    pub raw_options: &'a [u8],
}

impl<'a> Ipv4HeaderOpt<'a> {
    /// Get IPv4 options iterator
    pub fn options(&'a self) -> Ipv4OptionsIter<'a> {
        Ipv4OptionsIter::new(self.raw_options)
    }
}

impl Deref for Ipv4HeaderOpt<'_> {
    type Target = Ipv4Header;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for Ipv4Header {
    const NAME: &'static str = "IPv4Header";
    type InnerType = IpProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.protocol
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        (self.ihl() as usize) * 4
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.version() == 4 && self.ihl() >= 5
    }
}

impl HeaderParser for Ipv4Header {
    type Output<'a> = Ipv4HeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, raw_options: &'a [u8]) -> Self::Output<'a> {
        Ipv4HeaderOpt {
            header,
            raw_options,
        }
    }
}

impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 {} -> {} proto={} ttl={} len={}",
            self.src_ip(),
            self.dst_ip(),
            self.protocol(),
            self.ttl(),
            self.total_length()
        )?;

        if self.is_fragmenting() {
            write!(f, " frag offset={}", self.fragment_offset())?;
        }

        if self.has_options() {
            write!(f, " +opts")?;
        }

        Ok(())
    }
}

impl fmt::Display for Ipv4HeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)?;

        if !self.raw_options.is_empty() {
            write!(f, " opts=[")?;
            let mut first = true;
            for opt in self.options().flatten() {
                if !first {
                    write!(f, ",")?;
                }
                first = false;
                write!(f, "{}", opt)?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

mod tests {
    use super::*;
    #[test]
    fn test_ipv4_header_size() {
        assert_eq!(std::mem::size_of::<Ipv4Header>(), 20);
        assert_eq!(Ipv4Header::FIXED_LEN, 20);
    }

    #[test]
    fn test_ipv4_version_and_ihl() {
        let header = create_test_header();
        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5); // 5 * 4 = 20 bytes (no options)
        assert!(header.is_valid());
    }

    #[test]
    fn test_ipv4_dscp_ecn() {
        let mut header = create_test_header();

        // DSCP = 0x2E (46), ECN = 0x01
        header.dscp_ecn = 0xB9; // 10111001 in binary
        assert_eq!(header.dscp(), 46);
        assert_eq!(header.ecn(), 1);
    }

    #[test]
    fn test_ipv4_total_length() {
        let mut header = create_test_header();
        header.total_length = U16::new(1500);
        assert_eq!(header.total_length(), 1500);
    }

    #[test]
    fn test_ipv4_fragmentation() {
        let mut header = create_test_header();

        // No fragmentation
        header.flags_frag_offset = U16::new(0x4000); // Don't Fragment flag
        assert_eq!(header.flags(), 0x02);
        assert_eq!(header.fragment_offset(), 0);
        assert!(!header.is_fragmented());

        // With fragmentation: offset = 185 (0x00B9), More Fragments flag
        header.flags_frag_offset = U16::new(0x20B9);
        assert_eq!(header.flags(), 0x01); // More Fragments
        assert_eq!(header.fragment_offset(), 185);
        assert!(header.is_fragmented());
    }

    #[test]
    fn test_ipv4_addresses() {
        let header = create_test_header();

        // Test source address: 192.168.1.100
        let expected_src = Ipv4Addr::new(192, 168, 1, 100);
        assert_eq!(header.src_ip(), expected_src);
        assert_eq!(header.src_ip_raw(), [192, 168, 1, 100]);

        // Test destination address: 10.0.0.1
        let expected_dst = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(header.dst_ip(), expected_dst);
        assert_eq!(header.dst_ip_raw(), [10, 0, 0, 1]);
    }

    #[test]
    fn test_ipv4_protocol_ttl() {
        let header = create_test_header();
        assert_eq!(header.protocol(), IpProto::TCP);
        assert_eq!(header.ttl(), 64);
    }

    #[test]
    fn test_ipv4_parsing_basic() {
        let packet = create_test_packet();

        let result = Ipv4Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header_ext, payload) = result.unwrap();
        assert_eq!(header_ext.version(), 4);
        assert_eq!(header_ext.ihl(), 5);
        assert_eq!(header_ext.protocol(), IpProto::TCP);
        assert!(!header_ext.has_options());
        assert_eq!(header_ext.raw_options.len(), 0);
        assert_eq!(payload.len(), 0); // No payload in test packet
    }

    #[test]
    fn test_ipv4_parsing_invalid_version() {
        let mut packet = create_test_packet();
        packet[0] = 0x60; // Version 6 instead of 4

        let result = Ipv4Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_parsing_invalid_ihl() {
        let mut packet = create_test_packet();
        packet[0] = 0x44; // IHL = 4, which is invalid (minimum is 5)

        let result = Ipv4Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_parsing_too_small() {
        let packet = vec![0u8; 19]; // Only 19 bytes, need 20

        let result = Ipv4Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_total_len_no_options() {
        let packet = create_test_packet();
        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        // No options, should return 20 bytes
        assert_eq!(header_ext.total_len(&packet), 20);
        assert_eq!(header_ext.raw_options.len(), 0);
    }

    #[test]
    fn test_ipv4_with_options() {
        let mut packet = create_test_packet();

        // Change IHL to 6 (6 * 4 = 24 bytes header with 4 bytes of options)
        packet[0] = 0x46; // Version 4, IHL 6

        // Add 4 bytes of options (NOP padding)
        packet.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // 4x NOP

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        // Verify header length includes options
        assert_eq!(header_ext.ihl(), 6);
        assert_eq!(header_ext.total_len(&packet), 24); // 6 * 4 = 24 bytes
        assert!(header_ext.is_valid());
        assert!(header_ext.has_options());
        assert_eq!(header_ext.raw_options.len(), 4);

        // Verify we can iterate options
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 4); // 4 NOPs
    }

    #[test]
    fn test_ipv4_with_timestamp_option() {
        let mut packet = create_test_packet();

        // Change IHL to 9 (9 * 4 = 36 bytes header with 16 bytes of options)
        packet[0] = 0x49; // Version 4, IHL 9

        // Add Timestamp option (Type 68, Length 16)
        packet.push(0x44); // Type: Timestamp
        packet.push(0x10); // Length: 16 bytes
        packet.push(0x05); // Pointer: 5
        packet.push(0x00); // Overflow + Flags

        // Add 3 timestamps (3 * 4 = 12 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Timestamp 1
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // Timestamp 2
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // Timestamp 3

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        // Verify header length includes options
        assert_eq!(header_ext.ihl(), 9);
        assert_eq!(header_ext.total_len(&packet), 36); // 9 * 4 = 36 bytes
        assert!(header_ext.is_valid());
        assert_eq!(header_ext.raw_options.len(), 16);

        // Verify we can parse the timestamp option
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 1);
    }

    #[test]
    fn test_ipv4_with_record_route_option() {
        let mut packet = create_test_packet();

        // Change IHL to 10 (10 * 4 = 40 bytes header with 20 bytes of options)
        packet[0] = 0x4A; // Version 4, IHL 10

        // Add Record Route option
        // Type (1) + Length (1) + Pointer (1) + 4 addresses (16) = 19 bytes total
        packet.push(0x07); // Type: Record Route
        packet.push(0x13); // Length: 19 bytes (includes Type and Length fields)
        packet.push(0x04); // Pointer: 4 (points to first address slot)

        // Add 4 IP addresses (4 * 4 = 16 bytes)
        packet.extend_from_slice(&[192, 168, 1, 1]);
        packet.extend_from_slice(&[192, 168, 1, 2]);
        packet.extend_from_slice(&[192, 168, 1, 3]);
        packet.extend_from_slice(&[192, 168, 1, 4]);

        // Add NOP for padding (19 + 1 = 20 bytes total options)
        packet.push(0x01); // NOP

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        // Verify header length includes options
        assert_eq!(header_ext.ihl(), 10);
        assert_eq!(header_ext.total_len(&packet), 40); // 10 * 4 = 40 bytes
        assert!(header_ext.is_valid());
        assert_eq!(header_ext.raw_options.len(), 20);

        // Verify we can parse the record route option
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 2); // RecordRoute + NOP
    }

    #[test]
    fn test_ipv4_from_bytes_with_options_and_payload() {
        let mut packet = create_test_packet();

        // Change IHL to 7 (7 * 4 = 28 bytes header with 8 bytes of options)
        packet[0] = 0x47; // Version 4, IHL 7

        // Add 8 bytes of options (NOP + Security option)
        packet.push(0x01); // NOP
        packet.push(0x82); // Type: Security (copied)
        packet.push(0x06); // Length: 6 bytes
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Security data
        packet.push(0x01); // NOP for padding

        // Add some payload data
        let payload_data = b"Test payload after IP options";
        packet.extend_from_slice(payload_data);

        // Update total length in header (28 bytes header + payload)
        let total_len = 28 + payload_data.len();
        packet[2] = ((total_len >> 8) & 0xFF) as u8;
        packet[3] = (total_len & 0xFF) as u8;

        // Parse with from_bytes
        let result = Ipv4Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header_ext, payload) = result.unwrap();

        // Verify the payload starts after ALL of the header (base + options)
        // Should skip 28 bytes (7 * 4)
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);

        // Verify header info
        assert_eq!(header_ext.ihl(), 7);
        assert_eq!(header_ext.total_len(&packet), 28);
        assert_eq!(header_ext.total_length(), total_len);
        assert_eq!(header_ext.raw_options.len(), 8);

        // Verify we can parse the options
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 3); // NOP + Security + NOP
    }

    #[test]
    fn test_ipv4_total_len_includes_options() {
        // Test that total_len() correctly includes IP options
        let mut packet = create_test_packet();

        // Test 1: No options - should return 20
        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();
        assert_eq!(header_ext.total_len(&packet), 20);
        assert_eq!(header_ext.ihl(), 5);
        assert_eq!(header_ext.raw_options.len(), 0);

        // Test 2: With 4 bytes of options (IHL = 6)
        packet = create_test_packet();
        packet[0] = 0x46;
        packet.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]);
        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();
        assert_eq!(header_ext.total_len(&packet), 24); // 6 * 4
        assert_eq!(header_ext.ihl(), 6);
        assert_eq!(header_ext.raw_options.len(), 4);

        // Test 3: With 8 bytes of options (IHL = 7)
        packet = create_test_packet();
        packet[0] = 0x47;
        packet.extend_from_slice(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();
        assert_eq!(header_ext.total_len(&packet), 28); // 7 * 4
        assert_eq!(header_ext.ihl(), 7);
        assert_eq!(header_ext.raw_options.len(), 8);

        // Test 4: Maximum header size with options (IHL = 15)
        packet = create_test_packet();
        packet[0] = 0x4F; // IHL = 15
        let options = vec![0x01u8; 40]; // 40 bytes of NOP options
        packet.extend_from_slice(&options);
        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();
        assert_eq!(header_ext.total_len(&packet), 60); // 15 * 4
        assert_eq!(header_ext.ihl(), 15);
        assert_eq!(header_ext.raw_options.len(), 40);
    }

    #[test]
    fn test_ipv4_header_ext_with_options() {
        let mut packet = create_test_packet();
        packet[0] = 0x47; // IHL = 7

        // Add Router Alert option
        packet.extend_from_slice(&[148, 0x04, 0x00, 0x00]); // Router Alert

        // Add NOP padding
        packet.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]);

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_options.len(), 8);
        assert!(header_ext.has_options());

        // Parse options
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 5); // RouterAlert + 4 NOPs

        // Verify Deref works
        assert_eq!(header_ext.version(), 4);
        assert_eq!(header_ext.ihl(), 7);
        assert_eq!(header_ext.protocol(), IpProto::TCP);
    }

    #[test]
    fn test_ipv4_header_ext_deref() {
        let packet = create_test_packet();
        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        // Test that Deref allows access to all Ipv4Header methods
        assert_eq!(header_ext.version(), 4);
        assert_eq!(header_ext.ihl(), 5);
        assert_eq!(header_ext.dscp(), 0);
        assert_eq!(header_ext.ecn(), 0);
        assert_eq!(header_ext.ttl(), 64);
        assert_eq!(header_ext.protocol(), IpProto::TCP);
        assert_eq!(
            header_ext.src_ip(),
            "192.168.1.100".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(header_ext.dst_ip(), "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_ipv4_options_integration_record_route() {
        let mut packet = create_test_packet();
        packet[0] = 0x48; // IHL = 8 (32 bytes header)

        // Add Record Route option
        packet.push(0x07); // Type: Record Route
        packet.push(0x0B); // Length: 11 bytes
        packet.push(0x04); // Pointer: 4
        packet.extend_from_slice(&[192, 168, 1, 1]); // IP 1
        packet.extend_from_slice(&[192, 168, 1, 2]); // IP 2

        // Add NOP for padding to 12 bytes
        packet.push(0x01);

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_options.len(), 12);

        // Parse and verify the option
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 2); // RecordRoute + NOP

        use crate::packet::ipv4::opt::Ipv4OptionElement;
        match &opts[0] {
            Ipv4OptionElement::RecordRoute {
                pointer,
                route_data,
            } => {
                assert_eq!(*pointer, 4);
                assert_eq!(route_data.len(), 8);
                assert!(!opts[0].is_copied());
            }
            _ => panic!("Expected RecordRoute option"),
        }
    }

    #[test]
    fn test_ipv4_options_integration_timestamp() {
        let mut packet = create_test_packet();
        packet[0] = 0x47; // IHL = 7 (28 bytes header)

        // Add Timestamp option (Type 68)
        packet.push(0x44); // Type: Timestamp
        packet.push(0x08); // Length: 8 bytes
        packet.push(0x05); // Pointer: 5
        packet.push(0x00); // Overflow + Flags (0 = timestamps only)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Timestamp

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_options.len(), 8);

        // Parse and verify the option
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 1);

        use crate::packet::ipv4::opt::{Ipv4OptionElement, TimestampFlag};
        match &opts[0] {
            Ipv4OptionElement::Timestamp {
                pointer,
                overflow,
                flags,
                data,
            } => {
                assert_eq!(*pointer, 5);
                assert_eq!(*overflow, 0);
                assert_eq!(*flags, TimestampFlag::TimestampsOnly);
                assert_eq!(data.len(), 4);
                assert_eq!(opts[0].option_class(), 2);
            }
            _ => panic!("Expected Timestamp option"),
        }
    }

    #[test]
    fn test_ipv4_options_integration_security() {
        let mut packet = create_test_packet();
        packet[0] = 0x47; // IHL = 7 (28 bytes header, need 8 bytes for option + padding)

        // Add Security option (Type 130, copied bit set)
        packet.push(0x82); // Type: Security (130, with copied bit)
        packet.push(0x06); // Length: 6 bytes (Type + Length + 2 + 2)
        packet.extend_from_slice(&[0x00, 0xAB, 0x00, 0xCD]); // Classification (2 bytes) + Protection Authority (2 bytes)

        // Add padding to reach 8 bytes total options
        packet.extend_from_slice(&[0x01, 0x01]); // 2 NOPs for padding

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_options.len(), 8);

        // Parse and verify the option
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 3); // Security + 2 NOPs

        use crate::packet::ipv4::opt::Ipv4OptionElement;
        match &opts[0] {
            Ipv4OptionElement::Security {
                classification,
                protection_authority,
            } => {
                assert_eq!(*classification, 0x00AB);
                assert_eq!(*protection_authority, 0x00CD);
                assert!(opts[0].is_copied()); // Security should be copied
            }
            _ => panic!("Expected Security option"),
        }
    }

    #[test]
    fn test_ipv4_options_integration_multiple() {
        let mut packet = create_test_packet();
        packet[0] = 0x48; // IHL = 8 (32 bytes header)

        // NOP
        packet.push(0x01);

        // Stream ID
        packet.extend_from_slice(&[136, 0x04, 0x12, 0x34]);

        // Router Alert
        packet.extend_from_slice(&[148, 0x04, 0x00, 0x00]);

        // NOP padding (3 bytes to reach 12 bytes total)
        packet.extend_from_slice(&[0x01, 0x01, 0x01]);

        let (header_ext, _) = Ipv4Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_options.len(), 12);
        assert!(header_ext.has_options());

        // Parse all options
        let opts: Vec<_> = header_ext.options().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(opts.len(), 6); // NOP + StreamID + RouterAlert + 3 NOPs

        use crate::packet::ipv4::opt::Ipv4OptionElement;
        assert!(matches!(opts[0], Ipv4OptionElement::Nop));
        assert!(matches!(opts[1], Ipv4OptionElement::StreamId(0x1234)));
        assert!(matches!(opts[2], Ipv4OptionElement::RouterAlert(0)));
        assert!(matches!(opts[3], Ipv4OptionElement::Nop));
    }

    // Helper function to create a test header
    fn create_test_header() -> Ipv4Header {
        Ipv4Header {
            ver_ihl: 0x45, // Version 4, IHL 5
            dscp_ecn: 0x00,
            total_length: U16::new(20),
            identification: U16::new(0x1234),
            flags_frag_offset: U16::new(0x4000), // Don't Fragment
            ttl: 64,
            protocol: IpProto::TCP,
            checksum: U16::new(0),
            src_ip: U32::new(0xC0A80164), // 192.168.1.100
            dst_ip: U32::new(0x0A000001), // 10.0.0.1
        }
    }

    // Helper function to create a test packet
    fn create_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (4) + IHL (5)
        packet.push(0x45);

        // DSCP + ECN
        packet.push(0x00);

        // Total length (20 bytes for header only)
        packet.extend_from_slice(&[0x00, 0x14]);

        // Identification
        packet.extend_from_slice(&[0x12, 0x34]);

        // Flags + Fragment offset (Don't Fragment)
        packet.extend_from_slice(&[0x40, 0x00]);

        // TTL
        packet.push(64);

        // Protocol (TCP)
        packet.push(6);

        // Checksum
        packet.extend_from_slice(&[0x00, 0x00]);

        // Source IP: 192.168.1.100
        packet.extend_from_slice(&[192, 168, 1, 100]);

        // Destination IP: 10.0.0.1
        packet.extend_from_slice(&[10, 0, 0, 1]);

        packet
    }
}
