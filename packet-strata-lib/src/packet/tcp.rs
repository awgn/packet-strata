//! TCP (Transmission Control Protocol) packet parser
//!
//! This module implements parsing for TCP segments as defined in RFC 793.
//! TCP provides reliable, ordered, and error-checked delivery of data
//! between applications.
//!
//! # TCP Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Acknowledgment Number                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Data |       |C|E|U|A|P|R|S|F|                               |
//! | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
//! |       |       |R|E|G|K|H|T|N|N|                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |         Urgent Pointer        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Options (if Data Offset > 5)               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Minimum header size: 20 bytes (Data Offset = 5)
//! - Maximum header size: 60 bytes (Data Offset = 15)
//! - Flags: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
//!
//! # Examples
//!
//! ## Basic TCP parsing
//!
//! ```
//! use packet_strata::packet::tcp::TcpHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // TCP SYN packet
//! let packet = vec![
//!     0x1F, 0x90,              // Source port: 8080
//!     0x00, 0x50,              // Destination port: 80
//!     0x00, 0x00, 0x00, 0x01,  // Sequence number: 1
//!     0x00, 0x00, 0x00, 0x00,  // Acknowledgment number: 0
//!     0x50, 0x02,              // Data offset=5, Flags=SYN
//!     0xFF, 0xFF,              // Window size: 65535
//!     0x00, 0x00,              // Checksum
//!     0x00, 0x00,              // Urgent pointer
//!     // Payload follows...
//! ];
//!
//! let (header, payload) = TcpHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.src_port(), 8080);
//! assert_eq!(header.dst_port(), 80);
//! assert!(header.is_syn());
//! assert!(!header.is_ack());
//! assert_eq!(header.window_size(), 65535);
//! ```
//!
//! ## TCP with options (SYN-ACK)
//!
//! ```
//! use packet_strata::packet::tcp::TcpHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // TCP SYN-ACK packet with MSS option
//! let packet = vec![
//!     0x00, 0x50,              // Source port: 80
//!     0x1F, 0x90,              // Destination port: 8080
//!     0x00, 0x00, 0x00, 0x01,  // Sequence number: 1
//!     0x00, 0x00, 0x00, 0x02,  // Acknowledgment number: 2
//!     0x60, 0x12,              // Data offset=6, Flags=SYN+ACK
//!     0x72, 0x10,              // Window size: 29200
//!     0x00, 0x00,              // Checksum
//!     0x00, 0x00,              // Urgent pointer
//!     0x02, 0x04, 0x05, 0xB4,  // MSS option: 1460
//!     // Payload follows...
//! ];
//!
//! let (header, payload) = TcpHeader::from_bytes(&packet).unwrap();
//! assert!(header.is_syn());
//! assert!(header.is_ack());
//! assert_eq!(header.data_offset(), 6);
//! assert_eq!(header.data_offset() as usize * 4, 24);  // Header length in bytes
//! ```

pub mod opt;

use std::fmt::{self, Formatter};
use std::ops::Deref;

use smol_str::{SmolStr, SmolStrBuilder};
use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::tcp::opt::TcpOptionsIter;
use crate::packet::{HeaderParser, PacketHeader};

/// TCP Header structure as defined in RFC 793
///
/// The fixed portion of the TCP header is 20 bytes. Additional options
/// may be present if Data Offset > 5.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct TcpHeader {
    src_port: U16<BigEndian>,
    dst_port: U16<BigEndian>,
    sequence_number: U32<BigEndian>,
    acknowledgment_number: U32<BigEndian>,
    data_offset_flags: U16<BigEndian>,
    window_size: U16<BigEndian>,
    checksum: U16<BigEndian>,
    urgent_pointer: U16<BigEndian>,
}

impl TcpHeader {
    // TCP Flags
    pub const FLAG_FIN: u8 = 0x01;
    pub const FLAG_SYN: u8 = 0x02;
    pub const FLAG_RST: u8 = 0x04;
    pub const FLAG_PSH: u8 = 0x08;
    pub const FLAG_ACK: u8 = 0x10;
    pub const FLAG_URG: u8 = 0x20;
    pub const FLAG_ECE: u8 = 0x40;
    pub const FLAG_CWR: u8 = 0x80;

    #[allow(unused)]
    const NAME: &'static str = "TcpHeader";

    /// Returns the data offset (header length) in 32-bit words
    #[inline]
    pub fn data_offset(&self) -> u8 {
        (self.data_offset_flags.get() >> 12) as u8
    }

    /// Returns the TCP flags byte
    #[inline]
    pub fn flags(&self) -> u8 {
        (self.data_offset_flags.get() & 0x00FF) as u8
    }

    /// Check if FIN flag is set
    #[inline]
    pub fn is_fin(&self) -> bool {
        self.flags() & Self::FLAG_FIN != 0
    }

    /// Check if SYN flag is set
    #[inline]
    pub fn is_syn(&self) -> bool {
        self.flags() & Self::FLAG_SYN != 0
    }

    /// Check if RST flag is set
    #[inline]
    pub fn is_rst(&self) -> bool {
        self.flags() & Self::FLAG_RST != 0
    }

    /// Check if PSH flag is set
    #[inline]
    pub fn is_psh(&self) -> bool {
        self.flags() & Self::FLAG_PSH != 0
    }

    /// Check if ACK flag is set
    #[inline]
    pub fn is_ack(&self) -> bool {
        self.flags() & Self::FLAG_ACK != 0
    }

    /// Check if URG flag is set
    #[inline]
    pub fn is_urg(&self) -> bool {
        self.flags() & Self::FLAG_URG != 0
    }

    /// Check if ECE flag is set
    #[inline]
    pub fn is_ece(&self) -> bool {
        self.flags() & Self::FLAG_ECE != 0
    }

    /// Check if CWR flag is set
    #[inline]
    pub fn is_cwr(&self) -> bool {
        self.flags() & Self::FLAG_CWR != 0
    }

    /// Returns the source port number
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.src_port.get()
    }

    /// Returns the destination port number
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.dst_port.get()
    }

    /// Returns the sequence number
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number.get()
    }

    /// Validates the TCP header
    #[inline]
    fn is_valid(&self) -> bool {
        // Data offset must be at least 5 (20 bytes minimum)
        // and at most 15 (60 bytes maximum)
        let offset = self.data_offset();
        (5..=15).contains(&offset)
    }

    /// Returns the acknowledgment number
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        self.acknowledgment_number.get()
    }

    /// Returns the window size
    #[inline]
    pub fn window_size(&self) -> u16 {
        self.window_size.get()
    }

    /// Returns the urgent pointer
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        self.urgent_pointer.get()
    }

    /// Returns a string representation of active flags
    pub fn flags_string(&self) -> SmolStr {
        let mut result = SmolStrBuilder::new();
        if self.is_fin() {
            result.push('F');
        }
        if self.is_syn() {
            result.push('S');
        }
        if self.is_rst() {
            result.push('R');
        }
        if self.is_psh() {
            result.push('P');
        }
        if self.is_ack() {
            result.push('A');
        }
        if self.is_urg() {
            result.push('U');
        }
        if self.is_ece() {
            result.push('E');
        }
        if self.is_cwr() {
            result.push('C');
        }
        result.finish()
    }
}

#[derive (Debug, Clone)]
pub struct TcpHeaderOpt<'a> {
    pub header: &'a TcpHeader,
    pub raw_options: &'a [u8],
}

impl<'a> TcpHeaderOpt<'a> {
    /// Get TCP options slice
    pub fn options(&'a self) -> TcpOptionsIter<'a> {
        TcpOptionsIter::new(self.raw_options)
    }
}

impl Deref for TcpHeaderOpt<'_> {
    type Target = TcpHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for TcpHeader {
    const NAME: &'static str = "TcpHeader";
    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}

    /// Returns the header length in bytes
    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        (self.data_offset() as usize) * 4
    }

    /// Validates the TCP header
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for TcpHeader {
    type Output<'a> = TcpHeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, raw_options: &'a [u8]) -> Self::Output<'a> {
        TcpHeaderOpt {
            header,
            raw_options,
        }
    }
}

impl fmt::Display for TcpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP {} -> {} [{}] seq={} ack={} win={}",
            self.src_port(),
            self.dst_port(),
            self.flags_string(),
            self.sequence_number(),
            self.acknowledgment_number(),
            self.window_size()
        )?;

        if self.data_offset() > 5 {
            write!(f, " +opts")?;
        }

        Ok(())
    }
}

impl fmt::Display for TcpHeaderOpt<'_> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        let header = TcpHeader {
            src_port: U16::new(80),
            dst_port: U16::new(12345),
            sequence_number: U32::new(0),
            acknowledgment_number: U32::new(0),
            data_offset_flags: U16::new((5 << 12) | TcpHeader::FLAG_SYN as u16),
            window_size: U16::new(65535),
            checksum: U16::new(0),
            urgent_pointer: U16::new(0),
        };

        // Create a minimal buffer for total_len() call
        let buf = [0u8; 20];

        assert_eq!(header.data_offset(), 5);
        assert_eq!(header.total_len(&buf), 20);
        assert!(header.is_syn());
        assert!(!header.is_ack());
        assert!(header.is_valid());
    }

    #[test]
    fn test_tcp_header_validation() {
        let mut header = TcpHeader {
            src_port: U16::new(80),
            dst_port: U16::new(12345),
            sequence_number: U32::new(0),
            acknowledgment_number: U32::new(0),
            data_offset_flags: U16::new(4 << 12), // Invalid: too small
            window_size: U16::new(65535),
            checksum: U16::new(0),
            urgent_pointer: U16::new(0),
        };

        assert!(!header.is_valid());

        header.data_offset_flags = U16::new(5 << 12);
        assert!(header.is_valid());
    }

    #[test]
    fn test_tcp_header_size() {
        assert_eq!(std::mem::size_of::<TcpHeader>(), 20);
        assert_eq!(TcpHeader::FIXED_LEN, 20);
    }

    #[test]
    fn test_tcp_all_flags() {
        let mut header = create_test_header();

        // Test each flag individually
        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_FIN as u16);
        assert!(header.is_fin());
        assert!(!header.is_syn());

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_SYN as u16);
        assert!(header.is_syn());
        assert!(!header.is_fin());

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_RST as u16);
        assert!(header.is_rst());

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_PSH as u16);
        assert!(header.is_psh());

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_ACK as u16);
        assert!(header.is_ack());

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_URG as u16);
        assert!(header.is_urg());

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_ECE as u16);
        assert!(header.is_ece());

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_CWR as u16);
        assert!(header.is_cwr());

        // Test multiple flags
        header.data_offset_flags =
            U16::new((5 << 12) | (TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK) as u16);
        assert!(header.is_syn());
        assert!(header.is_ack());
        assert_eq!(header.flags_string(), "SA");
    }

    #[test]
    fn test_tcp_parsing_basic() {
        let packet = create_test_packet();

        let result = TcpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.src_port(), 54321);
        assert_eq!(header.dst_port(), 80);
        assert_eq!(header.data_offset(), 5);
        assert!(header.is_syn());
        assert!(header.is_valid());
        assert_eq!(payload.len(), 0); // No payload in test packet
    }

    #[test]
    fn test_tcp_parsing_too_small() {
        let packet = vec![0u8; 19]; // Only 19 bytes, need 20

        let result = TcpHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_total_len_no_options() {
        let packet = create_test_packet();
        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();

        // No options, should return 20 bytes
        assert_eq!(header.total_len(&packet), 20);
        assert_eq!(header.data_offset(), 5);
    }

    #[test]
    fn test_tcp_with_mss_option() {
        let mut packet = create_test_packet();

        // Change data offset to 6 (6 * 4 = 24 bytes header with 4 bytes of options)
        packet[12] = 0x60; // Data offset 6, no flags set initially
        packet[13] = 0x02; // SYN flag

        // Add MSS option (Kind 2, Length 4, MSS value 1460)
        packet.push(0x02); // Kind: MSS
        packet.push(0x04); // Length: 4 bytes
        packet.extend_from_slice(&1460u16.to_be_bytes()); // MSS value

        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();

        // Verify header length includes options
        assert_eq!(header.data_offset(), 6);
        assert_eq!(header.total_len(&packet), 24); // 6 * 4 = 24 bytes
        assert!(header.is_valid());

        // Get the raw options slice
        let options_len = (header.data_offset() as usize * 4) - TcpHeader::FIXED_LEN;
        let options_start = TcpHeader::FIXED_LEN;
        let raw_options = &packet[options_start..options_start + options_len];

        assert_eq!(raw_options.len(), 4);
        assert_eq!(raw_options[0], 0x02); // MSS kind
        assert_eq!(raw_options[1], 0x04); // Length
    }

    #[test]
    fn test_tcp_with_window_scale_option() {
        let mut packet = create_test_packet();

        // Change data offset to 6 (24 bytes with 4 bytes of options)
        packet[12] = 0x60;
        packet[13] = 0x02; // SYN flag

        // Add Window Scale option (Kind 3, Length 3, Shift count 7) + NOP for padding
        packet.push(0x03); // Kind: Window Scale
        packet.push(0x03); // Length: 3 bytes
        packet.push(0x07); // Shift count: 7
        packet.push(0x01); // NOP for padding to 4 bytes

        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.data_offset(), 6);
        assert_eq!(header.total_len(&packet), 24);

        let options_len = (header.data_offset() as usize * 4) - TcpHeader::FIXED_LEN;
        let options_start = TcpHeader::FIXED_LEN;
        let raw_options = &packet[options_start..options_start + options_len];

        assert_eq!(raw_options.len(), 4);
        assert_eq!(raw_options[0], 0x03); // Window Scale kind
        assert_eq!(raw_options[2], 0x07); // Shift count
    }

    #[test]
    fn test_tcp_with_timestamp_option() {
        let mut packet = create_test_packet();

        // Change data offset to 8 (8 * 4 = 32 bytes with 12 bytes of options)
        packet[12] = 0x80;
        packet[13] = 0x02; // SYN flag

        // Add Timestamp option (Kind 8, Length 10, TSval, TSecr)
        packet.push(0x08); // Kind: Timestamp
        packet.push(0x0A); // Length: 10 bytes
        packet.extend_from_slice(&12345678u32.to_be_bytes()); // TSval
        packet.extend_from_slice(&87654321u32.to_be_bytes()); // TSecr

        // Add 2 NOPs for padding to reach 12 bytes
        packet.push(0x01); // NOP
        packet.push(0x01); // NOP

        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.data_offset(), 8);
        assert_eq!(header.total_len(&packet), 32);

        let options_len = (header.data_offset() as usize * 4) - TcpHeader::FIXED_LEN;
        let options_start = TcpHeader::FIXED_LEN;
        let raw_options = &packet[options_start..options_start + options_len];

        assert_eq!(raw_options.len(), 12);
        assert_eq!(raw_options[0], 0x08); // Timestamp kind
        assert_eq!(raw_options[1], 0x0A); // Length
    }

    #[test]
    fn test_tcp_with_sack_permitted_option() {
        let mut packet = create_test_packet();

        // Change data offset to 6 (24 bytes with 4 bytes of options)
        packet[12] = 0x60;
        packet[13] = 0x02; // SYN flag

        // Add SACK Permitted option (Kind 4, Length 2) + 2 NOPs for padding
        packet.push(0x04); // Kind: SACK Permitted
        packet.push(0x02); // Length: 2 bytes
        packet.push(0x01); // NOP
        packet.push(0x01); // NOP

        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.data_offset(), 6);
        assert_eq!(header.total_len(&packet), 24);

        let options_len = (header.data_offset() as usize * 4) - TcpHeader::FIXED_LEN;
        let options_start = TcpHeader::FIXED_LEN;
        let raw_options = &packet[options_start..options_start + options_len];

        assert_eq!(raw_options[0], 0x04); // SACK Permitted kind
    }

    #[test]
    fn test_tcp_with_multiple_options() {
        let mut packet = create_test_packet();

        // Change data offset to 10 (10 * 4 = 40 bytes with 20 bytes of options)
        packet[12] = 0xA0;
        packet[13] = 0x02; // SYN flag

        // Add multiple options: MSS + SACK Permitted + Timestamp + Window Scale
        // MSS (4 bytes)
        packet.push(0x02); // Kind: MSS
        packet.push(0x04); // Length
        packet.extend_from_slice(&1460u16.to_be_bytes());

        // SACK Permitted (2 bytes)
        packet.push(0x04); // Kind: SACK Permitted
        packet.push(0x02); // Length

        // Timestamp (10 bytes)
        packet.push(0x08); // Kind: Timestamp
        packet.push(0x0A); // Length
        packet.extend_from_slice(&12345u32.to_be_bytes()); // TSval
        packet.extend_from_slice(&0u32.to_be_bytes()); // TSecr

        // Window Scale (3 bytes) + NOP for padding
        packet.push(0x03); // Kind: Window Scale
        packet.push(0x03); // Length
        packet.push(0x07); // Shift count
        packet.push(0x01); // NOP

        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.data_offset(), 10);
        assert_eq!(header.total_len(&packet), 40);

        let options_len = (header.data_offset() as usize * 4) - TcpHeader::FIXED_LEN;
        let options_start = TcpHeader::FIXED_LEN;
        let raw_options = &packet[options_start..options_start + options_len];

        assert_eq!(raw_options.len(), 20);
        assert_eq!(raw_options[0], 0x02); // MSS
        assert_eq!(raw_options[4], 0x04); // SACK Permitted
        assert_eq!(raw_options[6], 0x08); // Timestamp
        assert_eq!(raw_options[16], 0x03); // Window Scale
    }

    #[test]
    fn test_tcp_from_bytes_with_options_and_payload() {
        let mut packet = create_test_packet();

        // Change data offset to 7 (7 * 4 = 28 bytes header with 8 bytes of options)
        packet[12] = 0x70;
        packet[13] = 0x18; // PSH + ACK flags

        // Add 8 bytes of options (MSS + padding)
        packet.push(0x02); // MSS kind
        packet.push(0x04); // Length
        packet.extend_from_slice(&1460u16.to_be_bytes());
        packet.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // 4 NOPs

        // Add some payload data
        let payload_data = b"HTTP/1.1 200 OK\r\n";
        packet.extend_from_slice(payload_data);

        let result = TcpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify the payload starts after ALL of the header (base + options)
        // Should skip 28 bytes (7 * 4)
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);

        // Verify header info
        assert_eq!(header.data_offset(), 7);
        assert_eq!(header.total_len(&packet), 28);
        assert!(header.is_psh());
        assert!(header.is_ack());
    }

    #[test]
    fn test_tcp_total_len_includes_options() {
        // Test that total_len() correctly includes TCP options
        let mut packet = create_test_packet();

        // Test 1: No options - should return 20
        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 20);
        assert_eq!(header.data_offset(), 5);

        // Test 2: With 4 bytes of options (data offset = 6)
        packet = create_test_packet();
        packet[12] = 0x60; // Data offset 6
        packet.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // 4 NOPs
        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 24); // 6 * 4
        assert_eq!(header.data_offset(), 6);

        // Test 3: With 8 bytes of options (data offset = 7)
        packet = create_test_packet();
        packet[12] = 0x70;
        packet.extend_from_slice(&[0x01; 8]); // 8 NOPs
        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 28); // 7 * 4
        assert_eq!(header.data_offset(), 7);

        // Test 4: Maximum header size with options (data offset = 15)
        packet = create_test_packet();
        packet[12] = 0xF0; // Data offset 15
        packet.extend_from_slice(&[0x01; 40]); // 40 bytes of NOPs
        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 60); // 15 * 4
        assert_eq!(header.data_offset(), 15);
    }

    #[test]
    fn test_tcp_options_extraction() {
        let mut packet = create_test_packet();

        // No options case
        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();
        let options_len = (header.data_offset() as usize * 4) - TcpHeader::FIXED_LEN;
        assert_eq!(options_len, 0);

        // With options
        packet = create_test_packet();
        packet[12] = 0x60;
        packet.extend_from_slice(&[0x02, 0x04, 0x05, 0xb4]); // MSS option
        let (header, _) = TcpHeader::from_bytes(&packet).unwrap();
        let options_len = (header.data_offset() as usize * 4) - TcpHeader::FIXED_LEN;
        let options_start = TcpHeader::FIXED_LEN;
        let raw_options = &packet[options_start..options_start + options_len];
        assert_eq!(raw_options.len(), 4);
    }

    #[test]
    fn test_tcp_flags_string() {
        let mut header = create_test_header();

        header.data_offset_flags = U16::new(5 << 12);
        assert_eq!(header.flags_string(), "");

        header.data_offset_flags = U16::new((5 << 12) | TcpHeader::FLAG_SYN as u16);
        assert_eq!(header.flags_string(), "S");

        header.data_offset_flags =
            U16::new((5 << 12) | (TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK) as u16);
        assert_eq!(header.flags_string(), "SA");

        header.data_offset_flags = U16::new(
            (5 << 12) | (TcpHeader::FLAG_FIN | TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK) as u16,
        );
        assert_eq!(header.flags_string(), "FPA");

        // All flags
        header.data_offset_flags = U16::new((5 << 12) | 0xFF);
        assert_eq!(header.flags_string(), "FSRPAUEC");
    }

    #[test]
    fn test_tcp_sequence_and_ack_numbers() {
        let mut header = create_test_header();

        header.sequence_number = U32::new(1000);
        header.acknowledgment_number = U32::new(2000);

        assert_eq!(header.sequence_number(), 1000);
        assert_eq!(header.acknowledgment_number(), 2000);
    }

    #[test]
    fn test_tcp_window_and_urgent() {
        let mut header = create_test_header();

        header.window_size = U16::new(65535);
        header.urgent_pointer = U16::new(100);

        assert_eq!(header.window_size(), 65535);
        assert_eq!(header.urgent_pointer(), 100);
    }

    // Helper function to create a test header
    fn create_test_header() -> TcpHeader {
        TcpHeader {
            src_port: U16::new(80),
            dst_port: U16::new(12345),
            sequence_number: U32::new(0),
            acknowledgment_number: U32::new(0),
            data_offset_flags: U16::new(5 << 12), // Data offset 5, no flags
            window_size: U16::new(65535),
            checksum: U16::new(0),
            urgent_pointer: U16::new(0),
        }
    }

    // Helper function to create a test TCP packet
    fn create_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source port: 54321
        packet.extend_from_slice(&54321u16.to_be_bytes());

        // Destination port: 80
        packet.extend_from_slice(&80u16.to_be_bytes());

        // Sequence number: 1000
        packet.extend_from_slice(&1000u32.to_be_bytes());

        // Acknowledgment number: 0
        packet.extend_from_slice(&0u32.to_be_bytes());

        // Data offset (5) + Flags (SYN)
        packet.extend_from_slice(&0x5002u16.to_be_bytes()); // 5 << 12 | SYN

        // Window size: 65535
        packet.extend_from_slice(&65535u16.to_be_bytes());

        // Checksum: 0
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Urgent pointer: 0
        packet.extend_from_slice(&0u16.to_be_bytes());

        packet
    }
}
