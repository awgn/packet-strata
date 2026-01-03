//! UDP (User Datagram Protocol) packet parser
//!
//! This module implements parsing for UDP datagrams as defined in RFC 768.
//! UDP provides a simple, connectionless transport service with no guarantees
//! of delivery, ordering, or duplicate protection.
//!
//! # UDP Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            Length             |           Checksum            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Header size: 8 bytes (fixed)
//! - Length field: includes header + payload
//! - Checksum: optional in IPv4, mandatory in IPv6
//!
//! # Examples
//!
//! ## Basic UDP parsing
//!
//! ```
//! use packet_strata::packet::udp::UdpHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // UDP packet with DNS query
//! let packet = vec![
//!     0xC0, 0x00,        // Source port: 49152
//!     0x00, 0x35,        // Destination port: 53 (DNS)
//!     0x00, 0x10,        // Length: 16 bytes (8 header + 8 payload)
//!     0x00, 0x00,        // Checksum: 0 (not computed)
//!     // DNS payload follows...
//!     0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let (header, payload) = UdpHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.src_port(), 49152);
//! assert_eq!(header.dst_port(), 53);
//! assert_eq!(header.length(), 16);
//! assert_eq!(payload.len(), 8);
//! ```
//!
//! ## UDP with well-known ports
//!
//! ```
//! use packet_strata::packet::udp::UdpHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // UDP packet for DHCP
//! let packet = vec![
//!     0x00, 0x44,        // Source port: 68 (DHCP client)
//!     0x00, 0x43,        // Destination port: 67 (DHCP server)
//!     0x00, 0x08,        // Length: 8 bytes (header only)
//!     0x12, 0x34,        // Checksum
//! ];
//!
//! let (header, _) = UdpHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.src_port(), 68);
//! assert_eq!(header.dst_port(), 67);
//! assert_eq!(header.checksum(), 0x1234);
//! ```

use std::fmt::{self, Formatter};
use std::mem;

use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::{HeaderParser, PacketHeader};

/// UDP Header structure as defined in RFC 768
///
/// The UDP header is always 8 bytes and contains source port, destination port,
/// length, and checksum fields.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct UdpHeader {
    src_port: U16<BigEndian>,
    dst_port: U16<BigEndian>,
    length: U16<BigEndian>,
    checksum: U16<BigEndian>,
}

impl UdpHeader {
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

    /// Returns the total length of the UDP datagram (header + data)
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.get()
    }

    /// Returns the checksum value
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum.get()
    }

    /// Returns the length of the UDP header (always 8 bytes)
    #[inline]
    pub fn header_len(&self) -> usize {
        mem::size_of::<UdpHeader>()
    }

    /// Returns the length of the payload data
    #[inline]
    pub fn payload_len(&self) -> usize {
        let total = self.length() as usize;
        total.saturating_sub(Self::FIXED_LEN)
    }

    /// Validates the UDP header
    #[inline]
    pub fn is_valid(&self) -> bool {
        // UDP length must be at least 8 bytes (header size)
        self.length() >= Self::FIXED_LEN as u16
    }

    /// Verify UDP checksum (requires pseudo-header from IP layer)
    ///
    /// Note: For IPv4, the checksum is optional (can be 0)
    /// For IPv6, the checksum is mandatory
    pub fn verify_checksum(&self, src_ip: u32, dst_ip: u32, udp_data: &[u8]) -> bool {
        let checksum = self.checksum();

        // Checksum of 0 means no checksum was computed (valid for IPv4)
        if checksum == 0 {
            return true;
        }

        let computed = Self::compute_checksum(src_ip, dst_ip, udp_data);
        computed == checksum
    }

    /// Compute UDP checksum including pseudo-header
    pub fn compute_checksum(src_ip: u32, dst_ip: u32, udp_data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header: source IP
        sum += (src_ip >> 16) & 0xFFFF;
        sum += src_ip & 0xFFFF;

        // Pseudo-header: destination IP
        sum += (dst_ip >> 16) & 0xFFFF;
        sum += dst_ip & 0xFFFF;

        // Pseudo-header: protocol (17 for UDP)
        sum += 17;

        // Pseudo-header: UDP length
        sum += udp_data.len() as u32;

        // UDP header and data
        let mut i = 0;
        while i < udp_data.len() {
            if i + 1 < udp_data.len() {
                let word = u16::from_be_bytes([udp_data[i], udp_data[i + 1]]);
                sum += word as u32;
                i += 2;
            } else {
                // Odd length: pad with zero
                let word = u16::from_be_bytes([udp_data[i], 0]);
                sum += word as u32;
                i += 1;
            }
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        !sum as u16
    }
}

impl PacketHeader for UdpHeader {
    const NAME: &'static str = "UdpHeader";

    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }

    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}
}

impl HeaderParser for UdpHeader {
    type Output<'a> = &'a UdpHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for UdpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UDP {} -> {} len={}",
            self.src_port(),
            self.dst_port(),
            self.length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_header_basic() {
        let header = UdpHeader {
            src_port: U16::new(53),
            dst_port: U16::new(12345),
            length: U16::new(16), // 8 bytes header + 8 bytes payload
            checksum: U16::new(0),
        };

        assert_eq!(header.src_port(), 53);
        assert_eq!(header.dst_port(), 12345);
        assert_eq!(header.length(), 16);
        assert_eq!(header.header_len(), 8);
        assert_eq!(header.payload_len(), 8);
        assert!(header.is_valid());
    }

    #[test]
    fn test_udp_header_validation() {
        let invalid_header = UdpHeader {
            src_port: U16::new(53),
            dst_port: U16::new(12345),
            length: U16::new(7), // Too small
            checksum: U16::new(0),
        };

        assert!(!invalid_header.is_valid());

        let valid_header = UdpHeader {
            src_port: U16::new(53),
            dst_port: U16::new(12345),
            length: U16::new(8), // Minimum valid size
            checksum: U16::new(0),
        };

        assert!(valid_header.is_valid());
    }

    #[test]
    fn test_udp_checksum_zero() {
        let header = UdpHeader {
            src_port: U16::new(53),
            dst_port: U16::new(12345),
            length: U16::new(8),
            checksum: U16::new(0),
        };

        // Checksum of 0 should always be valid for IPv4
        assert!(header.verify_checksum(0x7f000001, 0x7f000001, &[]));
    }

    #[test]
    fn test_udp_header_size() {
        assert_eq!(mem::size_of::<UdpHeader>(), 8);
        assert_eq!(UdpHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_udp_parsing_basic() {
        let packet = create_test_packet();

        let result = UdpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.src_port(), 12345);
        assert_eq!(header.dst_port(), 53);
        assert_eq!(header.length(), 16);
        assert_eq!(payload.len(), 8); // "DNS data" payload
        assert!(header.is_valid());
    }

    #[test]
    fn test_udp_parsing_too_small() {
        let packet = vec![0u8; 7]; // Only 7 bytes, need 8

        let result = UdpHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_udp_total_len() {
        let packet = create_test_packet();
        let (header, _) = UdpHeader::from_bytes(&packet).unwrap();

        // UDP header is always 8 bytes (no options like TCP)
        assert_eq!(header.total_len(&packet), 8);
    }

    #[test]
    fn test_udp_from_bytes_with_payload() {
        let mut packet = Vec::new();

        // UDP Header
        packet.extend_from_slice(&5000u16.to_be_bytes()); // Source port
        packet.extend_from_slice(&8080u16.to_be_bytes()); // Destination port

        let payload_data = b"Hello, UDP!";
        let total_length = 8 + payload_data.len();

        packet.extend_from_slice(&(total_length as u16).to_be_bytes()); // Length
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (not computed)

        // Add payload
        packet.extend_from_slice(payload_data);

        let result = UdpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify header fields
        assert_eq!(header.src_port(), 5000);
        assert_eq!(header.dst_port(), 8080);
        assert_eq!(header.length(), total_length as u16);
        assert_eq!(header.payload_len(), payload_data.len());

        // Verify payload separation
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);
    }

    #[test]
    fn test_udp_payload_length_calculation() {
        let header1 = UdpHeader {
            src_port: U16::new(1234),
            dst_port: U16::new(5678),
            length: U16::new(8), // Header only, no payload
            checksum: U16::new(0),
        };
        assert_eq!(header1.payload_len(), 0);

        let header2 = UdpHeader {
            src_port: U16::new(1234),
            dst_port: U16::new(5678),
            length: U16::new(100), // 8 bytes header + 92 bytes payload
            checksum: U16::new(0),
        };
        assert_eq!(header2.payload_len(), 92);

        // Invalid length (less than header size)
        let header3 = UdpHeader {
            src_port: U16::new(1234),
            dst_port: U16::new(5678),
            length: U16::new(5), // Invalid
            checksum: U16::new(0),
        };
        assert_eq!(header3.payload_len(), 0);
    }

    #[test]
    fn test_udp_dns_packet() {
        let mut packet = Vec::new();

        // UDP Header for DNS query
        packet.extend_from_slice(&54321u16.to_be_bytes()); // Source port (ephemeral)
        packet.extend_from_slice(&53u16.to_be_bytes()); // Destination port (DNS)

        // Simplified DNS query payload
        let dns_payload = vec![
            0xab, 0xcd, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ];

        let total_length = 8 + dns_payload.len();
        packet.extend_from_slice(&(total_length as u16).to_be_bytes()); // Length
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum

        // Add DNS payload
        packet.extend_from_slice(&dns_payload);

        let (header, payload) = UdpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.src_port(), 54321);
        assert_eq!(header.dst_port(), 53);
        assert_eq!(header.length(), total_length as u16);
        assert_eq!(payload.len(), dns_payload.len());
        assert_eq!(payload, dns_payload.as_slice());
    }

    #[test]
    fn test_udp_checksum_computation() {
        // Simple test with known values
        let src_ip = 0xC0A80101; // 192.168.1.1
        let dst_ip = 0xC0A80102; // 192.168.1.2

        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&12345u16.to_be_bytes()); // Source port
        udp_packet.extend_from_slice(&80u16.to_be_bytes()); // Destination port
        udp_packet.extend_from_slice(&12u16.to_be_bytes()); // Length
        udp_packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (zero for computation)

        // Add 4 bytes of payload
        udp_packet.extend_from_slice(b"test");

        let checksum = UdpHeader::compute_checksum(src_ip, dst_ip, &udp_packet);

        // Checksum should be non-zero for non-empty data
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_udp_multiple_packets() {
        // Test parsing multiple different UDP packets
        let packets: Vec<(u16, u16, Vec<u8>)> = vec![
            (1234, 5678, b"payload1".to_vec()),
            (80, 54321, b"HTTP response".to_vec()),
            (53, 12345, b"DNS".to_vec()),
        ];

        for (src, dst, payload_data) in packets {
            let mut packet = Vec::new();
            packet.extend_from_slice(&src.to_be_bytes());
            packet.extend_from_slice(&dst.to_be_bytes());
            packet.extend_from_slice(&((8 + payload_data.len()) as u16).to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&payload_data);

            let (header, payload) = UdpHeader::from_bytes(&packet).unwrap();
            assert_eq!(header.src_port(), src);
            assert_eq!(header.dst_port(), dst);
            assert_eq!(payload, payload_data.as_slice());
        }
    }

    // Helper function to create a test UDP packet
    fn create_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source port: 12345
        packet.extend_from_slice(&12345u16.to_be_bytes());

        // Destination port: 53 (DNS)
        packet.extend_from_slice(&53u16.to_be_bytes());

        // Length: 16 (8 bytes header + 8 bytes payload)
        packet.extend_from_slice(&16u16.to_be_bytes());

        // Checksum: 0
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Payload: "DNS data"
        packet.extend_from_slice(b"DNS data");

        packet
    }
}
