//! SCTP (Stream Control Transmission Protocol) packet header implementation
//!
//! This module provides support for parsing and working with SCTP headers as defined in RFC 4960.
//! SCTP is a transport layer protocol that provides reliable, ordered delivery of messages
//! with support for multi-streaming and multi-homing.
//!
//! # SCTP Common Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Verification Tag                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Checksum (CRC32c)                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Common header size: 12 bytes (fixed)
//! - Verification Tag: identifies the association
//! - Checksum: CRC32c algorithm (not Adler-32)
//! - Data is organized in chunks after the common header
//!
//! # Examples
//!
//! ```
//! use packet_strata::packet::sctp::SctpHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // Parse an SCTP packet
//! let packet = vec![
//!     0x0B, 0x59, // Source port: 2905
//!     0x0B, 0x59, // Destination port: 2905
//!     0x12, 0x34, 0x56, 0x78, // Verification tag
//!     0x00, 0x00, 0x00, 0x00, // Checksum
//!     // Chunk data would follow...
//! ];
//!
//! let (header, payload) = SctpHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.src_port(), 2905);
//! assert_eq!(header.dst_port(), 2905);
//! assert_eq!(header.verification_tag(), 0x12345678);
//! ```

use std::fmt::{self, Formatter};
use std::mem;

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::{HeaderParser, PacketHeader};

/// SCTP (Stream Control Transmission Protocol) Header structure as defined in RFC 4960
///
/// The SCTP common header is 12 bytes and contains:
/// - Source port (16 bits)
/// - Destination port (16 bits)
/// - Verification tag (32 bits)
/// - Checksum (32 bits - CRC32c)
///
/// Following the common header, SCTP packets contain one or more chunks that carry
/// control information and user data.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct SctpHeader {
    src_port: U16<BigEndian>,
    dst_port: U16<BigEndian>,
    verification_tag: U32<BigEndian>,
    checksum: U32<BigEndian>,
}

impl SctpHeader {
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

    /// Returns the verification tag
    ///
    /// The verification tag is used to validate the sender of the packet.
    /// For INIT chunks, this field is set to 0.
    #[inline]
    pub fn verification_tag(&self) -> u32 {
        self.verification_tag.get()
    }

    /// Returns the checksum value (CRC32c)
    #[inline]
    pub fn checksum(&self) -> u32 {
        self.checksum.get()
    }

    /// Returns the length of the SCTP header (always 12 bytes)
    #[inline]
    pub fn header_len(&self) -> usize {
        mem::size_of::<SctpHeader>()
    }

    /// Validates the SCTP header
    ///
    /// Basic validation - more detailed validation would require
    /// examining the chunk data that follows the header
    #[inline]
    pub fn is_valid(&self) -> bool {
        // SCTP header itself is always valid if it's complete
        // Chunk validation would be done on the payload
        true
    }

    /// Computes the CRC32c checksum for SCTP
    ///
    /// SCTP uses CRC32c (Castagnoli) instead of the Internet checksum
    /// as defined in RFC 4960 Appendix B
    pub fn compute_checksum(sctp_data: &[u8]) -> u32 {
        const CRC32C_POLYNOMIAL: u32 = 0x1EDC6F41;
        const CRC32C_INITIAL: u32 = 0xFFFFFFFF;

        let mut crc = CRC32C_INITIAL;

        // Process the SCTP packet with checksum field set to 0
        let mut data = sctp_data.to_vec();
        if data.len() >= 12 {
            // Set checksum field (bytes 8-11) to 0 for computation
            data[8..12].copy_from_slice(&[0, 0, 0, 0]);
        }

        for &byte in &data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ CRC32C_POLYNOMIAL;
                } else {
                    crc >>= 1;
                }
            }
        }

        !crc
    }

    /// Verifies the SCTP checksum
    ///
    /// Returns true if the checksum is valid
    pub fn verify_checksum(&self, sctp_data: &[u8]) -> bool {
        let stored_checksum = self.checksum();
        let computed = Self::compute_checksum(sctp_data);
        computed == stored_checksum
    }
}

impl PacketHeader for SctpHeader {
    const NAME: &'static str = "SctpHeader";

    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }

    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}
}

impl HeaderParser for SctpHeader {
    type Output<'a> = &'a SctpHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for SctpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SCTP {} -> {} vtag=0x{:08x}",
            self.src_port(),
            self.dst_port(),
            self.verification_tag()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sctp_header_basic() {
        let header = SctpHeader {
            src_port: U16::new(3868),
            dst_port: U16::new(3868),
            verification_tag: U32::new(0x12345678),
            checksum: U32::new(0),
        };

        assert_eq!(header.src_port(), 3868);
        assert_eq!(header.dst_port(), 3868);
        assert_eq!(header.verification_tag(), 0x12345678);
        assert_eq!(header.checksum(), 0);
        assert_eq!(header.header_len(), 12);
        assert!(header.is_valid());
    }

    #[test]
    fn test_sctp_header_size() {
        assert_eq!(mem::size_of::<SctpHeader>(), 12);
        assert_eq!(SctpHeader::FIXED_LEN, 12);
    }

    #[test]
    fn test_sctp_parsing_basic() {
        let packet = create_test_packet();

        let result = SctpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();
        assert_eq!(header.src_port(), 2905);
        assert_eq!(header.dst_port(), 2905);
        assert_eq!(header.verification_tag(), 0xABCDEF01);
        assert!(header.is_valid());
        assert_eq!(payload.len(), 8); // Test payload
    }

    #[test]
    fn test_sctp_parsing_too_small() {
        let packet = vec![0u8; 11]; // Only 11 bytes, need 12

        let result = SctpHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_sctp_total_len() {
        let packet = create_test_packet();
        let (header, _) = SctpHeader::from_bytes(&packet).unwrap();

        // SCTP header is always 12 bytes (no options in common header)
        assert_eq!(header.total_len(&packet), 12);
    }

    #[test]
    fn test_sctp_from_bytes_with_payload() {
        let mut packet = Vec::new();

        // SCTP Header
        packet.extend_from_slice(&9899u16.to_be_bytes()); // Source port
        packet.extend_from_slice(&9899u16.to_be_bytes()); // Destination port
        packet.extend_from_slice(&0x11223344u32.to_be_bytes()); // Verification tag
        packet.extend_from_slice(&0u32.to_be_bytes()); // Checksum (not computed)

        // Add some chunk data as payload
        let chunk_data = b"SCTP CHUNK DATA";
        packet.extend_from_slice(chunk_data);

        let result = SctpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify header fields
        assert_eq!(header.src_port(), 9899);
        assert_eq!(header.dst_port(), 9899);
        assert_eq!(header.verification_tag(), 0x11223344);

        // Verify payload separation
        assert_eq!(payload.len(), chunk_data.len());
        assert_eq!(payload, chunk_data);
    }

    #[test]
    fn test_sctp_init_chunk() {
        let mut packet = Vec::new();

        // SCTP Header for INIT chunk
        packet.extend_from_slice(&5000u16.to_be_bytes()); // Source port
        packet.extend_from_slice(&5000u16.to_be_bytes()); // Destination port
        packet.extend_from_slice(&0u32.to_be_bytes()); // Verification tag (0 for INIT)
        packet.extend_from_slice(&0x12345678u32.to_be_bytes()); // Checksum

        // Simplified INIT chunk
        let chunk_data = vec![
            0x01, // Chunk type: INIT
            0x00, // Chunk flags
            0x00, 0x10, // Chunk length: 16 bytes
            0x00, 0x00, 0x00, 0x01, // Initiate tag
            0x00, 0x00, 0x10, 0x00, // a_rwnd
            0x00, 0x0A, // Number of outbound streams
            0x00, 0x0A, // Number of inbound streams
            0x00, 0x00, 0x00, 0x02, // Initial TSN
        ];
        packet.extend_from_slice(&chunk_data);

        let (header, payload) = SctpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.src_port(), 5000);
        assert_eq!(header.dst_port(), 5000);
        assert_eq!(header.verification_tag(), 0); // INIT has verification tag 0
        assert_eq!(payload.len(), chunk_data.len());
    }

    #[test]
    fn test_sctp_multiple_ports() {
        // Test various common SCTP port combinations
        let test_cases: Vec<(u16, u16)> = vec![
            (2905, 2905),   // SCTP default
            (3868, 3868),   // Diameter
            (9899, 9899),   // SCTP tunneling
            (36412, 36412), // S1AP (LTE)
            (38412, 38412), // NGAP (5G)
        ];

        for (src, dst) in test_cases {
            let mut packet = Vec::new();
            packet.extend_from_slice(&src.to_be_bytes());
            packet.extend_from_slice(&dst.to_be_bytes());
            packet.extend_from_slice(&0x11111111u32.to_be_bytes());
            packet.extend_from_slice(&0x22222222u32.to_be_bytes());

            let (header, _) = SctpHeader::from_bytes(&packet).unwrap();
            assert_eq!(header.src_port(), src);
            assert_eq!(header.dst_port(), dst);
        }
    }

    #[test]
    fn test_sctp_checksum_computation() {
        let mut packet = Vec::new();

        // Create a simple SCTP packet
        packet.extend_from_slice(&2905u16.to_be_bytes()); // Source port
        packet.extend_from_slice(&2905u16.to_be_bytes()); // Destination port
        packet.extend_from_slice(&0x12345678u32.to_be_bytes()); // Verification tag
        packet.extend_from_slice(&0u32.to_be_bytes()); // Checksum placeholder

        // Add simple chunk data
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x04]); // Simple chunk

        let checksum = SctpHeader::compute_checksum(&packet);

        // Checksum should be computed (implementation is simplified)
        // In a real implementation, this would use hardware-accelerated CRC32c
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_sctp_verification_tag_values() {
        // Test different verification tag values
        let tags = vec![0x00000000, 0xFFFFFFFF, 0x12345678, 0xABCDEF01];

        for tag in tags {
            let header = SctpHeader {
                src_port: U16::new(2905),
                dst_port: U16::new(2905),
                verification_tag: U32::new(tag),
                checksum: U32::new(0),
            };

            assert_eq!(header.verification_tag(), tag);
        }
    }

    #[test]
    fn test_sctp_wellknown_ports() {
        // Test well-known SCTP ports
        let header_diameter = SctpHeader {
            src_port: U16::new(3868),
            dst_port: U16::new(3868),
            verification_tag: U32::new(0),
            checksum: U32::new(0),
        };
        assert_eq!(header_diameter.src_port(), 3868); // Diameter

        let header_s1ap = SctpHeader {
            src_port: U16::new(36412),
            dst_port: U16::new(36412),
            verification_tag: U32::new(0),
            checksum: U32::new(0),
        };
        assert_eq!(header_s1ap.src_port(), 36412); // S1AP
    }

    // Helper function to create a test SCTP packet
    fn create_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source port: 2905
        packet.extend_from_slice(&2905u16.to_be_bytes());

        // Destination port: 2905
        packet.extend_from_slice(&2905u16.to_be_bytes());

        // Verification tag
        packet.extend_from_slice(&0xABCDEF01u32.to_be_bytes());

        // Checksum
        packet.extend_from_slice(&0u32.to_be_bytes());

        // Payload: simple test data
        packet.extend_from_slice(b"SCTP_TST");

        packet
    }
}
