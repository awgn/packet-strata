//! IPv6 (Internet Protocol version 6) packet parser
//!
//! This module implements parsing for IPv6 packets as defined in RFC 8200.
//! IPv6 is the most recent version of the Internet Protocol, designed to
//! replace IPv4 and provide a much larger address space.
//!
//! # IPv6 Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version| Traffic Class |           Flow Label                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Payload Length        |  Next Header  |   Hop Limit   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                                                               +
//! |                                                               |
//! +                         Source Address                        +
//! |                                                               |
//! +                                                               +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                                                               +
//! |                                                               |
//! +                      Destination Address                      +
//! |                                                               |
//! +                                                               +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Version: 6 (always)
//! - Header size: 40 bytes (fixed, unlike IPv4)
//! - Address size: 128 bits (16 bytes)
//! - Extension headers used for optional features
//!
//! # Examples
//!
//! ## Basic IPv6 parsing
//!
//! ```
//! use packet_strata::packet::ipv6::Ipv6Header;
//! use packet_strata::packet::protocol::IpProto;
//! use packet_strata::packet::HeaderParser;
//! use std::net::Ipv6Addr;
//!
//! // IPv6 packet with ICMPv6 payload
//! let packet = vec![
//!     0x60, 0x00, 0x00, 0x00,  // Version=6, TC=0, Flow Label=0
//!     0x00, 0x08,              // Payload Length: 8 bytes
//!     0x3A,                    // Next Header: ICMPv6 (58)
//!     0x40,                    // Hop Limit: 64
//!     // Source: ::1
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//!     // Destination: ::1
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//!     // ICMPv6 payload follows...
//! ];
//!
//! let (header, payload) = Ipv6Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 6);
//! assert_eq!(header.hop_limit(), 64);
//! assert_eq!(header.next_header(), IpProto::IPV6_ICMP);
//! assert_eq!(header.src_ip(), Ipv6Addr::LOCALHOST);
//! assert_eq!(header.dst_ip(), Ipv6Addr::LOCALHOST);
//! ```
//!
//! ## IPv6 with Traffic Class and Flow Label
//!
//! ```
//! use packet_strata::packet::ipv6::Ipv6Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // IPv6 packet with Traffic Class and Flow Label set
//! let packet = vec![
//!     0x6F, 0x12, 0x34, 0x56,  // Version=6, TC=0xF1, Flow Label=0x23456
//!     0x00, 0x00,              // Payload Length: 0
//!     0x06,                    // Next Header: TCP (6)
//!     0x80,                    // Hop Limit: 128
//!     // Source: 2001:db8::1
//!     0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//!     // Destination: 2001:db8::2
//!     0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
//! ];
//!
//! let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.traffic_class(), 0xF1);
//! assert_eq!(header.flow_label(), 0x23456);
//! assert_eq!(header.hop_limit(), 128);
//! ```

pub mod ext;

use std::fmt::{self, Formatter};
use std::net::Ipv6Addr;
use std::ops::Deref;

use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::ipv6::ext::Ipv6ExtensionHeadersIter;
use crate::packet::protocol::IpProto;
use crate::packet::{HeaderParser, PacketHeader};

/// IPv6 Header structure as defined in RFC 8200
///
/// The IPv6 header has a fixed size of 40 bytes, unlike IPv4 which has a variable size.
/// Extension headers are used for additional functionality instead of header options.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, Unaligned, KnownLayout, Debug, Clone, Copy)]
pub struct Ipv6Header {
    /// Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    ver_tc_flow: [u8; 4],
    /// Payload length (excludes the header itself)
    payload_length: U16<BigEndian>,
    /// Next header type (same values as IPv4 protocol field)
    next_header: IpProto,
    /// Hop limit (equivalent to IPv4 TTL)
    hop_limit: u8,
    /// Source IPv6 address (128 bits)
    src_ip: [u8; 16],
    /// Destination IPv6 address (128 bits)
    dst_ip: [u8; 16],
}

// IPv6 Extension Header Types (next_header values)
// Re-export from IpProto for convenience
pub const IPV6_NEXT_HOPBYHOP: IpProto = IpProto::IPV6_HOPOPT;
pub const IPV6_NEXT_TCP: IpProto = IpProto::TCP;
pub const IPV6_NEXT_UDP: IpProto = IpProto::UDP;
pub const IPV6_NEXT_IPV6: IpProto = IpProto::IPV6;
pub const IPV6_NEXT_ROUTING: IpProto = IpProto::IPV6_ROUTE;
pub const IPV6_NEXT_FRAGMENT: IpProto = IpProto::IPV6_FRAG;
pub const IPV6_NEXT_ICMPV6: IpProto = IpProto::IPV6_ICMP;
pub const IPV6_NEXT_NONE: IpProto = IpProto::IPV6_NONXT;
pub const IPV6_NEXT_DSTOPTS: IpProto = IpProto::IPV6_OPTS;
pub const IPV6_NEXT_MOBILITY: IpProto = IpProto::IPV6_MOBILITY;

impl Ipv6Header {
    /// Returns the IP version (should always be 6)
    #[inline]
    pub fn version(&self) -> u8 {
        self.ver_tc_flow[0] >> 4
    }

    /// Returns the Traffic Class (8 bits)
    /// Equivalent to DSCP + ECN in IPv4
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.ver_tc_flow[0] & 0x0F) << 4) | (self.ver_tc_flow[1] >> 4)
    }

    /// Returns the DSCP portion of Traffic Class (6 bits)
    #[inline]
    pub fn dscp(&self) -> u8 {
        self.traffic_class() >> 2
    }

    /// Returns the ECN portion of Traffic Class (2 bits)
    #[inline]
    pub fn ecn(&self) -> u8 {
        self.traffic_class() & 0x03
    }

    /// Returns the Flow Label (20 bits)
    /// Used for QoS and flow identification
    #[inline]
    pub fn flow_label(&self) -> u32 {
        let b1 = (self.ver_tc_flow[1] & 0x0F) as u32;
        let b2 = self.ver_tc_flow[2] as u32;
        let b3 = self.ver_tc_flow[3] as u32;
        (b1 << 16) | (b2 << 8) | b3
    }

    /// Returns the payload length in bytes
    /// Note: This does NOT include the IPv6 header itself (40 bytes)
    #[inline]
    pub fn payload_length(&self) -> usize {
        self.payload_length.get() as usize
    }

    /// Returns the total packet length (header + payload)
    #[inline]
    pub fn total_length(&self) -> usize {
        Self::FIXED_LEN + self.payload_length()
    }

    /// Returns the next header type
    /// This indicates the protocol of the next header (TCP, UDP, extension header, etc.)
    #[inline]
    pub fn next_header(&self) -> IpProto {
        self.next_header
    }

    /// Returns the hop limit
    /// Equivalent to TTL in IPv4
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    /// Returns the source IPv6 address as `Ipv6Addr`
    #[inline]
    pub fn src_ip(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.src_ip)
    }

    /// Returns the destination IPv6 address as `Ipv6Addr`
    #[inline]
    pub fn dst_ip(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.dst_ip)
    }

    /// Returns the source IPv6 address as raw bytes
    #[inline]
    pub fn src_ip_raw(&self) -> [u8; 16] {
        self.src_ip
    }

    /// Returns the destination IPv6 address as raw bytes
    #[inline]
    pub fn dst_ip_raw(&self) -> [u8; 16] {
        self.dst_ip
    }

    /// Check if this packet uses extension headers
    #[inline]
    pub fn has_extension_headers(&self) -> bool {
        matches!(
            self.next_header,
            IPV6_NEXT_HOPBYHOP | IPV6_NEXT_ROUTING | IPV6_NEXT_FRAGMENT | IPV6_NEXT_DSTOPTS
        )
    }

    /// Check if the next header is a transport protocol (TCP/UDP)
    #[inline]
    pub fn is_transport_protocol(&self) -> bool {
        matches!(self.next_header, IPV6_NEXT_TCP | IPV6_NEXT_UDP)
    }

    /// Parse extension headers starting from a given offset
    /// Returns (total_header_length, upper_layer_protocol, is_fragmented)
    /// Returns None if parsing fails or buffer is too small
    fn parse_extension_headers(
        buf: &[u8],
        bytes_available: usize,
        initial_next_header: IpProto,
        allow_fragment: bool,
    ) -> Option<(usize, IpProto, bool)> {
        if bytes_available < Self::FIXED_LEN {
            return None;
        }

        let mut len = Self::FIXED_LEN;
        let mut next_hdr = initial_next_header;
        let mut is_fragmented = false;

        // Parse extension headers
        while matches!(
            next_hdr,
            IPV6_NEXT_HOPBYHOP
                | IPV6_NEXT_ROUTING
                | IPV6_NEXT_DSTOPTS
                | IPV6_NEXT_MOBILITY
                | IPV6_NEXT_FRAGMENT
        ) {
            if next_hdr == IPV6_NEXT_FRAGMENT {
                if !allow_fragment {
                    return None;
                }
                is_fragmented = true;
                // Fragment header is 8 bytes fixed
                // Get next header field
                if len >= bytes_available {
                    return None;
                }
                next_hdr = IpProto::from(buf[len]);
                len += 8;
            } else {
                // Other extension headers
                // Need at least 2 more bytes to read next header and length
                if len + 2 > bytes_available {
                    return None;
                }

                // Extension header format:
                // - Byte 0: Next Header type
                // - Byte 1: Header Extension Length (in 8-byte units, not including first 8 bytes)
                next_hdr = IpProto::from(buf[len]);
                let ext_len = buf[len + 1];

                // Calculate delta: (1 + ext_len) * 8
                // This gives us the total size of this extension header
                let delta = (1 + ext_len as usize) * 8;

                // Zero length is invalid
                if delta == 0 {
                    return None;
                }

                len += delta;

                // Check if we have enough bytes
                if len > bytes_available {
                    return None;
                }
            }
        }

        Some((len, next_hdr, is_fragmented))
    }

    /// Calculate the total header length including extension headers
    ///
    /// Returns the total length of IPv6 header + all extension headers,
    /// or 0 if the packet is fragmented or if there's an error parsing.
    ///
    /// `buf` should start at the beginning of the IPv6 header and contain
    /// at least `bytes_available` bytes.
    pub fn total_header_len(&self, buf: &[u8], bytes_available: usize) -> usize {
        // Don't allow fragment headers - return 0 if encountered
        Self::parse_extension_headers(buf, bytes_available, self.next_header, false)
            .map(|(len, _, _)| len)
            .unwrap_or(0)
    }

    /// Get the upper layer protocol after skipping all extension headers
    /// Returns the protocol number and whether fragmentation was encountered
    pub fn upper_layer_protocol(
        &self,
        buf: &[u8],
        bytes_available: usize,
    ) -> Option<(IpProto, bool)> {
        // Allow fragment headers - we want to know if packet is fragmented
        Self::parse_extension_headers(buf, bytes_available, self.next_header, true)
            .map(|(_, protocol, is_fragmented)| (protocol, is_fragmented))
    }

    /// Check if there are extension headers to parse
    #[inline]
    pub fn should_parse_extensions(&self) -> bool {
        self.has_extension_headers()
    }
}

/// IPv6 Header with extension headers
#[derive(Debug, Clone)]
pub struct Ipv6HeaderExt<'a> {
    pub header: &'a Ipv6Header,
    pub raw_extensions: &'a [u8],
}

impl<'a> Ipv6HeaderExt<'a> {
    /// Get IPv6 extension headers iterator
    pub fn extensions(&'a self) -> Ipv6ExtensionHeadersIter<'a> {
        Ipv6ExtensionHeadersIter::new(self.header.next_header, self.raw_extensions)
    }

    /// Get the total header length including extensions
    pub fn ext_headers_len(&self) -> usize {
        Ipv6Header::FIXED_LEN + self.raw_extensions.len()
    }
}

impl Deref for Ipv6HeaderExt<'_> {
    type Target = Ipv6Header;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for Ipv6Header {
    const NAME: &'static str = "IPv6Header";
    type InnerType = IpProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.next_header
    }

    /// IPv6 header length including extension headers
    /// This uses the buffer to parse extension headers and calculate the correct length
    #[inline]
    fn total_len(&self, buf: &[u8]) -> usize {
        // Calculate total header length including extension headers
        // Allow fragment headers for parsing, return total length
        Self::parse_extension_headers(buf, buf.len(), self.next_header, true)
            .map(|(len, _, _)| len)
            .unwrap_or(Self::FIXED_LEN) // Return at least the fixed header length
    }

    /// Validate the IPv6 header
    #[inline]
    fn is_valid(&self) -> bool {
        // Version must be 6
        self.version() == 6
    }
}

impl HeaderParser for Ipv6Header {
    type Output<'a> = Ipv6HeaderExt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, raw_extensions: &'a [u8]) -> Self::Output<'a> {
        Ipv6HeaderExt {
            header,
            raw_extensions,
        }
    }
}

impl fmt::Display for Ipv6Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv6 {} -> {} proto={} hop={} len={}",
            self.src_ip(),
            self.dst_ip(),
            self.next_header(),
            self.hop_limit(),
            self.total_length()
        )?;

        if self.flow_label() != 0 {
            write!(f, " flow=0x{:05x}", self.flow_label())?;
        }

        if self.has_extension_headers() {
            write!(f, " +exts")?;
        }

        Ok(())
    }
}

impl fmt::Display for Ipv6HeaderExt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)?;

        if !self.raw_extensions.is_empty() {
            write!(f, " exts=[")?;
            let mut first = true;
            for ext in self.extensions().flatten() {
                if !first {
                    write!(f, ",")?;
                }
                first = false;
                write!(f, "{}", ext)?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_ipv6_header_size() {
        assert_eq!(mem::size_of::<Ipv6Header>(), 40);
        assert_eq!(Ipv6Header::FIXED_LEN, 40);
    }

    #[test]
    fn test_ipv6_version() {
        let header = create_test_header();
        assert_eq!(header.version(), 6);
        assert!(header.is_valid());
    }

    #[test]
    fn test_ipv6_traffic_class() {
        let mut header = create_test_header();

        // Set traffic class to 0xAB (10101011)
        // Version is 6 (0110), so first byte should be 0x6A (01101010)
        // Second nibble goes to upper 4 bits of second byte: 0xB0
        header.ver_tc_flow[0] = 0x6A;
        header.ver_tc_flow[1] = 0xB0;

        assert_eq!(header.traffic_class(), 0xAB);
        assert_eq!(header.dscp(), 0xAB >> 2);
        assert_eq!(header.ecn(), 0xAB & 0x03);
    }

    #[test]
    fn test_ipv6_flow_label() {
        let mut header = create_test_header();

        // Set flow label to 0x12345
        // Lower 4 bits of byte[1], all of byte[2] and byte[3]
        header.ver_tc_flow[1] = (header.ver_tc_flow[1] & 0xF0) | 0x01;
        header.ver_tc_flow[2] = 0x23;
        header.ver_tc_flow[3] = 0x45;

        assert_eq!(header.flow_label(), 0x12345);
    }

    #[test]
    fn test_ipv6_addresses() {
        let header = create_test_header();

        // Test source address: 2001:db8::1
        let expected_src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert_eq!(header.src_ip(), expected_src);

        // Test destination address: 2001:db8::2
        let expected_dst = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);
        assert_eq!(header.dst_ip(), expected_dst);
    }

    #[test]
    fn test_ipv6_payload_length() {
        let mut header = create_test_header();
        header.payload_length = U16::new(1024);

        assert_eq!(header.payload_length(), 1024);
        assert_eq!(header.total_length(), 40 + 1024);
    }

    #[test]
    fn test_ipv6_next_header() {
        let mut header = create_test_header();

        header.next_header = IPV6_NEXT_TCP;
        assert_eq!(header.next_header(), IpProto::TCP);
        assert!(header.is_transport_protocol());
        assert!(!header.has_extension_headers());

        header.next_header = IPV6_NEXT_FRAGMENT;
        assert!(header.has_extension_headers());
        assert!(!header.is_transport_protocol());
    }

    #[test]
    fn test_ipv6_parsing() {
        let packet = create_test_packet();

        let result = Ipv6Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header_ext, payload) = result.unwrap();
        assert_eq!(header_ext.version(), 6);
        assert_eq!(header_ext.next_header(), IPV6_NEXT_TCP);
        assert_eq!(header_ext.hop_limit(), 64);
        assert_eq!(header_ext.raw_extensions.len(), 0);
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn test_ipv6_parsing_invalid_version() {
        let mut packet = create_test_packet();
        packet[0] = 0x40; // Version 4 instead of 6

        let result = Ipv6Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_parsing_too_small() {
        let packet = vec![0u8; 39]; // Only 39 bytes, need 40

        let result = Ipv6Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_total_header_len_no_extensions() {
        let packet = create_test_packet();
        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();

        // No extension headers, should return 40
        assert_eq!(header.total_header_len(&packet, packet.len()), 40);
    }

    #[test]
    fn test_ipv6_total_header_len_with_extensions() {
        let mut packet = create_test_packet();

        // Change next header to Hop-by-Hop Options
        packet[6] = IPV6_NEXT_HOPBYHOP.into();

        // Add Hop-by-Hop extension header (8 bytes minimum)
        // Next Header: TCP (6)
        packet.push(IPV6_NEXT_TCP.into());
        // Hdr Ext Len: 0 (meaning 8 bytes total: (1+0)*8)
        packet.push(0);
        // Padding (6 bytes to make it 8 bytes total)
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();

        // 40 (base) + 8 (hop-by-hop) = 48
        assert_eq!(header.total_header_len(&packet, packet.len()), 48);
    }

    #[test]
    fn test_ipv6_upper_layer_protocol() {
        let packet = create_test_packet();
        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();

        // Direct TCP, no fragmentation
        let result = header.upper_layer_protocol(&packet, packet.len());
        assert_eq!(result, Some((IpProto::TCP, false)));
    }

    #[test]
    fn test_ipv6_upper_layer_protocol_with_extensions() {
        let mut packet = create_test_packet();

        // Change next header to Hop-by-Hop Options
        packet[6] = IPV6_NEXT_HOPBYHOP.into();

        // Add Hop-by-Hop extension header pointing to TCP
        packet.push(IPV6_NEXT_TCP.into()); // Next Header: TCP
        packet.push(0); // Hdr Ext Len: 0
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // Padding

        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();

        let result = header.upper_layer_protocol(&packet, packet.len());
        assert_eq!(result, Some((IpProto::TCP, false)));
    }

    #[test]
    fn test_ipv6_from_bytes_with_routing_extension() {
        let mut packet = create_test_packet();

        // Change next header to Routing
        packet[6] = IPV6_NEXT_ROUTING.into();

        // Add Routing extension header
        packet.push(IPV6_NEXT_TCP.into()); // Next Header: TCP
        packet.push(2); // Hdr Ext Len: 2 (meaning (1+2)*8 = 24 bytes total)
        packet.push(0); // Routing Type: 0
        packet.push(1); // Segments Left: 1
        packet.extend_from_slice(&[0, 0, 0, 0]); // Reserved (4 bytes)

        // Add one IPv6 address (16 bytes) for the route
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ]);

        // Add some payload data after the extension headers
        let payload_data = b"Test payload after routing header";
        packet.extend_from_slice(payload_data);

        // Update payload length in the header (extension headers + payload)
        let total_payload = 24 + payload_data.len();
        packet[4] = ((total_payload >> 8) & 0xFF) as u8;
        packet[5] = (total_payload & 0xFF) as u8;

        // Parse with from_bytes
        let result = Ipv6Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify the payload starts after ALL headers (base + extension)
        // Should skip 40 (base) + 24 (routing) = 64 bytes
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);

        // Verify header info
        assert_eq!(header.next_header(), IpProto::IPV6_ROUTE);
        assert!(header.has_extension_headers());

        // Verify total_length() is compatible with header size + payload
        // total_length = 40 (base) + payload_length
        // payload_length should include extension headers (24) + actual payload
        assert_eq!(header.total_length(), 40 + 24 + payload_data.len());
        assert_eq!(header.payload_length(), 24 + payload_data.len());

        // Verify total_length is at least as large as the total header length
        let total_header_len = header.total_header_len(&packet, packet.len());
        assert!(header.total_length() >= total_header_len);
    }

    #[test]
    fn test_ipv6_from_bytes_with_hopbyhop_extension() {
        let mut packet = create_test_packet();

        // Change next header to Hop-by-Hop Options
        packet[6] = IPV6_NEXT_HOPBYHOP.into();

        // Add Hop-by-Hop extension header (8 bytes)
        packet.push(IPV6_NEXT_UDP.into()); // Next Header: UDP
        packet.push(0); // Hdr Ext Len: 0 (meaning (1+0)*8 = 8 bytes total)
        packet.push(1); // PadN option
        packet.push(4); // Option length: 4
        packet.extend_from_slice(&[0, 0, 0, 0]); // Padding data

        // Add some payload data after the extension headers
        let payload_data = b"UDP payload";
        packet.extend_from_slice(payload_data);

        // Update payload length in the header (extension headers + payload)
        let total_payload = 8 + payload_data.len();
        packet[4] = ((total_payload >> 8) & 0xFF) as u8;
        packet[5] = (total_payload & 0xFF) as u8;

        // Parse with from_bytes
        let result = Ipv6Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify the payload starts after ALL headers (base + extension)
        // Should skip 40 (base) + 8 (hop-by-hop) = 48 bytes
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);

        // Verify header info
        assert_eq!(header.next_header(), IpProto::IPV6_HOPOPT);
        assert!(header.has_extension_headers());

        // Verify total_length() includes extension headers
        assert_eq!(header.total_length(), 40 + 8 + payload_data.len());
        assert_eq!(header.payload_length(), 8 + payload_data.len());

        // Verify total_length is at least as large as the total header length
        let total_header_len = header.total_header_len(&packet, packet.len());
        assert!(header.total_length() >= total_header_len);
    }

    #[test]
    fn test_ipv6_multiple_chained_extension_headers() {
        let mut packet = create_test_packet();

        // Change next header to Hop-by-Hop Options
        packet[6] = IPV6_NEXT_HOPBYHOP.into();

        // Add Hop-by-Hop extension header (8 bytes) pointing to Routing
        packet.push(IPV6_NEXT_ROUTING.into()); // Next Header: Routing
        packet.push(0); // Hdr Ext Len: 0 (8 bytes total)
        packet.push(1); // PadN option
        packet.push(4); // Option length: 4
        packet.extend_from_slice(&[0, 0, 0, 0]); // Padding data

        // Add Routing extension header (24 bytes) pointing to Destination Options
        packet.push(IPV6_NEXT_DSTOPTS.into()); // Next Header: Destination Options
        packet.push(2); // Hdr Ext Len: 2 (24 bytes total)
        packet.push(0); // Routing Type: 0
        packet.push(1); // Segments Left: 1
        packet.extend_from_slice(&[0, 0, 0, 0]); // Reserved (4 bytes)
                                                 // Add one IPv6 address (16 bytes)
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ]);

        // Add Destination Options extension header (8 bytes) pointing to TCP
        packet.push(IPV6_NEXT_TCP.into()); // Next Header: TCP
        packet.push(0); // Hdr Ext Len: 0 (8 bytes total)
        packet.push(1); // PadN option
        packet.push(4); // Option length: 4
        packet.extend_from_slice(&[0, 0, 0, 0]); // Padding data

        // Add some payload data
        let payload_data = b"TCP payload after multiple extension headers";
        packet.extend_from_slice(payload_data);

        // Update payload length: 8 (hop-by-hop) + 24 (routing) + 8 (dest opts) + payload
        let total_payload = 8 + 24 + 8 + payload_data.len();
        packet[4] = ((total_payload >> 8) & 0xFF) as u8;
        packet[5] = (total_payload & 0xFF) as u8;

        // Parse with from_bytes
        let result = Ipv6Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify the payload starts after ALL headers
        // Should skip 40 (base) + 8 (hop-by-hop) + 24 (routing) + 8 (dest opts) = 80 bytes
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);

        // Verify header info
        assert_eq!(header.next_header(), IpProto::IPV6_HOPOPT);
        assert!(header.has_extension_headers());

        // Verify total header length calculation
        assert_eq!(header.total_header_len(&packet, packet.len()), 80);

        // Verify upper layer protocol is TCP
        let result = header.upper_layer_protocol(&packet, packet.len());
        assert_eq!(result, Some((IpProto::TCP, false)));

        // Verify total_length() accounts for all extension headers
        // total_length = 40 (base) + 8 (hop) + 24 (routing) + 8 (dest opts) + payload
        assert_eq!(header.total_length(), 40 + 8 + 24 + 8 + payload_data.len());
        assert_eq!(header.payload_length(), 8 + 24 + 8 + payload_data.len());

        // Verify total_length is at least as large as the total header length
        let total_header_len = header.total_header_len(&packet, packet.len());
        assert!(header.total_length() >= total_header_len);
        assert_eq!(header.total_length(), total_header_len + payload_data.len());
    }

    #[test]
    fn test_ipv6_routing_extension_header() {
        let mut packet = create_test_packet();

        // Change next header to Routing
        packet[6] = IPV6_NEXT_ROUTING.into();

        // Add Routing extension header
        // Routing Type 0 header (deprecated but simple for testing)
        packet.push(IPV6_NEXT_TCP.into()); // Next Header: TCP
        packet.push(2); // Hdr Ext Len: 2 (meaning (1+2)*8 = 24 bytes total)
        packet.push(0); // Routing Type: 0
        packet.push(1); // Segments Left: 1
        packet.extend_from_slice(&[0, 0, 0, 0]); // Reserved (4 bytes)

        // Add one IPv6 address (16 bytes) for the route
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ]);

        // Update payload length to include the extension header (24 bytes)
        packet[4] = 0;
        packet[5] = 24;

        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();

        // Verify extension header is detected
        assert!(header.has_extension_headers());
        assert!(!header.is_transport_protocol());

        // Total header length: 40 (base) + 24 (routing) = 64
        assert_eq!(header.total_header_len(&packet, packet.len()), 64);

        // Upper layer protocol should find TCP after routing header
        let result = header.upper_layer_protocol(&packet, packet.len());
        assert_eq!(result, Some((IpProto::TCP, false)));

        // Verify total_length() is compatible with extension headers
        let total_header_len = header.total_header_len(&packet, packet.len());
        assert!(header.total_length() >= total_header_len);
        assert_eq!(header.total_length(), 40 + 24); // base + routing extension
        assert_eq!(header.payload_length(), 24);
    }

    #[test]
    fn test_ipv6_hopbyhop_extension_header() {
        let mut packet = create_test_packet();

        // Change next header to Hop-by-Hop Options
        packet[6] = IPV6_NEXT_HOPBYHOP.into();

        // Add Hop-by-Hop extension header (8 bytes minimum)
        packet.push(IPV6_NEXT_UDP.into()); // Next Header: UDP
        packet.push(0); // Hdr Ext Len: 0 (meaning (1+0)*8 = 8 bytes total)

        // Add padding options (6 bytes to make it 8 bytes total)
        packet.push(1); // PadN option
        packet.push(4); // Option length: 4
        packet.extend_from_slice(&[0, 0, 0, 0]); // Padding data

        // Update payload length to include the extension header (8 bytes)
        packet[4] = 0;
        packet[5] = 8;

        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();

        // Verify extension header is detected
        assert!(header.has_extension_headers());
        assert!(!header.is_transport_protocol());

        // Total header length: 40 (base) + 8 (hop-by-hop) = 48
        assert_eq!(header.total_header_len(&packet, packet.len()), 48);

        // Upper layer protocol should find UDP after hop-by-hop header
        let result = header.upper_layer_protocol(&packet, packet.len());
        assert_eq!(result, Some((IpProto::UDP, false)));

        // Verify total_length() is compatible with extension headers
        let total_header_len = header.total_header_len(&packet, packet.len());
        assert!(header.total_length() >= total_header_len);
        assert_eq!(header.total_length(), 40 + 8); // base + hop-by-hop extension
        assert_eq!(header.payload_length(), 8);
    }

    #[test]
    fn test_ipv6_total_len_includes_extension_headers() {
        // Test that total_len() correctly includes extension headers
        let mut packet = create_test_packet();

        // Test 1: No extension headers - should return 40
        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 40);

        // Test 2: With Hop-by-Hop extension header
        packet = create_test_packet();
        packet[6] = IPV6_NEXT_HOPBYHOP.into();
        packet.push(IPV6_NEXT_TCP.into());
        packet.push(0);
        packet.extend_from_slice(&[1, 4, 0, 0, 0, 0]);
        packet[4] = 0;
        packet[5] = 8;

        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 48); // 40 + 8

        // Test 3: With Routing extension header
        packet = create_test_packet();
        packet[6] = IPV6_NEXT_ROUTING.into();
        packet.push(IPV6_NEXT_TCP.into());
        packet.push(2);
        packet.push(0);
        packet.push(1);
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ]);
        packet[4] = 0;
        packet[5] = 24;

        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 64); // 40 + 24

        // Test 4: Multiple chained extension headers
        packet = create_test_packet();
        packet[6] = IPV6_NEXT_HOPBYHOP.into();
        // Hop-by-Hop -> Routing
        packet.push(IPV6_NEXT_ROUTING.into());
        packet.push(0);
        packet.extend_from_slice(&[1, 4, 0, 0, 0, 0]);
        // Routing -> TCP
        packet.push(IPV6_NEXT_TCP.into());
        packet.push(2);
        packet.push(0);
        packet.push(1);
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ]);
        packet[4] = 0;
        packet[5] = 32;

        let (header, _) = Ipv6Header::from_bytes(&packet).unwrap();
        assert_eq!(header.total_len(&packet), 72); // 40 + 8 + 24
    }

    // Helper function to create a test header
    fn create_test_header() -> Ipv6Header {
        Ipv6Header {
            ver_tc_flow: [0x60, 0x00, 0x00, 0x00], // Version 6
            payload_length: U16::new(0),
            next_header: IpProto::TCP,
            hop_limit: 64,
            src_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        }
    }

    // Helper function to create a test packet
    fn create_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (6) + Traffic Class (0) + Flow Label (0)
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);

        // Payload length (0 bytes)
        packet.extend_from_slice(&[0x00, 0x00]);

        // Next header (TCP)
        packet.push(IpProto::TCP.into());

        // Hop limit
        packet.push(64);

        // Source address: 2001:db8::1
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        // Destination address: 2001:db8::2
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        packet
    }

    #[test]
    fn test_ipv6_header_ext_no_extensions() {
        let packet = create_test_packet();
        let (header_ext, _) = Ipv6Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_extensions.len(), 0);
        assert!(!header_ext.should_parse_extensions());
        assert_eq!(header_ext.ext_headers_len(), 40); // Just the IPv6 header

        // Test Deref
        assert_eq!(header_ext.version(), 6);
        assert_eq!(header_ext.next_header(), IPV6_NEXT_TCP);
        assert_eq!(header_ext.hop_limit(), 64);
    }

    #[test]
    fn test_ipv6_header_ext_with_fragment() {
        let mut packet = create_test_packet();

        // Update next header to Fragment
        packet[6] = IPV6_NEXT_FRAGMENT.into();

        // Update payload length to 8 (fragment header size)
        packet[4] = 0;
        packet[5] = 8;

        // Add Fragment header
        packet.extend_from_slice(&[
            IpProto::TCP.into(), // Next Header: TCP
            0,                   // Reserved
            0x00,
            0x01, // Fragment Offset=0, M=1
            0x00,
            0x00,
            0x00,
            0x01, // Identification=1
        ]);

        let (header_ext, _) = Ipv6Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_extensions.len(), 8);
        assert!(header_ext.should_parse_extensions());
        assert_eq!(header_ext.ext_headers_len(), 48); // 40 + 8

        // Parse extensions
        let exts: Vec<_> = header_ext
            .extensions()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(exts.len(), 1);

        use crate::packet::ipv6::ext::Ipv6ExtensionHeader;
        match &exts[0] {
            Ipv6ExtensionHeader::Fragment {
                next_header,
                fragment_offset,
                more_fragments,
                identification,
            } => {
                assert_eq!(*next_header, IpProto::TCP);
                assert_eq!(*fragment_offset, 0);
                assert!(*more_fragments);
                assert_eq!(*identification, 1);
            }
            _ => panic!("Expected Fragment header"),
        }
    }

    #[test]
    fn test_ipv6_header_ext_with_hop_by_hop() {
        let mut packet = create_test_packet();

        // Update next header to Hop-by-Hop
        packet[6] = IPV6_NEXT_HOPBYHOP.into();

        // Update payload length to 8 (hop-by-hop header size)
        packet[4] = 0;
        packet[5] = 8;

        // Add Hop-by-Hop Options header
        packet.extend_from_slice(&[
            IpProto::TCP.into(), // Next Header: TCP
            0,                   // Hdr Ext Len: 0 (8 bytes total)
            1,
            4,
            0,
            0,
            0,
            0, // PadN option
        ]);

        let (header_ext, _) = Ipv6Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_extensions.len(), 8);
        assert_eq!(header_ext.ext_headers_len(), 48);

        // Parse extensions
        let exts: Vec<_> = header_ext
            .extensions()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(exts.len(), 1);

        use crate::packet::ipv6::ext::Ipv6ExtensionHeader;
        match &exts[0] {
            Ipv6ExtensionHeader::HopByHop {
                next_header,
                options,
            } => {
                assert_eq!(*next_header, IpProto::TCP);
                assert_eq!(options.len(), 6);
            }
            _ => panic!("Expected HopByHop header"),
        }
    }

    #[test]
    fn test_ipv6_header_ext_multiple_extensions() {
        let mut packet = create_test_packet();

        // Update next header to Hop-by-Hop
        packet[6] = IPV6_NEXT_HOPBYHOP.into();

        // Update payload length to 16 (8 + 8 bytes)
        packet[4] = 0;
        packet[5] = 16;

        // Add Hop-by-Hop Options header (Next: Fragment)
        packet.extend_from_slice(&[
            IPV6_NEXT_FRAGMENT.into(), // Next Header: Fragment
            0,                         // Hdr Ext Len: 0
            1,
            4,
            0,
            0,
            0,
            0, // PadN option
        ]);

        // Add Fragment header (Next: TCP)
        packet.extend_from_slice(&[
            IpProto::TCP.into(), // Next Header: TCP
            0,                   // Reserved
            0x00,
            0x00, // Fragment Offset=0, M=0
            0x00,
            0x00,
            0x00,
            0x42, // Identification=66
        ]);

        let (header_ext, _) = Ipv6Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_extensions.len(), 16);
        assert_eq!(header_ext.ext_headers_len(), 56); // 40 + 16

        // Parse extensions
        let exts: Vec<_> = header_ext
            .extensions()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(exts.len(), 2);

        use crate::packet::ipv6::ext::Ipv6ExtensionHeader;
        assert!(matches!(&exts[0], Ipv6ExtensionHeader::HopByHop { .. }));
        assert!(matches!(&exts[1], Ipv6ExtensionHeader::Fragment { .. }));

        // Verify next_header chaining
        assert_eq!(exts[0].next_header(), IPV6_NEXT_FRAGMENT);
        assert_eq!(exts[1].next_header(), IpProto::TCP);
    }

    #[test]
    fn test_ipv6_header_ext_deref() {
        let packet = create_test_packet();
        let (header_ext, _) = Ipv6Header::from_bytes(&packet).unwrap();

        // Test that Deref allows access to all Ipv6Header methods
        assert_eq!(header_ext.version(), 6);
        assert_eq!(header_ext.traffic_class(), 0);
        assert_eq!(header_ext.flow_label(), 0);
        assert_eq!(header_ext.payload_length(), 0);
        assert_eq!(header_ext.next_header(), IPV6_NEXT_TCP);
        assert_eq!(header_ext.hop_limit(), 64);

        let src = header_ext.src_ip();
        assert_eq!(src.to_string(), "2001:db8::1");

        let dst = header_ext.dst_ip();
        assert_eq!(dst.to_string(), "2001:db8::2");
    }

    #[test]
    fn test_ipv6_header_ext_with_routing() {
        let mut packet = create_test_packet();

        // Update next header to Routing
        packet[6] = IPV6_NEXT_ROUTING.into();

        // Update payload length to 8 (routing header size)
        packet[4] = 0;
        packet[5] = 8;

        // Add Routing header (minimal, Hdr Ext Len = 0)
        packet.extend_from_slice(&[
            IpProto::TCP.into(), // Next Header: TCP
            0,                   // Hdr Ext Len: 0 (8 bytes total)
            0,                   // Routing Type: 0
            0,                   // Segments Left: 0
            0,
            0,
            0,
            0, // Reserved/data
        ]);

        let (header_ext, _) = Ipv6Header::from_bytes(&packet).unwrap();

        assert_eq!(header_ext.raw_extensions.len(), 8);

        // Parse extensions
        let exts: Vec<_> = header_ext
            .extensions()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(exts.len(), 1);

        use crate::packet::ipv6::ext::Ipv6ExtensionHeader;
        match &exts[0] {
            Ipv6ExtensionHeader::Routing {
                next_header,
                routing_type,
                segments_left,
                data,
            } => {
                assert_eq!(*next_header, IpProto::TCP);
                assert_eq!(*routing_type, 0);
                assert_eq!(*segments_left, 0);
                assert_eq!(data.len(), 4);
            }
            _ => panic!("Expected Routing header"),
        }
    }
}
