//! Teredo tunneling protocol parser
//!
//! This module implements parsing for Teredo tunnels as defined in RFC 4380.
//! Teredo allows IPv6 connectivity for nodes behind IPv4 NAT devices by
//! encapsulating IPv6 packets in UDP datagrams.
//!
//! # Teredo Packet Format
//!
//! Teredo packets are carried over UDP (typically port 3544) and may contain
//! optional indicators before the IPv6 payload:
//!
//! ```text
//! +------------------+
//! |   UDP Header     |
//! +------------------+
//! | Authentication   |  (optional, type 0x0001)
//! +------------------+
//! | Origin Indication|  (optional, type 0x0000)
//! +------------------+
//! |   IPv6 Packet    |
//! +------------------+
//! ```
//!
//! ## Origin Indication (8 bytes)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Type (0x0000)         |      Obfuscated Port          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Obfuscated IPv4 Address                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! ## Authentication (variable length)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Type (0x0001)         |   ID-len      |  AU-len       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Client Identifier                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Authentication Value                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Nonce                                 |
//! |                       (8 bytes)                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Confirmation |
//! +-+-+-+-+-+-+-+-+
//! ```
//!
//! # Examples
//!
//! ## Basic Teredo parsing with Origin Indication
//!
//! ```
//! use packet_strata::packet::tunnel::teredo::TeredoHeader;
//! use packet_strata::packet::HeaderParser;
//! use std::net::Ipv4Addr;
//!
//! // Teredo packet with origin indication
//! let mut packet = Vec::new();
//! // Type: Origin Indication (0x0000)
//! packet.extend_from_slice(&0x0000u16.to_be_bytes());
//! // Obfuscated port: 0x1234 XOR 0xFFFF
//! packet.extend_from_slice(&(0xFFFFu16 ^ 0x1234u16).to_be_bytes());
//! // Obfuscated IPv4: 192.168.1.100 XOR 0xFFFFFFFF
//! packet.extend_from_slice(&(0xFFFFFFFFu32 ^ 0xC0A80164u32).to_be_bytes());
//! // Add minimal IPv6 header
//! packet.extend_from_slice(&[
//!     0x60, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x3a, 0x40,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//! ]);
//!
//! let (header, ipv6_payload) = TeredoHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.port(), 0x1234);
//! assert_eq!(header.ipv4_addr(), Ipv4Addr::new(192, 168, 1, 100));
//! ```
//!
//! ## Direct IPv6 parsing (no indicators)
//!
//! ```
//! use packet_strata::packet::tunnel::teredo::TeredoPacket;
//!
//! // Direct IPv6 packet without Teredo indicators
//! let packet = vec![
//!     0x60, 0x00, 0x00, 0x00,  // IPv6: version=6, traffic class, flow label
//!     0x00, 0x00, 0x3a, 0x40,  // payload length, next header (ICMPv6), hop limit
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  // src addr
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  // dst addr
//! ];
//!
//! let teredo = TeredoPacket::parse(&packet).unwrap();
//! assert!(teredo.authentication().is_none());
//! assert!(teredo.origin_indication().is_none());
//! ```

use std::fmt::{self, Formatter};
use std::net::Ipv4Addr;

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::protocol::IpProto;
use crate::packet::{HeaderParser, PacketHeader, PacketHeaderError};

/// Teredo UDP port (server/relay)
pub const TEREDO_PORT: u16 = 3544;

/// Teredo indicator type: Origin Indication
pub const TEREDO_TYPE_ORIGIN: u16 = 0x0000;

/// Teredo indicator type: Authentication
pub const TEREDO_TYPE_AUTH: u16 = 0x0001;

/// IPv6 version nibble (used to detect start of IPv6 packet)
const IPV6_VERSION_NIBBLE: u8 = 0x60;
const IPV6_VERSION_MASK: u8 = 0xF0;

/// Teredo Origin Indication header (8 bytes)
///
/// The origin indication contains the obfuscated (XOR'd) original
/// source port and IPv4 address of the Teredo client.
///
/// This is the most common Teredo header format used in practice.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Type (0x0000)         |      Obfuscated Port          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Obfuscated IPv4 Address                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, KnownLayout, Immutable)]
pub struct TeredoHeader {
    indicator_type: U16<BigEndian>,
    obfuscated_port: U16<BigEndian>,
    obfuscated_ipv4: U32<BigEndian>,
}

impl TeredoHeader {
    /// Returns the indicator type (should be 0x0000 for Origin Indication)
    #[inline]
    pub fn indicator_type(&self) -> u16 {
        self.indicator_type.get()
    }

    /// Returns the obfuscated port value (XOR'd with 0xFFFF)
    #[inline]
    pub fn obfuscated_port(&self) -> u16 {
        self.obfuscated_port.get()
    }

    /// Returns the original (de-obfuscated) port
    ///
    /// The port is obfuscated by XOR'ing with 0xFFFF
    #[inline]
    pub fn port(&self) -> u16 {
        self.obfuscated_port.get() ^ 0xFFFF
    }

    /// Returns the obfuscated IPv4 address value (XOR'd with 0xFFFFFFFF)
    #[inline]
    pub fn obfuscated_ipv4(&self) -> u32 {
        self.obfuscated_ipv4.get()
    }

    /// Returns the original (de-obfuscated) IPv4 address
    ///
    /// The address is obfuscated by XOR'ing with 0xFFFFFFFF
    #[inline]
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.obfuscated_ipv4.get() ^ 0xFFFFFFFF)
    }

    /// Validates the origin indication header
    #[inline]
    fn is_valid(&self) -> bool {
        self.indicator_type() == TEREDO_TYPE_ORIGIN
    }
}

impl PacketHeader for TeredoHeader {
    const NAME: &'static str = "TeredoHeader";
    type InnerType = IpProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        // Teredo always encapsulates IPv6
        IpProto::IPV6
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

impl HeaderParser for TeredoHeader {
    type Output<'a> = &'a TeredoHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _raw_options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for TeredoHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Teredo origin port={} ipv4={}",
            self.port(),
            self.ipv4_addr()
        )
    }
}

/// Teredo Authentication header (fixed part, 4 bytes)
///
/// The authentication header has a fixed part followed by variable-length
/// client identifier, authentication value, nonce, and confirmation byte.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Type (0x0001)         |   ID-len      |  AU-len       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, KnownLayout, Immutable)]
pub struct TeredoAuthHeader {
    indicator_type: U16<BigEndian>,
    id_len: u8,
    auth_len: u8,
}

impl TeredoAuthHeader {
    /// Size of the fixed authentication header in bytes
    pub const FIXED_SIZE: usize = 4;

    /// Size of the nonce field in bytes
    pub const NONCE_SIZE: usize = 8;

    /// Size of the confirmation byte
    pub const CONFIRMATION_SIZE: usize = 1;

    /// Returns the indicator type (should be 0x0001)
    #[inline]
    pub fn indicator_type(&self) -> u16 {
        self.indicator_type.get()
    }

    /// Returns the client identifier length
    #[inline]
    pub fn id_len(&self) -> u8 {
        self.id_len
    }

    /// Returns the authentication value length
    #[inline]
    pub fn auth_len(&self) -> u8 {
        self.auth_len
    }

    /// Returns the total length of the authentication header including variable parts
    #[inline]
    pub fn total_len(&self) -> usize {
        Self::FIXED_SIZE
            + self.id_len as usize
            + self.auth_len as usize
            + Self::NONCE_SIZE
            + Self::CONFIRMATION_SIZE
    }

    /// Validates the authentication header
    #[inline]
    fn is_valid(&self) -> bool {
        self.indicator_type() == TEREDO_TYPE_AUTH
    }
}

impl PacketHeader for TeredoAuthHeader {
    const NAME: &'static str = "TeredoAuthHeader";
    type InnerType = IpProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        IpProto::IPV6
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        self.total_len()
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

/// Teredo Authentication with parsed fields
#[derive (Debug, Clone)]
pub struct TeredoAuthHeaderFull<'a> {
    /// Fixed header part
    pub header: &'a TeredoAuthHeader,
    /// Client identifier (variable length)
    pub client_id: &'a [u8],
    /// Authentication value (variable length)
    pub auth_value: &'a [u8],
    /// Nonce (8 bytes)
    pub nonce: &'a [u8],
    /// Confirmation byte
    pub confirmation: u8,
}

impl<'a> TeredoAuthHeaderFull<'a> {
    /// Returns the total length of this authentication header
    #[inline]
    pub fn total_len(&self) -> usize {
        self.header.total_len()
    }
}

impl std::ops::Deref for TeredoAuthHeaderFull<'_> {
    type Target = TeredoAuthHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl HeaderParser for TeredoAuthHeader {
    type Output<'a> = TeredoAuthHeaderFull<'a>;

    fn into_view<'a>(header: &'a Self, options: &'a [u8]) -> Self::Output<'a> {
        let id_len = header.id_len() as usize;
        let auth_len = header.auth_len() as usize;

        let client_id = &options[..id_len];
        let auth_value = &options[id_len..id_len + auth_len];
        let nonce_start = id_len + auth_len;
        let nonce = &options[nonce_start..nonce_start + TeredoAuthHeader::NONCE_SIZE];
        let confirmation = options[nonce_start + TeredoAuthHeader::NONCE_SIZE];

        TeredoAuthHeaderFull {
            header,
            client_id,
            auth_value,
            nonce,
            confirmation,
        }
    }
}

impl fmt::Display for TeredoAuthHeaderFull<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TeredoAuth id_len={} auth_len={} confirmation={}",
            self.header.id_len(),
            self.header.auth_len(),
            self.confirmation
        )
    }
}

/// Teredo indicator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeredoIndicator {
    /// Origin Indication (type 0x0000)
    Origin,
    /// Authentication (type 0x0001)
    Authentication,
    /// Direct IPv6 packet (no indicator)
    None,
}

impl TeredoIndicator {
    /// Detect the indicator type from the first bytes
    pub fn detect(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }

        // Check if this is an IPv6 packet (version nibble = 6)
        if (buf[0] & IPV6_VERSION_MASK) == IPV6_VERSION_NIBBLE {
            return Some(TeredoIndicator::None);
        }

        let indicator_type = u16::from_be_bytes([buf[0], buf[1]]);

        match indicator_type {
            TEREDO_TYPE_ORIGIN => Some(TeredoIndicator::Origin),
            TEREDO_TYPE_AUTH => Some(TeredoIndicator::Authentication),
            _ => None, // Unknown indicator type
        }
    }
}

/// Parsed Teredo packet (for complex cases with optional Authentication)
///
/// Use this when you need to handle all Teredo variants including Authentication.
/// For simple Origin Indication parsing, use `TeredoHeader::from_bytes()` directly.
#[derive (Debug, Clone)]
pub struct TeredoPacket<'a> {
    /// Authentication header (if present)
    authentication: Option<TeredoAuthHeaderFull<'a>>,
    /// Origin indication header (if present)
    origin_indication: Option<&'a TeredoHeader>,
    /// IPv6 payload
    ipv6_payload: &'a [u8],
    /// Total header length (before IPv6)
    header_len: usize,
}

impl<'a> TeredoPacket<'a> {
    /// Parse a Teredo packet from the buffer (after UDP header)
    ///
    /// The buffer should contain the UDP payload of a Teredo packet.
    /// This will parse any authentication and origin indication headers
    /// and return the IPv6 payload.
    pub fn parse(buf: &'a [u8]) -> Result<Self, PacketHeaderError> {
        let mut offset = 0;
        let mut authentication = None;
        let mut origin_indication = None;

        // First, check for Authentication header
        if let Some(TeredoIndicator::Authentication) = TeredoIndicator::detect(&buf[offset..]) {
            let (auth, rest) = TeredoAuthHeader::from_bytes(&buf[offset..])?;
            offset = buf.len() - rest.len();
            authentication = Some(auth);
        }

        // Then, check for Origin Indication
        if let Some(TeredoIndicator::Origin) = TeredoIndicator::detect(&buf[offset..]) {
            let (origin, _) = TeredoHeader::from_bytes(&buf[offset..])?;
            origin_indication = Some(origin);
            offset += TeredoHeader::FIXED_LEN;
        }

        // Verify we have an IPv6 packet
        if buf.len() <= offset {
            return Err(PacketHeaderError::TooShort("TeredoPacket"));
        }

        // Check for IPv6 version
        if (buf[offset] & IPV6_VERSION_MASK) != IPV6_VERSION_NIBBLE {
            return Err(PacketHeaderError::Invalid("TeredoPacket: not IPv6"));
        }

        let ipv6_payload = &buf[offset..];

        Ok(TeredoPacket {
            authentication,
            origin_indication,
            ipv6_payload,
            header_len: offset,
        })
    }

    /// Returns the authentication header if present
    #[inline]
    pub fn authentication(&self) -> Option<&TeredoAuthHeaderFull<'a>> {
        self.authentication.as_ref()
    }

    /// Returns the origin indication header if present
    #[inline]
    pub fn origin_indication(&self) -> Option<&TeredoHeader> {
        self.origin_indication
    }

    /// Returns the IPv6 payload
    #[inline]
    pub fn ipv6_payload(&self) -> &'a [u8] {
        self.ipv6_payload
    }

    /// Returns the total Teredo header length (before IPv6)
    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Returns true if any Teredo indicators are present
    #[inline]
    pub fn has_indicators(&self) -> bool {
        self.authentication.is_some() || self.origin_indication.is_some()
    }
}

impl fmt::Display for TeredoPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Teredo")?;

        if let Some(auth) = &self.authentication {
            write!(f, " [{}]", auth)?;
        }

        if let Some(origin) = self.origin_indication {
            write!(f, " [{}]", origin)?;
        }

        write!(f, " ipv6_len={}", self.ipv6_payload.len())
    }
}

/// Check if a UDP packet might be Teredo based on ports
#[inline]
pub fn is_teredo_port(src_port: u16, dst_port: u16) -> bool {
    src_port == TEREDO_PORT || dst_port == TEREDO_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_minimal_ipv6() -> Vec<u8> {
        vec![
            0x60, 0x00, 0x00, 0x00, // version, traffic class, flow label
            0x00, 0x00, 0x3a, 0x40, // payload length, next header (ICMPv6), hop limit
            // Source address (::1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination address (::1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]
    }

    #[test]
    fn test_teredo_header_size() {
        assert_eq!(std::mem::size_of::<TeredoHeader>(), 8);
        assert_eq!(TeredoHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_auth_header_size() {
        assert_eq!(std::mem::size_of::<TeredoAuthHeader>(), 4);
        assert_eq!(TeredoAuthHeader::FIXED_SIZE, 4);
    }

    #[test]
    fn test_teredo_header_parsing() {
        let header = TeredoHeader {
            indicator_type: U16::new(TEREDO_TYPE_ORIGIN),
            obfuscated_port: U16::new(0xFFFF ^ 0x1234), // Port 0x1234
            obfuscated_ipv4: U32::new(0xFFFFFFFF ^ 0xC0A80164), // 192.168.1.100
        };

        assert_eq!(header.indicator_type(), TEREDO_TYPE_ORIGIN);
        assert_eq!(header.port(), 0x1234);
        assert_eq!(header.ipv4_addr(), Ipv4Addr::new(192, 168, 1, 100));
        assert!(header.is_valid());
    }

    #[test]
    fn test_teredo_header_obfuscation() {
        // Port 80 obfuscated
        let header = TeredoHeader {
            indicator_type: U16::new(TEREDO_TYPE_ORIGIN),
            obfuscated_port: U16::new(0xFFFF ^ 80),
            obfuscated_ipv4: U32::new(0xFFFFFFFF ^ 0x0A000001), // 10.0.0.1
        };

        assert_eq!(header.port(), 80);
        assert_eq!(header.ipv4_addr(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_teredo_header_from_bytes() {
        let mut packet = Vec::new();

        // Origin Indication
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Type
        packet.extend_from_slice(&(0xFFFFu16 ^ 0x1234).to_be_bytes()); // Obfuscated port
        packet.extend_from_slice(&(0xFFFFFFFFu32 ^ 0xC0A80101).to_be_bytes()); // Obfuscated IPv4

        // IPv6 header (payload)
        packet.extend_from_slice(&create_minimal_ipv6());

        let (header, ipv6_payload) = TeredoHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.port(), 0x1234);
        assert_eq!(header.ipv4_addr(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ipv6_payload.len(), 40);
        assert_eq!(header.inner_type(), IpProto::IPV6);
    }

    #[test]
    fn test_teredo_header_invalid_type() {
        let mut packet = Vec::new();

        // Wrong type (Auth instead of Origin)
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Type = Auth
        packet.extend_from_slice(&0xFFFFu16.to_be_bytes());
        packet.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes());

        let result = TeredoHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_teredo_header_too_short() {
        let packet = vec![0x00, 0x00, 0xFF, 0xFF]; // Only 4 bytes, need 8
        let result = TeredoHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_indicator_detect_ipv6() {
        let ipv6 = create_minimal_ipv6();
        let indicator = TeredoIndicator::detect(&ipv6);
        assert_eq!(indicator, Some(TeredoIndicator::None));
    }

    #[test]
    fn test_indicator_detect_origin() {
        let buf = vec![0x00, 0x00, 0xFF, 0xFF]; // Type 0x0000
        let indicator = TeredoIndicator::detect(&buf);
        assert_eq!(indicator, Some(TeredoIndicator::Origin));
    }

    #[test]
    fn test_indicator_detect_auth() {
        let buf = vec![0x00, 0x01, 0x00, 0x00]; // Type 0x0001
        let indicator = TeredoIndicator::detect(&buf);
        assert_eq!(indicator, Some(TeredoIndicator::Authentication));
    }

    #[test]
    fn test_parse_direct_ipv6() {
        let packet = create_minimal_ipv6();

        let teredo = TeredoPacket::parse(&packet).unwrap();
        assert!(teredo.authentication().is_none());
        assert!(teredo.origin_indication().is_none());
        assert!(!teredo.has_indicators());
        assert_eq!(teredo.header_len(), 0);
        assert_eq!(teredo.ipv6_payload().len(), 40);
    }

    #[test]
    fn test_parse_with_origin_indication() {
        let mut packet = Vec::new();

        // Origin Indication
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Type
        packet.extend_from_slice(&(0xFFFFu16 ^ 0x1234).to_be_bytes()); // Obfuscated port
        packet.extend_from_slice(&(0xFFFFFFFFu32 ^ 0xC0A80101).to_be_bytes()); // Obfuscated IPv4

        // IPv6 header
        packet.extend_from_slice(&create_minimal_ipv6());

        let teredo = TeredoPacket::parse(&packet).unwrap();
        assert!(teredo.authentication().is_none());
        assert!(teredo.origin_indication().is_some());
        assert!(teredo.has_indicators());
        assert_eq!(teredo.header_len(), 8);

        let origin = teredo.origin_indication().unwrap();
        assert_eq!(origin.port(), 0x1234);
        assert_eq!(origin.ipv4_addr(), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_with_authentication() {
        let mut packet = Vec::new();

        // Authentication header
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Type
        packet.push(4); // ID-len
        packet.push(8); // AU-len
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // Client ID (4 bytes)
        packet.extend_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8]); // Auth value (8 bytes)
        packet.extend_from_slice(&[0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8]); // Nonce (8 bytes)
        packet.push(0x00); // Confirmation

        // IPv6 header
        packet.extend_from_slice(&create_minimal_ipv6());

        let teredo = TeredoPacket::parse(&packet).unwrap();
        assert!(teredo.authentication().is_some());
        assert!(teredo.origin_indication().is_none());
        assert!(teredo.has_indicators());

        let auth = teredo.authentication().unwrap();
        assert_eq!(auth.header.id_len(), 4);
        assert_eq!(auth.header.auth_len(), 8);
        assert_eq!(auth.client_id, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(auth.nonce.len(), 8);
        assert_eq!(auth.confirmation, 0x00);
    }

    #[test]
    fn test_parse_with_auth_and_origin() {
        let mut packet = Vec::new();

        // Authentication header (minimal)
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Type
        packet.push(0); // ID-len = 0
        packet.push(0); // AU-len = 0
        packet.extend_from_slice(&[0x00; 8]); // Nonce
        packet.push(0x00); // Confirmation

        // Origin Indication
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Type
        packet.extend_from_slice(&(0xFFFFu16 ^ 3544).to_be_bytes()); // Teredo port
        packet.extend_from_slice(&(0xFFFFFFFFu32 ^ 0x08080808).to_be_bytes()); // 8.8.8.8

        // IPv6 header
        packet.extend_from_slice(&create_minimal_ipv6());

        let teredo = TeredoPacket::parse(&packet).unwrap();
        assert!(teredo.authentication().is_some());
        assert!(teredo.origin_indication().is_some());
        assert!(teredo.has_indicators());

        let origin = teredo.origin_indication().unwrap();
        assert_eq!(origin.port(), 3544);
        assert_eq!(origin.ipv4_addr(), Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn test_parse_too_short() {
        let packet = vec![0x00]; // Too short
        assert!(TeredoPacket::parse(&packet).is_err());
    }

    #[test]
    fn test_parse_no_ipv6() {
        let packet = vec![
            0x00, 0x00, // Origin indication type
            0xFF, 0xFF, // Port
            0xFF, 0xFF, 0xFF, 0xFF, // IPv4
                  // Missing IPv6
        ];
        assert!(TeredoPacket::parse(&packet).is_err());
    }

    #[test]
    fn test_parse_invalid_ipv6_version() {
        let mut packet = vec![
            0x00, 0x00, // Origin indication type
            0xFF, 0xFF, // Port
            0xFF, 0xFF, 0xFF, 0xFF, // IPv4
        ];
        // Invalid "IPv6" with version 4
        packet.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]);

        assert!(TeredoPacket::parse(&packet).is_err());
    }

    #[test]
    fn test_teredo_port_check() {
        assert!(is_teredo_port(3544, 12345));
        assert!(is_teredo_port(12345, 3544));
        assert!(is_teredo_port(3544, 3544));
        assert!(!is_teredo_port(80, 443));
    }

    #[test]
    fn test_display_teredo_header() {
        let header = TeredoHeader {
            indicator_type: U16::new(TEREDO_TYPE_ORIGIN),
            obfuscated_port: U16::new(0xFFFF ^ 1234),
            obfuscated_ipv4: U32::new(0xFFFFFFFF ^ 0x0A000001),
        };

        let display = format!("{}", header);
        assert!(display.contains("Teredo"));
        assert!(display.contains("port=1234"));
        assert!(display.contains("10.0.0.1"));
    }

    #[test]
    fn test_display_packet() {
        let packet = create_minimal_ipv6();
        let teredo = TeredoPacket::parse(&packet).unwrap();

        let display = format!("{}", teredo);
        assert!(display.contains("Teredo"));
        assert!(display.contains("ipv6_len=40"));
    }

    #[test]
    fn test_auth_total_len() {
        let fixed = TeredoAuthHeader {
            indicator_type: U16::new(TEREDO_TYPE_AUTH),
            id_len: 4,
            auth_len: 8,
        };

        // 4 (fixed) + 4 (id) + 8 (auth) + 8 (nonce) + 1 (confirmation) = 25
        assert_eq!(fixed.total_len(), 25);
    }

    #[test]
    fn test_auth_minimal() {
        let fixed = TeredoAuthHeader {
            indicator_type: U16::new(TEREDO_TYPE_AUTH),
            id_len: 0,
            auth_len: 0,
        };

        // 4 (fixed) + 0 (id) + 0 (auth) + 8 (nonce) + 1 (confirmation) = 13
        assert_eq!(fixed.total_len(), 13);
        assert!(fixed.is_valid());
    }

    #[test]
    fn test_auth_header_from_bytes() {
        let mut packet = Vec::new();

        // Authentication header
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Type
        packet.push(2); // ID-len
        packet.push(4); // AU-len
        packet.extend_from_slice(&[0x01, 0x02]); // Client ID (2 bytes)
        packet.extend_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4]); // Auth value (4 bytes)
        packet.extend_from_slice(&[0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8]); // Nonce
        packet.push(0x42); // Confirmation

        // Some payload
        packet.extend_from_slice(&[0x60, 0x00]); // IPv6 start

        let (auth, _payload) = TeredoAuthHeader::from_bytes(&packet).unwrap();
        assert_eq!(auth.id_len(), 2);
        assert_eq!(auth.auth_len(), 4);
        assert_eq!(auth.client_id, &[0x01, 0x02]);
        assert_eq!(auth.auth_value, &[0xA1, 0xA2, 0xA3, 0xA4]);
        assert_eq!(auth.confirmation, 0x42);
        assert_eq!(auth.inner_type(), IpProto::IPV6);
    }

    #[test]
    fn test_real_world_teredo_address() {
        // Teredo addresses encode the server, flags, NAT port, and client IPv4
        // Example: server 65.54.227.120, port 40000, client 192.0.2.45

        let header = TeredoHeader {
            indicator_type: U16::new(TEREDO_TYPE_ORIGIN),
            obfuscated_port: U16::new(0xFFFF ^ 40000),
            obfuscated_ipv4: U32::new(0xFFFFFFFF ^ 0xC000022D), // 192.0.2.45
        };

        assert_eq!(header.port(), 40000);
        assert_eq!(header.ipv4_addr(), Ipv4Addr::new(192, 0, 2, 45));
    }
}
