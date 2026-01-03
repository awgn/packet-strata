//! BSD Null/Loopback encapsulation header implementation
//!
//! The Null/Loopback link type is used by BSD systems (FreeBSD, macOS, etc.)
//! for the loopback interface. It consists of a 4-byte protocol family field
//! that indicates the network layer protocol.
//!
//! # Header Format (4 bytes)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Protocol Family                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The protocol family field uses BSD `AF_*` constants in **host byte order**
//! (little-endian on most systems, but can be big-endian on some).
//!
//! # Common Protocol Family Values
//!
//! | Value | Protocol |
//! |-------|----------|
//! | 2     | AF_INET (IPv4) |
//! | 24/28/30 | AF_INET6 (IPv6) - varies by OS |
//!
//! # Examples
//!
//! ## Basic Null header parsing
//!
//! ```
//! use packet_strata::packet::null::NullHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // Null header with IPv4 payload (little-endian AF_INET = 2)
//! let packet = vec![
//!     0x02, 0x00, 0x00, 0x00,  // Protocol family: AF_INET (IPv4)
//!     // IPv4 payload follows...
//!     0x45, 0x00, 0x00, 0x28,  // IPv4 header start
//! ];
//!
//! let (header, payload) = NullHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.protocol(), EtherProto::IPV4);
//! assert_eq!(payload.len(), 4);
//! ```
//!
//! ## IPv6 over loopback
//!
//! ```
//! use packet_strata::packet::null::NullHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // Null header with IPv6 payload (little-endian AF_INET6 = 30 on macOS/FreeBSD)
//! let packet = vec![
//!     0x1e, 0x00, 0x00, 0x00,  // Protocol family: AF_INET6 (IPv6) on macOS
//!     // IPv6 payload follows...
//! ];
//!
//! let (header, payload) = NullHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.protocol(), EtherProto::IPV6);
//! ```
//!
//! # References
//!
//! - https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
//! - BSD socket.h AF_* constants

use std::fmt::{Display, Formatter};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// BSD Address Family values
///
/// These are the `AF_*` constants from BSD systems. Note that the values
/// can differ between operating systems, particularly for IPv6.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// AF_INET - IPv4
    Inet = 2,
    /// AF_INET6 - IPv6 (Linux value)
    Inet6Linux = 10,
    /// AF_INET6 - IPv6 (macOS/iOS value)
    Inet6Darwin = 30,
    /// AF_INET6 - IPv6 (FreeBSD value)
    Inet6FreeBsd = 28,
    /// AF_INET6 - IPv6 (OpenBSD value)
    Inet6OpenBsd = 24,
    /// Unknown address family
    Unknown(u32),
}

impl From<u32> for AddressFamily {
    fn from(value: u32) -> Self {
        match value {
            2 => AddressFamily::Inet,
            10 => AddressFamily::Inet6Linux,
            24 => AddressFamily::Inet6OpenBsd,
            28 => AddressFamily::Inet6FreeBsd,
            30 => AddressFamily::Inet6Darwin,
            other => AddressFamily::Unknown(other),
        }
    }
}

impl AddressFamily {
    /// Check if this address family represents IPv6
    pub fn is_ipv6(&self) -> bool {
        matches!(
            self,
            AddressFamily::Inet6Linux
                | AddressFamily::Inet6Darwin
                | AddressFamily::Inet6FreeBsd
                | AddressFamily::Inet6OpenBsd
        )
    }

    /// Convert to EtherProto for compatibility with the rest of the stack
    pub fn to_ether_proto(&self) -> EtherProto {
        match self {
            AddressFamily::Inet => EtherProto::IPV4,
            AddressFamily::Inet6Linux
            | AddressFamily::Inet6Darwin
            | AddressFamily::Inet6FreeBsd
            | AddressFamily::Inet6OpenBsd => EtherProto::IPV6,
            AddressFamily::Unknown(_) => EtherProto::from(0u16),
        }
    }
}

impl Display for AddressFamily {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::Inet => write!(f, "AF_INET"),
            AddressFamily::Inet6Linux => write!(f, "AF_INET6 (Linux)"),
            AddressFamily::Inet6Darwin => write!(f, "AF_INET6 (Darwin)"),
            AddressFamily::Inet6FreeBsd => write!(f, "AF_INET6 (FreeBSD)"),
            AddressFamily::Inet6OpenBsd => write!(f, "AF_INET6 (OpenBSD)"),
            AddressFamily::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// BSD Null/Loopback header
///
/// This is the link-layer header used on BSD loopback interfaces.
/// It consists of a single 4-byte field containing the address family
/// in host byte order.
///
/// # Wire Format
///
/// The header is 4 bytes containing the protocol family in host byte order.
/// Since most systems are little-endian, we parse it as little-endian by default,
/// but also check for big-endian encoding for portability.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct NullHeader {
    /// Protocol family in host byte order (typically little-endian)
    family: [u8; 4],
}

impl NullHeader {
    /// Header size in bytes
    pub const SIZE: usize = 4;

    /// Get the raw protocol family value (little-endian interpretation)
    #[inline]
    pub fn family_raw_le(&self) -> u32 {
        u32::from_le_bytes(self.family)
    }

    /// Get the raw protocol family value (big-endian interpretation)
    #[inline]
    pub fn family_raw_be(&self) -> u32 {
        u32::from_be_bytes(self.family)
    }

    /// Get the address family
    ///
    /// This method tries to detect the byte order by checking if the value
    /// makes sense as a known address family. It first tries little-endian
    /// (most common), then big-endian.
    #[inline]
    pub fn address_family(&self) -> AddressFamily {
        let le_value = self.family_raw_le();
        let be_value = self.family_raw_be();

        // Try little-endian first (most common)
        match le_value {
            2 | 10 | 24 | 28 | 30 => AddressFamily::from(le_value),
            _ => {
                // Try big-endian
                match be_value {
                    2 | 10 | 24 | 28 | 30 => AddressFamily::from(be_value),
                    // Default to little-endian interpretation
                    _ => AddressFamily::from(le_value),
                }
            }
        }
    }

    /// Get the protocol as EtherProto for compatibility with the iterator
    #[inline]
    pub fn protocol(&self) -> EtherProto {
        self.address_family().to_ether_proto()
    }
}

impl PacketHeader for NullHeader {
    const NAME: &'static str = "Null/Loopback";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.protocol()
    }
}

impl HeaderParser for NullHeader {
    type Output<'a> = &'a NullHeader;

    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl Display for NullHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Null family={} (0x{:08x})",
            self.address_family(),
            self.family_raw_le()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_header_size() {
        assert_eq!(std::mem::size_of::<NullHeader>(), 4);
        assert_eq!(NullHeader::SIZE, 4);
    }

    #[test]
    fn test_null_header_ipv4_le() {
        // Little-endian AF_INET = 2
        let packet = vec![0x02, 0x00, 0x00, 0x00, 0x45, 0x00]; // + some IPv4 data

        let (header, payload) = NullHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.family_raw_le(), 2);
        assert_eq!(header.address_family(), AddressFamily::Inet);
        assert_eq!(header.protocol(), EtherProto::IPV4);
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_null_header_ipv6_darwin() {
        // Little-endian AF_INET6 on macOS = 30
        let packet = vec![0x1e, 0x00, 0x00, 0x00, 0x60, 0x00]; // + some IPv6 data

        let (header, payload) = NullHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.family_raw_le(), 30);
        assert_eq!(header.address_family(), AddressFamily::Inet6Darwin);
        assert!(header.address_family().is_ipv6());
        assert_eq!(header.protocol(), EtherProto::IPV6);
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_null_header_ipv6_linux() {
        // Little-endian AF_INET6 on Linux = 10
        let packet = vec![0x0a, 0x00, 0x00, 0x00];

        let (header, _payload) = NullHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.family_raw_le(), 10);
        assert_eq!(header.address_family(), AddressFamily::Inet6Linux);
        assert!(header.address_family().is_ipv6());
        assert_eq!(header.protocol(), EtherProto::IPV6);
    }

    #[test]
    fn test_null_header_ipv6_freebsd() {
        // Little-endian AF_INET6 on FreeBSD = 28
        let packet = vec![0x1c, 0x00, 0x00, 0x00];

        let (header, _payload) = NullHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.family_raw_le(), 28);
        assert_eq!(header.address_family(), AddressFamily::Inet6FreeBsd);
        assert!(header.address_family().is_ipv6());
    }

    #[test]
    fn test_null_header_ipv6_openbsd() {
        // Little-endian AF_INET6 on OpenBSD = 24
        let packet = vec![0x18, 0x00, 0x00, 0x00];

        let (header, _payload) = NullHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.family_raw_le(), 24);
        assert_eq!(header.address_family(), AddressFamily::Inet6OpenBsd);
        assert!(header.address_family().is_ipv6());
    }

    #[test]
    fn test_null_header_ipv4_be() {
        // Big-endian AF_INET = 2 (some old captures might have this)
        let packet = vec![0x00, 0x00, 0x00, 0x02];

        let (header, _payload) = NullHeader::from_bytes(&packet).unwrap();

        // Should detect big-endian and return correct family
        assert_eq!(header.address_family(), AddressFamily::Inet);
        assert_eq!(header.protocol(), EtherProto::IPV4);
    }

    #[test]
    fn test_null_header_unknown() {
        // Unknown address family
        let packet = vec![0xff, 0x00, 0x00, 0x00];

        let (header, _payload) = NullHeader::from_bytes(&packet).unwrap();

        assert!(matches!(
            header.address_family(),
            AddressFamily::Unknown(255)
        ));
        assert_eq!(header.protocol(), EtherProto::from(0u16));
    }

    #[test]
    fn test_null_header_too_short() {
        let packet = vec![0x02, 0x00, 0x00]; // Only 3 bytes

        let result = NullHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_null_header_display() {
        let packet = vec![0x02, 0x00, 0x00, 0x00];
        let (header, _) = NullHeader::from_bytes(&packet).unwrap();

        let display = format!("{}", header);
        assert!(display.contains("Null"));
        assert!(display.contains("family="));
        assert!(display.contains("AF_INET"));
    }

    #[test]
    fn test_address_family_display() {
        assert_eq!(format!("{}", AddressFamily::Inet), "AF_INET");
        assert_eq!(format!("{}", AddressFamily::Inet6Linux), "AF_INET6 (Linux)");
        assert_eq!(
            format!("{}", AddressFamily::Inet6Darwin),
            "AF_INET6 (Darwin)"
        );
        assert_eq!(format!("{}", AddressFamily::Unknown(99)), "Unknown(99)");
    }

    #[test]
    fn test_packet_header_trait() {
        let packet = vec![0x02, 0x00, 0x00, 0x00];
        let (header, _) = NullHeader::from_bytes(&packet).unwrap();

        assert_eq!(NullHeader::NAME, "Null/Loopback");
        assert_eq!(header.inner_type(), EtherProto::IPV4);
    }
}
