//! Linux Cooked Capture (SLL and SLLv2) header implementations
//!
//! SLL (Linux Cooked Capture) is a pseudo-header used by libpcap when capturing
//! on the "any" device or on devices that don't have a link-layer header.
//!
//! # SLL Header Format (16 bytes)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Packet Type           |          ARPHRD Type          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Link-layer address length  |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! |                    Link-layer address (8 bytes)               |
//! +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |          Protocol Type        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # SLLv2 Header Format (20 bytes)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Protocol Type         |         Reserved (MBZ)        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Interface Index                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          ARPHRD Type          |         Packet Type           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Link-layer address length  |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! |                    Link-layer address (8 bytes)               |
//! +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Examples
//!
//! ## Basic SLL parsing
//!
//! ```
//! use packet_strata::packet::sll::SllHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // SLL header with IPv4 payload
//! let packet = vec![
//!     0x00, 0x00,                          // Packet type: Host (0)
//!     0x00, 0x01,                          // ARPHRD type: Ethernet (1)
//!     0x00, 0x06,                          // Address length: 6
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Link-layer address
//!     0x00, 0x00,                          // Padding
//!     0x08, 0x00,                          // Protocol: IPv4
//!     // IPv4 payload follows...
//! ];
//!
//! let (header, payload) = SllHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.protocol(), EtherProto::IPV4);
//! assert_eq!(header.ll_addr_len(), 6);
//! ```
//!
//! ## SLLv2 parsing
//!
//! ```
//! use packet_strata::packet::sll::Sllv2Header;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // SLLv2 header with IPv6 payload
//! let packet = vec![
//!     0x86, 0xDD,                          // Protocol: IPv6
//!     0x00, 0x00,                          // Reserved
//!     0x00, 0x00, 0x00, 0x02,              // Interface index: 2
//!     0x00, 0x01,                          // ARPHRD type: Ethernet
//!     0x04,                                // Packet type: Outgoing (4)
//!     0x06,                                // Address length: 6
//!     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Link-layer address
//!     0x00, 0x00,                          // Padding
//!     // IPv6 payload follows...
//! ];
//!
//! let (header, payload) = Sllv2Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.protocol(), EtherProto::IPV6);
//! assert_eq!(header.interface_index(), 2);
//! ```
//!
//! # References
//!
//! - https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
//! - https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html

use core::fmt;
use std::fmt::{Display, Formatter};

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// SLL packet type indicating the direction/type of the packet
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SllPacketType {
    /// Packet was sent to us by somebody else
    Host = 0,
    /// Packet was broadcast by somebody else
    Broadcast = 1,
    /// Packet was multicast, but not broadcast, by somebody else
    Multicast = 2,
    /// Packet was sent by somebody else to somebody else
    OtherHost = 3,
    /// Packet was sent by us
    Outgoing = 4,
    /// Packet was sent by us (kernel loopback)
    LoopbackOutgoing = 5,
    /// Packet was fastrouted (internal use)
    FastRoute = 6,
    /// Unknown packet type
    Unknown(u16),
}

impl From<u16> for SllPacketType {
    fn from(value: u16) -> Self {
        match value {
            0 => SllPacketType::Host,
            1 => SllPacketType::Broadcast,
            2 => SllPacketType::Multicast,
            3 => SllPacketType::OtherHost,
            4 => SllPacketType::Outgoing,
            5 => SllPacketType::LoopbackOutgoing,
            6 => SllPacketType::FastRoute,
            v => SllPacketType::Unknown(v),
        }
    }
}

impl Display for SllPacketType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SllPacketType::Host => write!(f, "Host"),
            SllPacketType::Broadcast => write!(f, "Broadcast"),
            SllPacketType::Multicast => write!(f, "Multicast"),
            SllPacketType::OtherHost => write!(f, "OtherHost"),
            SllPacketType::Outgoing => write!(f, "Outgoing"),
            SllPacketType::LoopbackOutgoing => write!(f, "LoopbackOutgoing"),
            SllPacketType::FastRoute => write!(f, "FastRoute"),
            SllPacketType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// ARPHRD types (subset of common ones)
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArphrdType {
    /// Ethernet 10/100Mbps
    Ether = 1,
    /// IEEE 802.11
    Ieee80211 = 801,
    /// IEEE 802.11 + Radiotap header
    Ieee80211Radiotap = 803,
    /// Loopback device
    Loopback = 772,
    /// PPP
    Ppp = 512,
    /// Unknown type
    Unknown(u16),
}

impl From<u16> for ArphrdType {
    fn from(value: u16) -> Self {
        match value {
            1 => ArphrdType::Ether,
            801 => ArphrdType::Ieee80211,
            803 => ArphrdType::Ieee80211Radiotap,
            772 => ArphrdType::Loopback,
            512 => ArphrdType::Ppp,
            v => ArphrdType::Unknown(v),
        }
    }
}

impl Display for ArphrdType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ArphrdType::Ether => write!(f, "Ethernet"),
            ArphrdType::Ieee80211 => write!(f, "IEEE802.11"),
            ArphrdType::Ieee80211Radiotap => write!(f, "IEEE802.11+Radiotap"),
            ArphrdType::Loopback => write!(f, "Loopback"),
            ArphrdType::Ppp => write!(f, "PPP"),
            ArphrdType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

// ============================================================================
// SLL (Linux Cooked Capture v1) - 16 bytes
// ============================================================================

/// SLL Header (Linux Cooked Capture v1)
///
/// Fixed 16-byte header format:
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Packet Type           |        ARPHRD Type            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Link-layer addr length    |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                    Link-layer address (8 bytes)               |
/// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout, Debug, Clone, Copy)]
pub struct SllHeader {
    /// Packet type (incoming, outgoing, etc.)
    packet_type: U16<BigEndian>,
    /// ARPHRD type (hardware type)
    arphrd_type: U16<BigEndian>,
    /// Link-layer address length
    ll_addr_len: U16<BigEndian>,
    /// Link-layer address (8 bytes, zero-padded if shorter)
    ll_addr: [u8; 8],
    /// Protocol type (EtherType)
    protocol: EtherProto,
}

impl SllHeader {
    /// Returns the packet type
    #[inline]
    pub fn packet_type(&self) -> SllPacketType {
        SllPacketType::from(self.packet_type.get())
    }

    /// Returns the raw packet type value
    #[inline]
    pub fn packet_type_raw(&self) -> u16 {
        self.packet_type.get()
    }

    /// Returns the ARPHRD type
    #[inline]
    pub fn arphrd_type(&self) -> ArphrdType {
        ArphrdType::from(self.arphrd_type.get())
    }

    /// Returns the raw ARPHRD type value
    #[inline]
    pub fn arphrd_type_raw(&self) -> u16 {
        self.arphrd_type.get()
    }

    /// Returns the link-layer address length
    #[inline]
    pub fn ll_addr_len(&self) -> u16 {
        self.ll_addr_len.get()
    }

    /// Returns the link-layer address (up to 8 bytes, use ll_addr_len for actual length)
    #[inline]
    pub fn ll_addr(&self) -> &[u8] {
        let len = std::cmp::min(self.ll_addr_len.get() as usize, 8);
        &self.ll_addr[..len]
    }

    /// Returns the full 8-byte link-layer address field
    #[inline]
    pub fn ll_addr_raw(&self) -> &[u8; 8] {
        &self.ll_addr
    }

    /// Returns the protocol type (EtherType)
    #[inline]
    pub fn protocol(&self) -> EtherProto {
        self.protocol
    }
}

impl PacketHeader for SllHeader {
    const NAME: &'static str = "SllHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.protocol
    }
}

impl HeaderParser for SllHeader {
    type Output<'a> = &'a SllHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl Display for SllHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SLL type={} hw={} proto={}",
            self.packet_type(),
            self.arphrd_type(),
            self.protocol()
        )?;

        // Format link-layer address if present
        let addr_len = self.ll_addr_len() as usize;
        if addr_len > 0 && addr_len <= 8 {
            write!(f, " addr=")?;
            for (i, byte) in self.ll_addr[..addr_len].iter().enumerate() {
                if i > 0 {
                    write!(f, ":")?;
                }
                write!(f, "{:02x}", byte)?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// SLLv2 (Linux Cooked Capture v2) - 20 bytes
// ============================================================================

/// SLLv2 Header (Linux Cooked Capture v2)
///
/// Fixed 20-byte header format:
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Protocol Type         |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Interface Index                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         ARPHRD Type           |  Packet Type  | LL Addr Len   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                    Link-layer address (8 bytes)               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout, Debug, Clone, Copy)]
pub struct Sllv2Header {
    /// Protocol type (EtherType)
    protocol: EtherProto,
    /// Reserved (must be zero)
    reserved: U16<BigEndian>,
    /// Interface index
    interface_index: U32<BigEndian>,
    /// ARPHRD type (hardware type)
    arphrd_type: U16<BigEndian>,
    /// Packet type (incoming, outgoing, etc.) - 1 byte in v2
    packet_type: u8,
    /// Link-layer address length - 1 byte in v2
    ll_addr_len: u8,
    /// Link-layer address (8 bytes, zero-padded if shorter)
    ll_addr: [u8; 8],
}

impl Sllv2Header {
    /// Returns the protocol type (EtherType)
    #[inline]
    pub fn protocol(&self) -> EtherProto {
        self.protocol
    }

    /// Returns the interface index
    #[inline]
    pub fn interface_index(&self) -> u32 {
        self.interface_index.get()
    }

    /// Returns the ARPHRD type
    #[inline]
    pub fn arphrd_type(&self) -> ArphrdType {
        ArphrdType::from(self.arphrd_type.get())
    }

    /// Returns the raw ARPHRD type value
    #[inline]
    pub fn arphrd_type_raw(&self) -> u16 {
        self.arphrd_type.get()
    }

    /// Returns the packet type
    #[inline]
    pub fn packet_type(&self) -> SllPacketType {
        SllPacketType::from(self.packet_type as u16)
    }

    /// Returns the raw packet type value
    #[inline]
    pub fn packet_type_raw(&self) -> u8 {
        self.packet_type
    }

    /// Returns the link-layer address length
    #[inline]
    pub fn ll_addr_len(&self) -> u8 {
        self.ll_addr_len
    }

    /// Returns the link-layer address (up to 8 bytes, use ll_addr_len for actual length)
    #[inline]
    pub fn ll_addr(&self) -> &[u8] {
        let len = std::cmp::min(self.ll_addr_len as usize, 8);
        &self.ll_addr[..len]
    }

    /// Returns the full 8-byte link-layer address field
    #[inline]
    pub fn ll_addr_raw(&self) -> &[u8; 8] {
        &self.ll_addr
    }
}

impl PacketHeader for Sllv2Header {
    const NAME: &'static str = "Sllv2Header";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.protocol
    }
}

impl HeaderParser for Sllv2Header {
    type Output<'a> = &'a Sllv2Header;

    #[inline]
    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl Display for Sllv2Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SLLv2 if={} type={} hw={} proto={}",
            self.interface_index(),
            self.packet_type(),
            self.arphrd_type(),
            self.protocol()
        )?;

        // Format link-layer address if present
        let addr_len = self.ll_addr_len as usize;
        if addr_len > 0 && addr_len <= 8 {
            write!(f, " addr=")?;
            for (i, byte) in self.ll_addr[..addr_len].iter().enumerate() {
                if i > 0 {
                    write!(f, ":")?;
                }
                write!(f, "{:02x}", byte)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_sll_header_size() {
        assert_eq!(mem::size_of::<SllHeader>(), 16);
        assert_eq!(SllHeader::FIXED_LEN, 16);
    }

    #[test]
    fn test_sllv2_header_size() {
        assert_eq!(mem::size_of::<Sllv2Header>(), 20);
        assert_eq!(Sllv2Header::FIXED_LEN, 20);
    }

    #[test]
    fn test_sll_header_parse() {
        // Example SLL header: Host, Ethernet, 6-byte MAC, IPv4
        let packet: [u8; 16] = [
            0x00, 0x00, // packet_type: Host (0)
            0x00, 0x01, // arphrd_type: Ethernet (1)
            0x00, 0x06, // ll_addr_len: 6
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, // ll_addr (6 bytes + 2 padding)
            0x08, 0x00, // protocol: IPv4
        ];

        let (header, remaining) =
            SllHeader::from_bytes(&packet).expect("Failed to parse SllHeader");

        assert_eq!(header.packet_type(), SllPacketType::Host);
        assert_eq!(header.arphrd_type(), ArphrdType::Ether);
        assert_eq!(header.ll_addr_len(), 6);
        assert_eq!(header.ll_addr(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(header.protocol(), EtherProto::IPV4);
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_sll_header_outgoing() {
        let packet: [u8; 16] = [
            0x00, 0x04, // packet_type: Outgoing (4)
            0x00, 0x01, // arphrd_type: Ethernet (1)
            0x00, 0x06, // ll_addr_len: 6
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00, // ll_addr
            0x86, 0xdd, // protocol: IPv6
        ];

        let (header, _) = SllHeader::from_bytes(&packet).expect("Failed to parse SllHeader");

        assert_eq!(header.packet_type(), SllPacketType::Outgoing);
        assert_eq!(header.protocol(), EtherProto::IPV6);
    }

    #[test]
    fn test_sllv2_header_parse() {
        // Example SLLv2 header
        let packet: [u8; 20] = [
            0x08, 0x00, // protocol: IPv4
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x02, // interface_index: 2
            0x00, 0x01, // arphrd_type: Ethernet (1)
            0x00, // packet_type: Host (0)
            0x06, // ll_addr_len: 6
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, // ll_addr
        ];

        let (header, remaining) =
            Sllv2Header::from_bytes(&packet).expect("Failed to parse Sllv2Header");

        assert_eq!(header.protocol(), EtherProto::IPV4);
        assert_eq!(header.interface_index(), 2);
        assert_eq!(header.arphrd_type(), ArphrdType::Ether);
        assert_eq!(header.packet_type(), SllPacketType::Host);
        assert_eq!(header.ll_addr_len(), 6);
        assert_eq!(header.ll_addr(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_sllv2_header_with_payload() {
        let mut packet = Vec::new();

        // SLLv2 header
        packet.extend_from_slice(&[
            0x08, 0x00, // protocol: IPv4
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x05, // interface_index: 5
            0x00, 0x01, // arphrd_type: Ethernet (1)
            0x04, // packet_type: Outgoing (4)
            0x06, // ll_addr_len: 6
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00, // ll_addr
        ]);

        // Add some payload
        packet.extend_from_slice(b"test payload");

        let (header, remaining) =
            Sllv2Header::from_bytes(&packet).expect("Failed to parse Sllv2Header");

        assert_eq!(header.protocol(), EtherProto::IPV4);
        assert_eq!(header.interface_index(), 5);
        assert_eq!(header.packet_type(), SllPacketType::Outgoing);
        assert_eq!(remaining, b"test payload");
    }

    #[test]
    fn test_sll_display() {
        let packet: [u8; 16] = [
            0x00, 0x00, // packet_type: Host
            0x00, 0x01, // arphrd_type: Ethernet
            0x00, 0x06, // ll_addr_len: 6
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x08, 0x00, // protocol: IPv4
        ];

        let (header, _) = SllHeader::from_bytes(&packet).unwrap();
        let display = format!("{}", header);

        assert!(display.contains("SLL"));
        assert!(display.contains("Host"));
        assert!(display.contains("Ethernet"));
        assert!(display.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_sllv2_display() {
        let packet: [u8; 20] = [
            0x08, 0x00, // protocol: IPv4
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x03, // interface_index: 3
            0x00, 0x01, // arphrd_type: Ethernet
            0x00, // packet_type: Host
            0x06, // ll_addr_len: 6
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00,
        ];

        let (header, _) = Sllv2Header::from_bytes(&packet).unwrap();
        let display = format!("{}", header);

        assert!(display.contains("SLLv2"));
        assert!(display.contains("if=3"));
        assert!(display.contains("Host"));
        assert!(display.contains("11:22:33:44:55:66"));
    }

    #[test]
    fn test_packet_type_display() {
        assert_eq!(format!("{}", SllPacketType::Host), "Host");
        assert_eq!(format!("{}", SllPacketType::Broadcast), "Broadcast");
        assert_eq!(format!("{}", SllPacketType::Multicast), "Multicast");
        assert_eq!(format!("{}", SllPacketType::OtherHost), "OtherHost");
        assert_eq!(format!("{}", SllPacketType::Outgoing), "Outgoing");
        assert_eq!(format!("{}", SllPacketType::Unknown(99)), "Unknown(99)");
    }

    #[test]
    fn test_arphrd_type_display() {
        assert_eq!(format!("{}", ArphrdType::Ether), "Ethernet");
        assert_eq!(format!("{}", ArphrdType::Loopback), "Loopback");
        assert_eq!(format!("{}", ArphrdType::Ieee80211), "IEEE802.11");
        assert_eq!(format!("{}", ArphrdType::Unknown(999)), "Unknown(999)");
    }

    #[test]
    fn test_sll_too_short() {
        let packet: [u8; 10] = [0; 10]; // Too short for SLL header

        let result = SllHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_sllv2_too_short() {
        let packet: [u8; 15] = [0; 15]; // Too short for SLLv2 header

        let result = Sllv2Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_sll_loopback() {
        let packet: [u8; 16] = [
            0x00, 0x04, // packet_type: Outgoing
            0x03, 0x04, // arphrd_type: Loopback (772 = 0x0304)
            0x00, 0x00, // ll_addr_len: 0 (loopback has no link-layer address)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, // protocol: IPv4
        ];

        let (header, _) = SllHeader::from_bytes(&packet).expect("Failed to parse");

        assert_eq!(header.arphrd_type(), ArphrdType::Loopback);
        assert_eq!(header.ll_addr_len(), 0);
        assert_eq!(header.ll_addr(), &[]);
    }
}
