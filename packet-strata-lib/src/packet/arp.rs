//! ARP (Address Resolution Protocol) packet parsing
//!
//! This module implements parsing for ARP packets as defined in RFC 826.
//! ARP is used to map network layer addresses (like IPv4) to link layer addresses (like MAC).
//!
//! # ARP Header Format (for Ethernet/IPv4)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Hardware Type         |         Protocol Type         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  HW Addr Len  | Proto Addr Len|          Operation            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Sender Hardware Address                    |
//! +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |    Sender Protocol Address    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Sender Protocol Address    |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! |                    Target Hardware Address                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Target Protocol Address                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Fixed header size: 8 bytes (before variable-length addresses)
//! - For Ethernet/IPv4: 28 bytes total (6+4+6+4 for addresses)
//! - Hardware Type: 1 for Ethernet
//! - Protocol Type: 0x0800 for IPv4
//! - Operation: 1 (Request), 2 (Reply)
//!
//! # Examples
//!
//! ```no_run
//! use packet_strata::packet::arp::{ArpHeader, ArpOperation};
//! use packet_strata::packet::HeaderParser;
//! use std::net::Ipv4Addr;
//!
//! # fn main() {
//! # let packet_bytes: Vec<u8> = vec![]; // ARP packet data
//! let (arp_header, remaining) = ArpHeader::from_bytes(&packet_bytes).unwrap();
//!
//! // Check if it's a request or reply
//! match arp_header.operation() {
//!     ArpOperation::REQUEST => println!("ARP Request"),
//!     ArpOperation::REPLY => println!("ARP Reply"),
//!     _ => println!("Other ARP operation"),
//! }
//!
//! // For Ethernet/IPv4 ARP, access IP addresses
//! if let Some(sender_ip) = arp_header.sender_ipv4() {
//!     println!("Sender IP: {}", sender_ip);
//! }
//! # }
//! ```

use core::fmt;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use std::ops::Deref;
use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::ether::EthAddr;
use crate::packet::{HeaderParser, PacketHeader};

/// ARP Hardware Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct ArpHardwareType(pub U16<BigEndian>);

impl ArpHardwareType {
    pub const ETHERNET: ArpHardwareType = ArpHardwareType(U16::new(1)); // Ethernet (10Mb)
    pub const EXPERIMENTAL_ETHERNET: ArpHardwareType = ArpHardwareType(U16::new(2)); // Experimental Ethernet (3Mb)
    pub const AX25: ArpHardwareType = ArpHardwareType(U16::new(3)); // Amateur Radio AX.25
    pub const PROTEON_TOKEN_RING: ArpHardwareType = ArpHardwareType(U16::new(4)); // Proteon ProNET Token Ring
    pub const CHAOS: ArpHardwareType = ArpHardwareType(U16::new(5)); // Chaos
    pub const IEEE802: ArpHardwareType = ArpHardwareType(U16::new(6)); // IEEE 802 Networks
    pub const ARCNET: ArpHardwareType = ArpHardwareType(U16::new(7)); // ARCNET
    pub const HYPERCHANNEL: ArpHardwareType = ArpHardwareType(U16::new(8)); // Hyperchannel
    pub const LANSTAR: ArpHardwareType = ArpHardwareType(U16::new(9)); // Lanstar
    pub const AUTONET: ArpHardwareType = ArpHardwareType(U16::new(10)); // Autonet Short Address
    pub const LOCALTALK: ArpHardwareType = ArpHardwareType(U16::new(11)); // LocalTalk
    pub const LOCALNET: ArpHardwareType = ArpHardwareType(U16::new(12)); // LocalNet (IBM PCNet or SYTEK LocalNET)
    pub const ULTRA_LINK: ArpHardwareType = ArpHardwareType(U16::new(13)); // Ultra link
    pub const SMDS: ArpHardwareType = ArpHardwareType(U16::new(14)); // SMDS
    pub const FRAME_RELAY: ArpHardwareType = ArpHardwareType(U16::new(15)); // Frame Relay
    pub const ATM: ArpHardwareType = ArpHardwareType(U16::new(16)); // Asynchronous Transmission Mode (ATM)
    pub const HDLC: ArpHardwareType = ArpHardwareType(U16::new(17)); // HDLC
    pub const FIBRE_CHANNEL: ArpHardwareType = ArpHardwareType(U16::new(18)); // Fibre Channel
    pub const ATM_2: ArpHardwareType = ArpHardwareType(U16::new(19)); // Asynchronous Transmission Mode (ATM)
    pub const SERIAL_LINE: ArpHardwareType = ArpHardwareType(U16::new(20)); // Serial Line

    #[inline]
    pub fn value(&self) -> u16 {
        self.0.get()
    }
}

impl Display for ArpHardwareType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let name = match *self {
            ArpHardwareType::ETHERNET => "ethernet",
            ArpHardwareType::EXPERIMENTAL_ETHERNET => "exp-ethernet",
            ArpHardwareType::AX25 => "ax25",
            ArpHardwareType::PROTEON_TOKEN_RING => "token-ring",
            ArpHardwareType::CHAOS => "chaos",
            ArpHardwareType::IEEE802 => "ieee802",
            ArpHardwareType::ARCNET => "arcnet",
            ArpHardwareType::HYPERCHANNEL => "hyperchannel",
            ArpHardwareType::LANSTAR => "lanstar",
            ArpHardwareType::AUTONET => "autonet",
            ArpHardwareType::LOCALTALK => "localtalk",
            ArpHardwareType::LOCALNET => "localnet",
            ArpHardwareType::ULTRA_LINK => "ultra-link",
            ArpHardwareType::SMDS => "smds",
            ArpHardwareType::FRAME_RELAY => "frame-relay",
            ArpHardwareType::ATM => "atm",
            ArpHardwareType::HDLC => "hdlc",
            ArpHardwareType::FIBRE_CHANNEL => "fibre-channel",
            ArpHardwareType::ATM_2 => "atm2",
            ArpHardwareType::SERIAL_LINE => "serial-line",
            _ => return write!(f, "unknown({})", self.value()),
        };
        write!(f, "{}", name)
    }
}

/// ARP Protocol Type (typically matches EtherType for the protocol being resolved)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct ArpProtocolType(pub U16<BigEndian>);

impl ArpProtocolType {
    pub const IPV4: ArpProtocolType = ArpProtocolType(U16::new(0x0800)); // IPv4

    #[inline]
    pub fn value(&self) -> u16 {
        self.0.get()
    }
}

impl Display for ArpProtocolType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            ArpProtocolType::IPV4 => write!(f, "ipv4"),
            _ => write!(f, "0x{:04x}", self.value()),
        }
    }
}

/// ARP Operation Code
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct ArpOperation(pub U16<BigEndian>);

impl ArpOperation {
    pub const REQUEST: ArpOperation = ArpOperation(U16::new(1)); // ARP request
    pub const REPLY: ArpOperation = ArpOperation(U16::new(2)); // ARP reply
    pub const RARP_REQUEST: ArpOperation = ArpOperation(U16::new(3)); // RARP request
    pub const RARP_REPLY: ArpOperation = ArpOperation(U16::new(4)); // RARP reply
    pub const DRARP_REQUEST: ArpOperation = ArpOperation(U16::new(5)); // DRARP request
    pub const DRARP_REPLY: ArpOperation = ArpOperation(U16::new(6)); // DRARP reply
    pub const DRARP_ERROR: ArpOperation = ArpOperation(U16::new(7)); // DRARP error
    pub const INARP_REQUEST: ArpOperation = ArpOperation(U16::new(8)); // InARP request
    pub const INARP_REPLY: ArpOperation = ArpOperation(U16::new(9)); // InARP reply
    pub const ARP_NAK: ArpOperation = ArpOperation(U16::new(10)); // ARP NAK

    #[inline]
    pub fn value(&self) -> u16 {
        self.0.get()
    }
}

impl Display for ArpOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let name = match *self {
            ArpOperation::REQUEST => "request",
            ArpOperation::REPLY => "reply",
            ArpOperation::RARP_REQUEST => "rarp-request",
            ArpOperation::RARP_REPLY => "rarp-reply",
            ArpOperation::DRARP_REQUEST => "drarp-request",
            ArpOperation::DRARP_REPLY => "drarp-reply",
            ArpOperation::DRARP_ERROR => "drarp-error",
            ArpOperation::INARP_REQUEST => "inarp-request",
            ArpOperation::INARP_REPLY => "inarp-reply",
            ArpOperation::ARP_NAK => "arp-nak",
            _ => return write!(f, "unknown({})", self.value()),
        };
        write!(f, "{}", name)
    }
}

/// ARP Header structure (RFC 826) - Fixed portion
///
/// This represents the fixed portion of an ARP packet. The actual hardware and
/// protocol addresses follow this header and have variable lengths specified by
/// `hlen` and `plen` fields.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout, Debug, Clone, Copy)]
pub struct ArpHeader {
    htype: ArpHardwareType, // Hardware type
    ptype: ArpProtocolType, // Protocol type
    hlen: u8,               // Hardware address length
    plen: u8,               // Protocol address length
    oper: ArpOperation,     // Operation code
}

impl ArpHeader {
    /// Returns the hardware type
    #[inline]
    pub fn hardware_type(&self) -> ArpHardwareType {
        self.htype
    }

    /// Returns the protocol type
    #[inline]
    pub fn protocol_type(&self) -> ArpProtocolType {
        self.ptype
    }

    /// Returns the hardware address length in bytes
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        self.hlen
    }

    /// Returns the protocol address length in bytes
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        self.plen
    }

    /// Returns the ARP operation
    #[inline]
    pub fn operation(&self) -> ArpOperation {
        self.oper
    }

    /// Returns the total size of addresses in the ARP packet
    #[inline]
    fn addresses_len(&self) -> usize {
        // sender hw + sender proto + target hw + target proto
        2 * (self.hlen as usize + self.plen as usize)
    }

    /// Validates the ARP header
    #[inline]
    fn is_valid(&self) -> bool {
        // Most common case: Ethernet (hlen=6) and IPv4 (plen=4)
        // But we accept other valid combinations
        self.hlen > 0 && self.plen > 0
    }

    /// Check if this is Ethernet/IPv4 ARP
    #[inline]
    pub fn is_eth_ipv4(&self) -> bool {
        self.htype == ArpHardwareType::ETHERNET
            && self.ptype == ArpProtocolType::IPV4
            && self.hlen == 6
            && self.plen == 4
    }
}

impl PacketHeader for ArpHeader {
    const NAME: &'static str = "ArpHeader";
    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::FIXED_LEN + self.addresses_len()
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for ArpHeader {
    type Output<'a> = ArpHeaderFull<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, addresses: &'a [u8]) -> Self::Output<'a> {
        ArpHeaderFull { header, addresses }
    }
}

/// ARP Header with addresses
///
/// This is the proxy object returned by the parser. It provides access to both
/// the fixed header and the variable-length address fields.
#[derive(Debug, Clone)]
pub struct ArpHeaderFull<'a> {
    pub header: &'a ArpHeader,
    pub addresses: &'a [u8],
}

impl<'a> ArpHeaderFull<'a> {
    /// Returns the hardware type
    #[inline]
    pub fn hardware_type(&self) -> ArpHardwareType {
        self.header.hardware_type()
    }

    /// Returns the protocol type
    #[inline]
    pub fn protocol_type(&self) -> ArpProtocolType {
        self.header.protocol_type()
    }

    /// Returns the hardware address length
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        self.header.hardware_len()
    }

    /// Returns the protocol address length
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        self.header.protocol_len()
    }

    /// Returns the ARP operation
    #[inline]
    pub fn operation(&self) -> ArpOperation {
        self.header.operation()
    }

    /// Check if this is Ethernet/IPv4 ARP
    #[inline]
    pub fn is_eth_ipv4(&self) -> bool {
        self.header.is_eth_ipv4()
    }

    /// Get sender hardware address (raw bytes)
    #[inline]
    pub fn sender_hw_addr_raw(&self) -> &[u8] {
        let hlen = self.hardware_len() as usize;
        &self.addresses[0..hlen]
    }

    /// Get sender protocol address (raw bytes)
    #[inline]
    pub fn sender_proto_addr_raw(&self) -> &[u8] {
        let hlen = self.hardware_len() as usize;
        let plen = self.protocol_len() as usize;
        &self.addresses[hlen..hlen + plen]
    }

    /// Get target hardware address (raw bytes)
    #[inline]
    pub fn target_hw_addr_raw(&self) -> &[u8] {
        let hlen = self.hardware_len() as usize;
        let plen = self.protocol_len() as usize;
        &self.addresses[hlen + plen..hlen + plen + hlen]
    }

    /// Get target protocol address (raw bytes)
    #[inline]
    pub fn target_proto_addr_raw(&self) -> &[u8] {
        let hlen = self.hardware_len() as usize;
        let plen = self.protocol_len() as usize;
        &self.addresses[hlen + plen + hlen..]
    }

    /// For Ethernet/IPv4 ARP, get sender MAC address
    #[inline]
    pub fn sender_hw_addr(&self) -> Option<&EthAddr> {
        if self.is_eth_ipv4() {
            zerocopy::Ref::<_, EthAddr>::from_prefix(self.sender_hw_addr_raw())
                .ok()
                .map(|(r, _)| zerocopy::Ref::into_ref(r))
        } else {
            None
        }
    }

    /// For Ethernet/IPv4 ARP, get sender IPv4 address as bytes
    #[inline]
    pub fn sender_proto_addr(&self) -> Option<[u8; 4]> {
        if self.is_eth_ipv4() {
            self.sender_proto_addr_raw().try_into().ok()
        } else {
            None
        }
    }

    /// For Ethernet/IPv4 ARP, get sender IPv4 address
    #[inline]
    pub fn sender_ipv4(&self) -> Option<Ipv4Addr> {
        self.sender_proto_addr().map(Ipv4Addr::from)
    }

    /// For Ethernet/IPv4 ARP, get target MAC address
    #[inline]
    pub fn target_hw_addr(&self) -> Option<&EthAddr> {
        if self.is_eth_ipv4() {
            zerocopy::Ref::<_, EthAddr>::from_prefix(self.target_hw_addr_raw())
                .ok()
                .map(|(r, _)| zerocopy::Ref::into_ref(r))
        } else {
            None
        }
    }

    /// For Ethernet/IPv4 ARP, get target IPv4 address as bytes
    #[inline]
    pub fn target_proto_addr(&self) -> Option<[u8; 4]> {
        if self.is_eth_ipv4() {
            self.target_proto_addr_raw().try_into().ok()
        } else {
            None
        }
    }

    /// For Ethernet/IPv4 ARP, get target IPv4 address
    #[inline]
    pub fn target_ipv4(&self) -> Option<Ipv4Addr> {
        self.target_proto_addr().map(Ipv4Addr::from)
    }
}

impl Deref for ArpHeaderFull<'_> {
    type Target = ArpHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl Display for ArpHeaderFull<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_eth_ipv4() {
            // Format for Ethernet/IPv4
            if let (Some(sha), Some(spa), Some(tha), Some(tpa)) = (
                self.sender_hw_addr(),
                self.sender_ipv4(),
                self.target_hw_addr(),
                self.target_ipv4(),
            ) {
                write!(
                    f,
                    "ARP {} {} -> {} ({}): {} -> {}",
                    self.operation(),
                    sha,
                    tha,
                    if self.operation() == ArpOperation::REQUEST {
                        "who-has"
                    } else {
                        "is-at"
                    },
                    spa,
                    tpa
                )
            } else {
                write!(f, "ARP {} (invalid)", self.operation())
            }
        } else {
            // Generic format
            write!(
                f,
                "ARP {} htype={} ptype={} hlen={} plen={}",
                self.operation(),
                self.hardware_type(),
                self.protocol_type(),
                self.hardware_len(),
                self.protocol_len()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_arp_request_eth_ipv4() {
        // ARP request: Who has 192.168.1.1? Tell 192.168.1.2
        let packet = vec![
            0x00, 0x01, // Hardware type: Ethernet (1)
            0x08, 0x00, // Protocol type: IPv4 (0x0800)
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x01, // Opcode: request (1)
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC address
            192, 168, 1, 2, // Sender IP address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC address (unknown)
            192, 168, 1, 1, // Target IP address
        ];

        let (arp, remaining) = ArpHeader::from_bytes(&packet).expect("Failed to parse ARP");

        assert_eq!(remaining.len(), 0);
        assert_eq!(arp.hardware_type(), ArpHardwareType::ETHERNET);
        assert_eq!(arp.protocol_type(), ArpProtocolType::IPV4);
        assert_eq!(arp.hardware_len(), 6);
        assert_eq!(arp.protocol_len(), 4);
        assert_eq!(arp.operation(), ArpOperation::REQUEST);
        assert!(arp.is_eth_ipv4());

        // Check Ethernet/IPv4 specific accessors
        assert_eq!(
            arp.sender_hw_addr().unwrap().to_string(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(arp.sender_proto_addr().unwrap(), [192, 168, 1, 2]);
        assert_eq!(arp.sender_ipv4().unwrap(), Ipv4Addr::new(192, 168, 1, 2));

        assert_eq!(
            arp.target_hw_addr().unwrap().to_string(),
            "00:00:00:00:00:00"
        );
        assert_eq!(arp.target_proto_addr().unwrap(), [192, 168, 1, 1]);
        assert_eq!(arp.target_ipv4().unwrap(), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_arp_reply_eth_ipv4() {
        // ARP reply: 192.168.1.1 is at 11:22:33:44:55:66
        let packet = vec![
            0x00, 0x01, // Hardware type: Ethernet (1)
            0x08, 0x00, // Protocol type: IPv4 (0x0800)
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x02, // Opcode: reply (2)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Sender MAC address
            192, 168, 1, 1, // Sender IP address
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Target MAC address
            192, 168, 1, 2, // Target IP address
        ];

        let (arp, remaining) = ArpHeader::from_bytes(&packet).expect("Failed to parse ARP reply");

        assert_eq!(remaining.len(), 0);
        assert_eq!(arp.operation(), ArpOperation::REPLY);
        assert!(arp.is_eth_ipv4());

        assert_eq!(
            arp.sender_hw_addr().unwrap().to_string(),
            "11:22:33:44:55:66"
        );
        assert_eq!(arp.sender_proto_addr().unwrap(), [192, 168, 1, 1]);
    }

    #[test]
    fn test_arp_packet_too_short() {
        let short_packet = vec![0x00, 0x01, 0x08, 0x00]; // Only 4 bytes

        let result = ArpHeader::from_bytes(&short_packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_arp_invalid_lengths() {
        // Invalid hardware/protocol lengths (both zero)
        let packet = vec![
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x00, // Hardware size: 0 (invalid)
            0x00, // Protocol size: 0 (invalid)
            0x00, 0x01, // Opcode: request
        ];

        let result = ArpHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_arp_display() {
        let packet = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            192, 168, 1, 2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();
        let display_str = format!("{}", arp);

        assert!(display_str.contains("request"));
        assert!(display_str.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_arp_operation_display() {
        assert_eq!(format!("{}", ArpOperation::REQUEST), "request");
        assert_eq!(format!("{}", ArpOperation::REPLY), "reply");
        assert_eq!(format!("{}", ArpOperation::RARP_REQUEST), "rarp-request");
        assert_eq!(format!("{}", ArpOperation::RARP_REPLY), "rarp-reply");
        assert_eq!(format!("{}", ArpOperation::ARP_NAK), "arp-nak");
    }

    #[test]
    fn test_arp_hardware_type_display() {
        assert_eq!(format!("{}", ArpHardwareType::ETHERNET), "ethernet");
        assert_eq!(format!("{}", ArpHardwareType::IEEE802), "ieee802");
        assert_eq!(format!("{}", ArpHardwareType::FRAME_RELAY), "frame-relay");
        assert_eq!(
            format!("{}", ArpHardwareType(U16::new(9999))),
            "unknown(9999)"
        );
    }

    #[test]
    fn test_arp_protocol_type_display() {
        assert_eq!(format!("{}", ArpProtocolType::IPV4), "ipv4");
        assert_eq!(format!("{}", ArpProtocolType(U16::new(0x1234))), "0x1234");
    }

    #[test]
    fn test_arp_with_payload() {
        let mut packet = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            192, 168, 1, 2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,
        ];

        // Add some extra payload bytes (padding or other data)
        packet.extend_from_slice(b"extra data");

        let (arp, remaining) = ArpHeader::from_bytes(&packet).unwrap();

        assert_eq!(arp.operation(), ArpOperation::REQUEST);
        assert_eq!(remaining, b"extra data");
    }

    #[test]
    fn test_arp_rarp_request() {
        let packet = vec![
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x03, // Opcode: RARP request (3)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Sender MAC
            0, 0, 0, 0, // Sender IP (unknown)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Target MAC (broadcast)
            0, 0, 0, 0, // Target IP (unknown)
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();
        assert_eq!(arp.operation(), ArpOperation::RARP_REQUEST);
    }

    #[test]
    fn test_arp_gratuitous() {
        // Gratuitous ARP: sender IP == target IP
        let packet = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            192, 168, 1, 100, // Sender IP
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Target MAC (broadcast)
            192, 168, 1, 100, // Target IP (same as sender)
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();

        // In gratuitous ARP, sender and target IPs are the same
        assert_eq!(arp.sender_ipv4().unwrap(), Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(arp.sender_ipv4().unwrap(), arp.target_ipv4().unwrap());
        assert_eq!(arp.operation(), ArpOperation::REQUEST);
    }

    #[test]
    fn test_arp_probe() {
        // ARP Probe: sender IP is 0.0.0.0
        let packet = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0,
            0, 0, 0, // Sender IP (0.0.0.0 in probe)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC (unknown)
            192, 168, 1, 100, // Target IP (IP being probed)
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();

        assert_eq!(arp.sender_ipv4().unwrap(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(arp.target_ipv4().unwrap(), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_arp_real_world_request() {
        // Real-world ARP request captured from network
        // Who has 10.0.0.1? Tell 10.0.0.2
        let packet = vec![
            0x00, 0x01, // Ethernet
            0x08, 0x00, // IPv4
            0x06, 0x04, // hlen=6, plen=4
            0x00, 0x01, // Request
            0x08, 0x00, 0x27, 0x12, 0x34, 0x56, // Sender MAC
            10, 0, 0, 2, // Sender IP: 10.0.0.2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC: unknown
            10, 0, 0, 1, // Target IP: 10.0.0.1
        ];

        let (arp, remaining) = ArpHeader::from_bytes(&packet).unwrap();

        assert_eq!(remaining.len(), 0);
        assert_eq!(arp.sender_ipv4().unwrap(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(arp.target_ipv4().unwrap(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            arp.sender_hw_addr().unwrap(),
            &EthAddr::from_str("08:00:27:12:34:56").unwrap()
        );
    }

    #[test]
    fn test_arp_real_world_reply() {
        // Real-world ARP reply
        // 10.0.0.1 is at 52:54:00:12:34:56
        let packet = vec![
            0x00, 0x01, // Ethernet
            0x08, 0x00, // IPv4
            0x06, 0x04, // hlen=6, plen=4
            0x00, 0x02, // Reply
            0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // Sender MAC: 52:54:00:12:34:56
            10, 0, 0, 1, // Sender IP: 10.0.0.1
            0x08, 0x00, 0x27, 0x12, 0x34, 0x56, // Target MAC
            10, 0, 0, 2, // Target IP: 10.0.0.2
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();

        assert_eq!(arp.operation(), ArpOperation::REPLY);
        assert_eq!(
            arp.sender_hw_addr().unwrap(),
            &EthAddr::from_str("52:54:00:12:34:56").unwrap()
        );
        assert_eq!(arp.sender_ipv4().unwrap(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_arp_from_bytes_multiple_packets() {
        // Test parsing multiple different ARP packets
        let test_cases = vec![
            (
                vec![
                    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                    0xff, 192, 168, 1, 2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,
                ],
                ArpOperation::REQUEST,
            ),
            (
                vec![
                    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 192, 168, 1, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 192, 168, 1, 2,
                ],
                ArpOperation::REPLY,
            ),
        ];

        for (packet, expected_op) in test_cases {
            let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();
            assert_eq!(arp.operation(), expected_op);
            assert!(arp.is_eth_ipv4());
        }
    }

    #[test]
    fn test_arp_size_constants() {
        assert_eq!(
            std::mem::size_of::<ArpHeader>(),
            8,
            "ARP fixed header should be 8 bytes"
        );
        assert_eq!(ArpHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_arp_packet_boundary_conditions() {
        // Test exact size packet
        let packet = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            192, 168, 1, 2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,
        ];

        assert_eq!(packet.len(), 28);
        let (arp, remaining) = ArpHeader::from_bytes(&packet).unwrap();
        assert_eq!(remaining.len(), 0);
        assert!(arp.is_eth_ipv4());
    }

    #[test]
    fn test_arp_generic_parsing() {
        // Test with non-standard hardware/protocol lengths
        let mut packet = vec![
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x08, // Hardware size: 8 (non-standard, not 6)
            0x04, // Protocol size: 4
            0x00, 0x01, // Opcode: request
        ];

        // Add sender hw (8 bytes), sender proto (4 bytes), target hw (8 bytes), target proto (4 bytes)
        packet.extend_from_slice(&[0xAA; 8]); // sender hw
        packet.extend_from_slice(&[192, 168, 1, 2]); // sender proto
        packet.extend_from_slice(&[0xBB; 8]); // target hw
        packet.extend_from_slice(&[192, 168, 1, 1]); // target proto

        let (arp, remaining) = ArpHeader::from_bytes(&packet).unwrap();

        assert_eq!(remaining.len(), 0);
        assert_eq!(arp.hardware_len(), 8);
        assert_eq!(arp.protocol_len(), 4);
        assert_eq!(arp.operation(), ArpOperation::REQUEST);

        // This should NOT be eth_ipv4 because hlen is 8, not 6
        assert!(!arp.is_eth_ipv4());

        // Check raw address accessors
        assert_eq!(arp.sender_hw_addr_raw().len(), 8);
        assert_eq!(arp.sender_proto_addr_raw(), &[192, 168, 1, 2]);
        assert_eq!(arp.target_hw_addr_raw().len(), 8);
        assert_eq!(arp.target_proto_addr_raw(), &[192, 168, 1, 1]);
    }

    #[test]
    fn test_arp_deref() {
        let packet = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            192, 168, 1, 2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();

        // Test that Deref works
        assert_eq!(arp.hardware_type(), ArpHardwareType::ETHERNET);
        assert_eq!(arp.protocol_type(), ArpProtocolType::IPV4);
    }

    #[test]
    fn test_arp_zerocopy_parsing() {
        // Test that zerocopy parsing works correctly for addresses
        let packet = vec![
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, 0x04, // hlen=6, plen=4
            0x00, 0x01, // Request
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Sender MAC
            10, 20, 30, 40, // Sender IP
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Target MAC
            50, 60, 70, 80, // Target IP
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();

        // Test raw address accessors
        assert_eq!(
            arp.sender_hw_addr_raw(),
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
        assert_eq!(arp.sender_proto_addr_raw(), &[10, 20, 30, 40]);
        assert_eq!(
            arp.target_hw_addr_raw(),
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(arp.target_proto_addr_raw(), &[50, 60, 70, 80]);

        // Test typed accessors using zerocopy
        assert!(arp.sender_hw_addr().is_some());
        assert_eq!(
            arp.sender_hw_addr().unwrap().to_string(),
            "11:22:33:44:55:66"
        );

        assert!(arp.target_hw_addr().is_some());
        assert_eq!(
            arp.target_hw_addr().unwrap().to_string(),
            "aa:bb:cc:dd:ee:ff"
        );

        // Test IPv4 address parsing
        assert_eq!(arp.sender_proto_addr().unwrap(), [10, 20, 30, 40]);
        assert_eq!(arp.target_proto_addr().unwrap(), [50, 60, 70, 80]);

        // Test IPv4 as Ipv4Addr
        assert_eq!(arp.sender_ipv4().unwrap(), Ipv4Addr::new(10, 20, 30, 40));
        assert_eq!(arp.target_ipv4().unwrap(), Ipv4Addr::new(50, 60, 70, 80));
    }

    #[test]
    fn test_arp_non_eth_ipv4_returns_none() {
        // Test with non-standard hardware length (7 instead of 6)
        let mut packet = vec![
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x07, // Hardware size: 7 (non-standard!)
            0x04, // Protocol size: 4
            0x00, 0x01, // Opcode: request
        ];

        // Add addresses: sender hw (7), sender proto (4), target hw (7), target proto (4)
        packet.extend_from_slice(&[0xAA; 7]); // sender hw
        packet.extend_from_slice(&[192, 168, 1, 2]); // sender proto
        packet.extend_from_slice(&[0xBB; 7]); // target hw
        packet.extend_from_slice(&[192, 168, 1, 1]); // target proto

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();

        // Should NOT be recognized as eth_ipv4 due to hlen=7
        assert!(!arp.is_eth_ipv4());

        // Typed accessors should return None
        assert!(arp.sender_hw_addr().is_none());
        assert!(arp.target_hw_addr().is_none());
        assert!(arp.sender_proto_addr().is_none());
        assert!(arp.target_proto_addr().is_none());
        assert!(arp.sender_ipv4().is_none());
        assert!(arp.target_ipv4().is_none());

        // But raw accessors should still work
        assert_eq!(arp.sender_hw_addr_raw().len(), 7);
        assert_eq!(arp.sender_proto_addr_raw(), &[192, 168, 1, 2]);
    }

    #[test]
    fn test_arp_ipv4addr_parsing() {
        // Test using Ipv4Addr::parse like IPv4 module does
        let packet = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            192, 168, 1, 2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,
        ];

        let (arp, _) = ArpHeader::from_bytes(&packet).unwrap();

        // Test using parse
        assert_eq!(
            arp.sender_ipv4().unwrap(),
            "192.168.1.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            arp.target_ipv4().unwrap(),
            "192.168.1.1".parse::<Ipv4Addr>().unwrap()
        );

        // Test Display implementation works
        let sender_ip = arp.sender_ipv4().unwrap();
        assert_eq!(sender_ip.to_string(), "192.168.1.2");

        let target_ip = arp.target_ipv4().unwrap();
        assert_eq!(target_ip.to_string(), "192.168.1.1");
    }
}
