//! ICMPv6 (Internet Control Message Protocol for IPv6) packet parser
//!
//! This module implements parsing for ICMPv6 messages as defined in RFC 4443.
//! ICMPv6 is used for error reporting, diagnostics, and Neighbor Discovery
//! Protocol (NDP) in IPv6 networks.
//!
//! # ICMPv6 Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Message Body                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Header size: 8 bytes (fixed)
//! - Type values 0-127: Error messages
//! - Type values 128-255: Informational messages
//! - Checksum is mandatory (unlike ICMPv4 over IPv4)
//!
//! # Examples
//!
//! ## ICMPv6 Echo Request (ping6)
//!
//! ```
//! use packet_strata::packet::icmp6::{Icmp6Header, Icmp6Type};
//! use packet_strata::packet::HeaderParser;
//!
//! // ICMPv6 Echo Request packet
//! let packet = vec![
//!     0x80,              // Type: Echo Request (128)
//!     0x00,              // Code: 0
//!     0x00, 0x00,        // Checksum
//!     0x00, 0x01,        // Identifier: 1
//!     0x00, 0x01,        // Sequence Number: 1
//!     // Payload follows...
//! ];
//!
//! let (header, payload) = Icmp6Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.icmp6_type(), Icmp6Type::ECHO_REQUEST);
//! assert_eq!(header.code(), 0);
//! assert_eq!(header.echo_id(), 1);
//! assert_eq!(header.echo_sequence(), 1);
//! ```
//!
//! ## ICMPv6 Echo Reply
//!
//! ```
//! use packet_strata::packet::icmp6::{Icmp6Header, Icmp6Type};
//! use packet_strata::packet::HeaderParser;
//!
//! // ICMPv6 Echo Reply packet
//! let packet = vec![
//!     0x81,              // Type: Echo Reply (129)
//!     0x00,              // Code: 0
//!     0x00, 0x00,        // Checksum
//!     0x00, 0x01,        // Identifier: 1
//!     0x00, 0x02,        // Sequence Number: 2
//! ];
//!
//! let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.icmp6_type(), Icmp6Type::ECHO_REPLY);
//! assert_eq!(header.echo_id(), 1);
//! assert_eq!(header.echo_sequence(), 2);
//! ```

use std::fmt::{self, Formatter};
use std::mem;

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::HeaderParser;
use crate::packet::PacketHeader;

/// ICMPv6 Message Type
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    Unaligned,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
#[repr(transparent)]
pub struct Icmp6Type(pub u8);

impl Icmp6Type {
    pub const DST_UNREACH: Icmp6Type = Icmp6Type(1);
    pub const PACKET_TOO_BIG: Icmp6Type = Icmp6Type(2);
    pub const TIME_EXCEEDED: Icmp6Type = Icmp6Type(3);
    pub const PARAM_PROB: Icmp6Type = Icmp6Type(4);
    pub const ECHO_REQUEST: Icmp6Type = Icmp6Type(128);
    pub const ECHO_REPLY: Icmp6Type = Icmp6Type(129);
    pub const MLD_LISTENER_QUERY: Icmp6Type = Icmp6Type(130);
    pub const MLD_LISTENER_REPORT: Icmp6Type = Icmp6Type(131);
    pub const MLD_LISTENER_REDUCTION: Icmp6Type = Icmp6Type(132);

    pub const ROUTER_SOLICITATION: Icmp6Type = Icmp6Type(133);
    pub const ROUTER_ADVERTISEMENT: Icmp6Type = Icmp6Type(134);
    pub const NEIGHBOR_SOLICITATION: Icmp6Type = Icmp6Type(135);
    pub const NEIGHBOR_ADVERTISEMENT: Icmp6Type = Icmp6Type(136);
    pub const REDIRECT_MESSAGE: Icmp6Type = Icmp6Type(137);
    pub const ROUTER_RENUMBERING: Icmp6Type = Icmp6Type(138);
    pub const NODE_INFORMATION_QUERY: Icmp6Type = Icmp6Type(139);
    pub const NODE_INFORMATION_RESPONSE: Icmp6Type = Icmp6Type(140);

    pub const INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION: Icmp6Type = Icmp6Type(141);
    pub const INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT: Icmp6Type = Icmp6Type(142);
    pub const MULTICAST_LISTENER_DISCOVERY_REPORTS: Icmp6Type = Icmp6Type(143);
    pub const HOME_AGENT_ADDRESS_DISCOVERY_REQUEST: Icmp6Type = Icmp6Type(144);
    pub const HOME_AGENT_ADDRESS_DISCOVERY_REPLY: Icmp6Type = Icmp6Type(145);
    pub const MOBILE_PREFIX_SOLICITATION: Icmp6Type = Icmp6Type(146);
    pub const MOBILE_PREFIX_ADVERTISEMENT: Icmp6Type = Icmp6Type(147);
    pub const CERTIFICATION_PATH_SOLICITATION: Icmp6Type = Icmp6Type(148);
    pub const CERTIFICATION_PATH_ADVERTISEMENT: Icmp6Type = Icmp6Type(149);
    pub const EXPERIMENTAL_MOBILITY: Icmp6Type = Icmp6Type(150);
    pub const MULTICAST_ROUTER_ADVERTISEMENT: Icmp6Type = Icmp6Type(151);
    pub const MULTICAST_ROUTER_SOLICITATION: Icmp6Type = Icmp6Type(152);
    pub const MULTICAST_ROUTER_TERMINATION: Icmp6Type = Icmp6Type(153);
    pub const FMIPV6: Icmp6Type = Icmp6Type(154);
    pub const RPL_CONTROL_MESSAGE: Icmp6Type = Icmp6Type(155);
    pub const ILNPV6_LOCATOR_UPDATE: Icmp6Type = Icmp6Type(156);
    pub const DUPLICATE_ADDRESS_REQUEST: Icmp6Type = Icmp6Type(157);
    pub const DUPLICATE_ADDRESS_CONFIRM: Icmp6Type = Icmp6Type(158);
    pub const MPL_CONTROL_MESSAGE: Icmp6Type = Icmp6Type(159);
    pub const EXTENDED_ECHO_REQUEST: Icmp6Type = Icmp6Type(160);
    pub const EXTENDED_ECHO_REPLY: Icmp6Type = Icmp6Type(161);
}

impl From<u8> for Icmp6Type {
    fn from(value: u8) -> Self {
        Icmp6Type(value)
    }
}

impl From<Icmp6Type> for u8 {
    fn from(value: Icmp6Type) -> Self {
        value.0
    }
}

impl fmt::Display for Icmp6Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            1 => "destination-unreachable",
            2 => "packet-too-big",
            3 => "time-exceeded",
            4 => "parameter-problem",
            128 => "echo-request",
            129 => "echo-reply",
            130 => "multicast-listener-query",
            131 => "multicast-listener-report",
            132 => "multicast-listener-reduction",
            133 => "router-solicitation",
            134 => "router-advertisement",
            135 => "neighbor-solicitation",
            136 => "neighbor-advertisement",
            137 => "redirect-message",
            138 => "router-renumbering",
            139 => "node-information-query",
            140 => "node-information-response",
            141 => "inverse-neighbor-discovery-solicitation",
            142 => "inverse-neighbor-discovery-advertisement",
            143 => "multicast-listener-discovery-report",
            144 => "home-agent-address-discovery-request",
            145 => "home-agent-address-discovery-reply",
            146 => "mobile-prefix-solicitation",
            147 => "mobile-prefix-advertisement",
            148 => "certification-path-solicitation",
            149 => "certification-path-advertisement",
            150 => "experimental-mobility",
            151 => "multicast-router-advertisement",
            152 => "multicast-router-solicitation",
            153 => "multicast-router-termination",
            154 => "fmipv6",
            155 => "rpl-control-message",
            156 => "ilnpv6-locator-update",
            157 => "duplicate-address-request",
            158 => "duplicate-address-confirmation",
            159 => "mpl-control-message",
            160 => "extended-echo-request",
            161 => "extended-echo-reply",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMPv6 Code for Destination Unreachable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Icmp6CodeUnreachable(pub u8);

impl Icmp6CodeUnreachable {
    pub const NOROUTE: Icmp6CodeUnreachable = Icmp6CodeUnreachable(0); // no route to destination
    pub const ADMIN: Icmp6CodeUnreachable = Icmp6CodeUnreachable(1); // communication with destination administratively prohibited
    pub const BEYONDSCOPE: Icmp6CodeUnreachable = Icmp6CodeUnreachable(2); // beyond scope of source address
    pub const ADDR: Icmp6CodeUnreachable = Icmp6CodeUnreachable(3); // address unreachable
    pub const NOPORT: Icmp6CodeUnreachable = Icmp6CodeUnreachable(4); // port unreachable
}

impl From<u8> for Icmp6CodeUnreachable {
    fn from(value: u8) -> Self {
        Icmp6CodeUnreachable(value)
    }
}

impl From<Icmp6CodeUnreachable> for u8 {
    fn from(value: Icmp6CodeUnreachable) -> Self {
        value.0
    }
}

impl fmt::Display for Icmp6CodeUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "no-route",
            1 => "admin-prohibited",
            2 => "beyond-scope",
            3 => "address-unreachable",
            4 => "port-unreachable",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMPv6 Code for Time Exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Icmp6CodeTimeExceed(pub u8);

impl Icmp6CodeTimeExceed {
    pub const TRANSIT: Icmp6CodeTimeExceed = Icmp6CodeTimeExceed(0); // Hop Limit == 0 in transit
    pub const REASSEMBLY: Icmp6CodeTimeExceed = Icmp6CodeTimeExceed(1); // Reassembly time out
}

impl From<u8> for Icmp6CodeTimeExceed {
    fn from(value: u8) -> Self {
        Icmp6CodeTimeExceed(value)
    }
}

impl From<Icmp6CodeTimeExceed> for u8 {
    fn from(value: Icmp6CodeTimeExceed) -> Self {
        value.0
    }
}

impl fmt::Display for Icmp6CodeTimeExceed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "hop-limit-exceeded",
            1 => "reassembly-timeout",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMPv6 Code for Parameter Problem
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Icmp6CodeParamProb(pub u8);

impl Icmp6CodeParamProb {
    pub const HEADER: Icmp6CodeParamProb = Icmp6CodeParamProb(0); // erroneous header field
    pub const NEXTHEADER: Icmp6CodeParamProb = Icmp6CodeParamProb(1); // unrecognized Next Header
    pub const OPTION: Icmp6CodeParamProb = Icmp6CodeParamProb(2); // unrecognized IPv6 option
}

impl From<u8> for Icmp6CodeParamProb {
    fn from(value: u8) -> Self {
        Icmp6CodeParamProb(value)
    }
}

impl From<Icmp6CodeParamProb> for u8 {
    fn from(value: Icmp6CodeParamProb) -> Self {
        value.0
    }
}

impl fmt::Display for Icmp6CodeParamProb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "erroneous-header",
            1 => "unrecognized-next-header",
            2 => "unrecognized-option",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMPv6 Header structure as defined in RFC 4443
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct Icmp6Header {
    icmp6_type: Icmp6Type,
    code: u8,
    checksum: U16<BigEndian>,
    // Union data - we represent it as raw bytes
    // Can be interpreted as:
    // - data32[1]: 32-bit data
    // - data16[2]: 16-bit data
    // - data8[4]: 8-bit data
    un: U32<BigEndian>,
}

impl Icmp6Header {
    pub const FIXED_LEN: usize = mem::size_of::<Icmp6Header>();

    /// Returns the ICMPv6 message type
    #[inline]
    pub fn icmp6_type(&self) -> Icmp6Type {
        self.icmp6_type
    }

    /// Returns the ICMPv6 code
    #[inline]
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Returns the checksum
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum.get()
    }

    /// Returns the raw union data
    #[inline]
    pub fn un(&self) -> u32 {
        self.un.get()
    }

    /// For Echo/Echo Reply: returns the identifier
    #[inline]
    pub fn echo_id(&self) -> u16 {
        (self.un.get() >> 16) as u16
    }

    /// For Echo/Echo Reply: returns the sequence number
    #[inline]
    pub fn echo_sequence(&self) -> u16 {
        (self.un.get() & 0xFFFF) as u16
    }

    /// For Packet Too Big: returns the MTU
    #[inline]
    pub fn mtu(&self) -> u32 {
        self.un.get()
    }

    /// For Parameter Problem: returns the pointer
    #[inline]
    pub fn pointer(&self) -> u32 {
        self.un.get()
    }

    /// Validates the ICMPv6 header
    #[inline]
    pub fn is_valid(&self) -> bool {
        // Basic validation - all ICMPv6 headers are valid structurally
        // Additional validation can be done based on type/code combinations
        true
    }

    /// Compute ICMPv6 checksum including pseudo-header
    /// Note: ICMPv6 checksum is mandatory (unlike ICMPv4)
    pub fn compute_checksum(src_ip: &[u8; 16], dst_ip: &[u8; 16], icmp6_data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header: source IP (128 bits = 16 bytes)
        for i in (0..16).step_by(2) {
            let word = u16::from_be_bytes([src_ip[i], src_ip[i + 1]]);
            sum += word as u32;
        }

        // Pseudo-header: destination IP (128 bits = 16 bytes)
        for i in (0..16).step_by(2) {
            let word = u16::from_be_bytes([dst_ip[i], dst_ip[i + 1]]);
            sum += word as u32;
        }

        // Pseudo-header: ICMPv6 length (32 bits)
        let icmp_len = icmp6_data.len() as u32;
        sum += (icmp_len >> 16) & 0xFFFF;
        sum += icmp_len & 0xFFFF;

        // Pseudo-header: next header (ICMPv6 = 58)
        sum += 58;

        // ICMPv6 header and data
        let mut i = 0;
        while i < icmp6_data.len() {
            if i + 1 < icmp6_data.len() {
                let word = u16::from_be_bytes([icmp6_data[i], icmp6_data[i + 1]]);
                sum += word as u32;
                i += 2;
            } else {
                // Odd length: pad with zero
                let word = u16::from_be_bytes([icmp6_data[i], 0]);
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

    /// Verify ICMPv6 checksum
    pub fn verify_checksum(&self, src_ip: &[u8; 16], dst_ip: &[u8; 16], icmp6_data: &[u8]) -> bool {
        let computed = Self::compute_checksum(src_ip, dst_ip, icmp6_data);
        computed == 0 || computed == 0xFFFF
    }
}

impl PacketHeader for Icmp6Header {
    const NAME: &'static str = "Icmp6Header";
    type InnerType = Icmp6Type;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.icmp6_type
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

impl HeaderParser for Icmp6Header {
    type Output<'a> = &'a Icmp6Header;

    #[inline]
    fn into_view<'a>(header: &'a Self, _: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for Icmp6Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ICMPv6 {}", self.icmp6_type())?;

        // Add type-specific information
        match self.icmp6_type() {
            Icmp6Type::ECHO_REQUEST | Icmp6Type::ECHO_REPLY => {
                write!(f, " id={} seq={}", self.echo_id(), self.echo_sequence())?;
            }
            Icmp6Type::DST_UNREACH => {
                let code = Icmp6CodeUnreachable::from(self.code());
                write!(f, " code={}", code)?;
            }
            Icmp6Type::PACKET_TOO_BIG => {
                write!(f, " mtu={}", self.mtu())?;
            }
            Icmp6Type::TIME_EXCEEDED => {
                let code = Icmp6CodeTimeExceed::from(self.code());
                write!(f, " code={}", code)?;
            }
            Icmp6Type::PARAM_PROB => {
                let code = Icmp6CodeParamProb::from(self.code());
                write!(f, " code={} ptr={}", code, self.pointer())?;
            }
            _ => {
                if self.code() != 0 {
                    write!(f, " code={}", self.code())?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp6_type_constants() {
        assert_eq!(Icmp6Type::DST_UNREACH.0, 1);
        assert_eq!(Icmp6Type::PACKET_TOO_BIG.0, 2);
        assert_eq!(Icmp6Type::TIME_EXCEEDED.0, 3);
        assert_eq!(Icmp6Type::ECHO_REQUEST.0, 128);
        assert_eq!(Icmp6Type::ECHO_REPLY.0, 129);
        assert_eq!(Icmp6Type::ROUTER_SOLICITATION.0, 133);
        assert_eq!(Icmp6Type::NEIGHBOR_SOLICITATION.0, 135);
    }

    #[test]
    fn test_icmp6_type_display() {
        assert_eq!(format!("{}", Icmp6Type::ECHO_REQUEST), "echo-request");
        assert_eq!(format!("{}", Icmp6Type::ECHO_REPLY), "echo-reply");
        assert_eq!(
            format!("{}", Icmp6Type::DST_UNREACH),
            "destination-unreachable"
        );
        assert_eq!(
            format!("{}", Icmp6Type::NEIGHBOR_SOLICITATION),
            "neighbor-solicitation"
        );
        assert_eq!(
            format!("{}", Icmp6Type::ROUTER_ADVERTISEMENT),
            "router-advertisement"
        );
        assert_eq!(format!("{}", Icmp6Type::PACKET_TOO_BIG), "packet-too-big");
        assert_eq!(format!("{}", Icmp6Type::TIME_EXCEEDED), "time-exceeded");
        assert_eq!(format!("{}", Icmp6Type::PARAM_PROB), "parameter-problem");
        assert_eq!(format!("{}", Icmp6Type::from(99)), "unknown-99");
    }

    #[test]
    fn test_icmp6_code_constants() {
        assert_eq!(Icmp6CodeUnreachable::NOROUTE.0, 0);
        assert_eq!(Icmp6CodeUnreachable::NOPORT.0, 4);

        assert_eq!(Icmp6CodeTimeExceed::TRANSIT.0, 0);
        assert_eq!(Icmp6CodeTimeExceed::REASSEMBLY.0, 1);

        assert_eq!(Icmp6CodeParamProb::HEADER.0, 0);
        assert_eq!(Icmp6CodeParamProb::NEXTHEADER.0, 1);
    }

    #[test]
    fn test_icmp6_code_display() {
        assert_eq!(
            format!("{}", Icmp6CodeUnreachable::NOPORT),
            "port-unreachable"
        );
        assert_eq!(format!("{}", Icmp6CodeUnreachable::NOROUTE), "no-route");
        assert_eq!(format!("{}", Icmp6CodeUnreachable::from(99)), "unknown-99");

        assert_eq!(
            format!("{}", Icmp6CodeTimeExceed::TRANSIT),
            "hop-limit-exceeded"
        );
        assert_eq!(format!("{}", Icmp6CodeTimeExceed::from(99)), "unknown-99");

        assert_eq!(
            format!("{}", Icmp6CodeParamProb::HEADER),
            "erroneous-header"
        );
        assert_eq!(format!("{}", Icmp6CodeParamProb::from(99)), "unknown-99");
    }

    #[test]
    fn test_icmp6_header_size() {
        assert_eq!(mem::size_of::<Icmp6Header>(), 8);
        assert_eq!(Icmp6Header::FIXED_LEN, 8);
    }

    #[test]
    fn test_icmp6_echo_request() {
        let mut packet = Vec::new();

        // ICMPv6 Echo Request
        packet.push(128); // Type: Echo Request
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&5678u16.to_be_bytes()); // Sequence

        let result = Icmp6Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert_eq!(header.icmp6_type(), Icmp6Type::ECHO_REQUEST);
        assert_eq!(header.code(), 0);
        assert_eq!(header.echo_id(), 1234);
        assert_eq!(header.echo_sequence(), 5678);
        assert!(header.is_valid());
    }

    #[test]
    fn test_icmp6_echo_reply() {
        let mut packet = Vec::new();

        // ICMPv6 Echo Reply
        packet.push(129); // Type: Echo Reply
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&5678u16.to_be_bytes()); // Sequence

        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp6_type(), Icmp6Type::ECHO_REPLY);
        assert_eq!(header.code(), 0);
        assert_eq!(header.echo_id(), 1234);
        assert_eq!(header.echo_sequence(), 5678);
    }

    #[test]
    fn test_icmp6_dest_unreachable() {
        let mut packet = Vec::new();

        // ICMPv6 Destination Unreachable - Port Unreachable
        packet.push(1); // Type: Dest Unreachable
        packet.push(Icmp6CodeUnreachable::NOPORT.0); // Code: Port Unreachable
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&0u32.to_be_bytes()); // Unused

        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp6_type(), Icmp6Type::DST_UNREACH);
        assert_eq!(header.code(), Icmp6CodeUnreachable::NOPORT.0);
    }

    #[test]
    fn test_icmp6_time_exceeded() {
        let mut packet = Vec::new();

        // ICMPv6 Time Exceeded - Hop Limit exceeded
        packet.push(3); // Type: Time Exceeded
        packet.push(Icmp6CodeTimeExceed::TRANSIT.0); // Code: Hop Limit exceeded
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&0u32.to_be_bytes()); // Unused

        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp6_type(), Icmp6Type::TIME_EXCEEDED);
        assert_eq!(header.code(), Icmp6CodeTimeExceed::TRANSIT.0);
    }

    #[test]
    fn test_icmp6_packet_too_big() {
        let mut packet = Vec::new();

        // ICMPv6 Packet Too Big
        packet.push(2); // Type: Packet Too Big
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum

        // MTU: 1280
        let mtu = 1280u32;
        packet.extend_from_slice(&mtu.to_be_bytes());

        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp6_type(), Icmp6Type::PACKET_TOO_BIG);
        assert_eq!(header.code(), 0);
        assert_eq!(header.mtu(), mtu);
    }

    #[test]
    fn test_icmp6_param_problem() {
        let mut packet = Vec::new();

        // ICMPv6 Parameter Problem
        packet.push(4); // Type: Parameter Problem
        packet.push(Icmp6CodeParamProb::HEADER.0); // Code: Erroneous header
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum

        // Pointer: 40
        let pointer = 40u32;
        packet.extend_from_slice(&pointer.to_be_bytes());

        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp6_type(), Icmp6Type::PARAM_PROB);
        assert_eq!(header.code(), Icmp6CodeParamProb::HEADER.0);
        assert_eq!(header.pointer(), pointer);
    }

    #[test]
    fn test_icmp6_neighbor_solicitation() {
        let mut packet = Vec::new();

        // ICMPv6 Neighbor Solicitation
        packet.push(135); // Type: Neighbor Solicitation
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&0u32.to_be_bytes()); // Reserved

        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp6_type(), Icmp6Type::NEIGHBOR_SOLICITATION);
        assert_eq!(header.code(), 0);
    }

    #[test]
    fn test_icmp6_router_advertisement() {
        let mut packet = Vec::new();

        // ICMPv6 Router Advertisement
        packet.push(134); // Type: Router Advertisement
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&0u32.to_be_bytes()); // Cur Hop Limit, Flags, Router Lifetime

        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp6_type(), Icmp6Type::ROUTER_ADVERTISEMENT);
        assert_eq!(header.code(), 0);
    }

    #[test]
    fn test_icmp6_parsing_too_small() {
        let packet = vec![0u8; 7]; // Only 7 bytes, need 8

        let result = Icmp6Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_icmp6_total_len() {
        let packet = create_test_echo_packet();
        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();

        // ICMPv6 header is always 8 bytes (no variable length)
        assert_eq!(header.total_len(&packet), 8);
    }

    #[test]
    fn test_icmp6_from_bytes_with_payload() {
        let mut packet = Vec::new();

        // ICMPv6 Echo Request
        packet.push(128); // Type: Echo Request
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&1u16.to_be_bytes()); // ID
        packet.extend_from_slice(&1u16.to_be_bytes()); // Sequence

        // Add payload
        let payload_data = b"Hello ICMPv6!";
        packet.extend_from_slice(payload_data);

        let result = Icmp6Header::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify header fields
        assert_eq!(header.icmp6_type(), Icmp6Type::ECHO_REQUEST);
        assert_eq!(header.code(), 0);
        assert_eq!(header.echo_id(), 1);
        assert_eq!(header.echo_sequence(), 1);

        // Verify payload separation
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);
    }

    #[test]
    fn test_icmp6_checksum_computation() {
        // IPv6 addresses (simplified)
        let src_ip: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_ip: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let mut packet = Vec::new();

        // ICMPv6 Echo Request
        packet.push(128); // Type
        packet.push(0); // Code
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (zero for computation)
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&0x5678u16.to_be_bytes()); // Sequence

        // Add some payload
        packet.extend_from_slice(b"test");

        let checksum = Icmp6Header::compute_checksum(&src_ip, &dst_ip, &packet);

        // Checksum should be non-zero
        assert_ne!(checksum, 0);

        // Now set the checksum in the packet
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        // Verify should pass
        let (header, _) = Icmp6Header::from_bytes(&packet).unwrap();
        assert!(header.verify_checksum(&src_ip, &dst_ip, &packet));
    }

    // Helper function to create a test ICMPv6 Echo packet
    fn create_test_echo_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Type: Echo Request
        packet.push(128);

        // Code: 0
        packet.push(0);

        // Checksum: 0
        packet.extend_from_slice(&0u16.to_be_bytes());

        // ID: 1234
        packet.extend_from_slice(&1234u16.to_be_bytes());

        // Sequence: 1
        packet.extend_from_slice(&1u16.to_be_bytes());

        packet
    }
}
