//! ICMP (Internet Control Message Protocol) packet parser
//!
//! This module implements parsing for ICMP messages as defined in RFC 792.
//! ICMP is used by network devices to send error messages and operational
//! information (e.g., ping requests and replies).
//!
//! # ICMP Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Rest of Header                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Header size: 8 bytes (fixed)
//! - Type field: identifies the ICMP message type
//! - Code field: provides additional context for the type
//! - Common types: Echo Request (8), Echo Reply (0), Destination Unreachable (3)
//!
//! # Examples
//!
//! ## ICMP Echo Request (ping)
//!
//! ```
//! use packet_strata::packet::icmp::{IcmpHeader, IcmpType};
//! use packet_strata::packet::HeaderParser;
//!
//! // ICMP Echo Request packet
//! let packet = vec![
//!     0x08,              // Type: Echo Request (8)
//!     0x00,              // Code: 0
//!     0x00, 0x00,        // Checksum
//!     0x00, 0x01,        // Identifier: 1
//!     0x00, 0x01,        // Sequence Number: 1
//!     // Payload follows...
//! ];
//!
//! let (header, payload) = IcmpHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.icmp_type(), IcmpType::ECHO);
//! assert_eq!(header.code(), 0);
//! assert_eq!(header.echo_id(), 1);
//! assert_eq!(header.echo_sequence(), 1);
//! ```
//!
//! ## ICMP Echo Reply
//!
//! ```
//! use packet_strata::packet::icmp::{IcmpHeader, IcmpType};
//! use packet_strata::packet::HeaderParser;
//!
//! // ICMP Echo Reply packet
//! let packet = vec![
//!     0x00,              // Type: Echo Reply (0)
//!     0x00,              // Code: 0
//!     0x00, 0x00,        // Checksum
//!     0x00, 0x01,        // Identifier: 1
//!     0x00, 0x02,        // Sequence Number: 2
//! ];
//!
//! let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.icmp_type(), IcmpType::ECHO_REPLY);
//! assert_eq!(header.echo_id(), 1);
//! assert_eq!(header.echo_sequence(), 2);
//! ```

use std::fmt::{self, Formatter};
use std::mem;

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::HeaderParser;
use crate::packet::PacketHeader;

/// ICMP Message Type
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
pub struct IcmpType(pub u8);

impl IcmpType {
    pub const ECHO_REPLY: IcmpType = IcmpType(0); // Echo Reply
    pub const DEST_UNREACH: IcmpType = IcmpType(3); // Destination Unreachable
    pub const SOURCE_QUENCH: IcmpType = IcmpType(4); // Source Quench
    pub const REDIRECT: IcmpType = IcmpType(5); // Redirect (change route)
    pub const ECHO: IcmpType = IcmpType(8); // Echo Request
    pub const ROUTER_ADV: IcmpType = IcmpType(9); // Router Advertisement
    pub const ROUTER_SOLICIT: IcmpType = IcmpType(10); // Router Solicitation
    pub const TIME_EXCEEDED: IcmpType = IcmpType(11); // Time Exceeded
    pub const PARAMETER_PROBLEM: IcmpType = IcmpType(12); // Parameter Problem
    pub const TIMESTAMP: IcmpType = IcmpType(13); // Timestamp Request
    pub const TIMESTAMP_REPLY: IcmpType = IcmpType(14); // Timestamp Reply
    pub const INFO_REQUEST: IcmpType = IcmpType(15); // Information Request
    pub const INFO_REPLY: IcmpType = IcmpType(16); // Information Reply
    pub const ADDRESS: IcmpType = IcmpType(17); // Address Mask Request
    pub const ADDRESS_REPLY: IcmpType = IcmpType(18); // Address Mask Reply
    pub const EX_ECHO: IcmpType = IcmpType(42); // Extended Echo Request
    pub const EX_ECHO_REPLY: IcmpType = IcmpType(43); // Extended Echo Reply
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        IcmpType(value)
    }
}

impl From<IcmpType> for u8 {
    fn from(value: IcmpType) -> Self {
        value.0
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "echo-reply",
            3 => "dest-unreachable",
            4 => "source-quench",
            5 => "redirect",
            8 => "echo-request",
            9 => "router-adv",
            10 => "router-solicit",
            11 => "time-exceeded",
            12 => "param-problem",
            13 => "timestamp-request",
            14 => "timestamp-reply",
            15 => "info-request",
            16 => "info-reply",
            17 => "address-request",
            18 => "address-reply",
            42 => "ex-echo-request",
            43 => "ex-echo-reply",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMP Code for Destination Unreachable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IcmpCodeUnreachable(pub u8);

impl IcmpCodeUnreachable {
    pub const NET_UNREACH: IcmpCodeUnreachable = IcmpCodeUnreachable(0); // Network Unreachable
    pub const HOST_UNREACH: IcmpCodeUnreachable = IcmpCodeUnreachable(1); // Host Unreachable
    pub const PROT_UNREACH: IcmpCodeUnreachable = IcmpCodeUnreachable(2); // Protocol Unreachable
    pub const PORT_UNREACH: IcmpCodeUnreachable = IcmpCodeUnreachable(3); // Port Unreachable
    pub const FRAG_NEEDED: IcmpCodeUnreachable = IcmpCodeUnreachable(4); // Fragmentation Needed/DF set
    pub const SR_FAILED: IcmpCodeUnreachable = IcmpCodeUnreachable(5); // Source Route failed
    pub const NET_UNKNOWN: IcmpCodeUnreachable = IcmpCodeUnreachable(6); // Network Unknown
    pub const HOST_UNKNOWN: IcmpCodeUnreachable = IcmpCodeUnreachable(7); // Host Unknown
    pub const HOST_ISOLATED: IcmpCodeUnreachable = IcmpCodeUnreachable(8); // Host Isolated
    pub const NET_ANO: IcmpCodeUnreachable = IcmpCodeUnreachable(9); // Network ANO
    pub const HOST_ANO: IcmpCodeUnreachable = IcmpCodeUnreachable(10); // Host ANO
    pub const NET_UNR_TOS: IcmpCodeUnreachable = IcmpCodeUnreachable(11); // Network Unreachable for TOS
    pub const HOST_UNR_TOS: IcmpCodeUnreachable = IcmpCodeUnreachable(12); // Host Unreachable for TOS
    pub const PKT_FILTERED: IcmpCodeUnreachable = IcmpCodeUnreachable(13); // Packet filtered
    pub const PREC_VIOLATION: IcmpCodeUnreachable = IcmpCodeUnreachable(14); // Precedence violation
    pub const PREC_CUTOFF: IcmpCodeUnreachable = IcmpCodeUnreachable(15); // Precedence cut off
}

impl From<u8> for IcmpCodeUnreachable {
    fn from(value: u8) -> Self {
        IcmpCodeUnreachable(value)
    }
}

impl From<IcmpCodeUnreachable> for u8 {
    fn from(value: IcmpCodeUnreachable) -> Self {
        value.0
    }
}

impl fmt::Display for IcmpCodeUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "net-unreachable",
            1 => "host-unreachable",
            2 => "protocol-unreachable",
            3 => "port-unreachable",
            4 => "frag-needed",
            5 => "source-route-failed",
            6 => "dest-net-unknown",
            7 => "dest-host-unknown",
            8 => "source-host-isolated",
            9 => "dest-net-prohibited",
            10 => "dest-host-prohibited",
            11 => "net-unreachable-tos",
            12 => "host-unreachable-tos",
            13 => "pkt-filtered",
            14 => "precedence-violation",
            15 => "precedence-cutoff",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMP Code for Redirect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IcmpCodeRedirect(pub u8);

impl IcmpCodeRedirect {
    pub const REDIR_NET: IcmpCodeRedirect = IcmpCodeRedirect(0); // Redirect Net
    pub const REDIR_HOST: IcmpCodeRedirect = IcmpCodeRedirect(1); // Redirect Host
    pub const REDIR_NETTOS: IcmpCodeRedirect = IcmpCodeRedirect(2); // Redirect Net for TOS
    pub const REDIR_HOSTTOS: IcmpCodeRedirect = IcmpCodeRedirect(3); // Redirect Host for TOS
}

impl From<u8> for IcmpCodeRedirect {
    fn from(value: u8) -> Self {
        IcmpCodeRedirect(value)
    }
}

impl From<IcmpCodeRedirect> for u8 {
    fn from(value: IcmpCodeRedirect) -> Self {
        value.0
    }
}

impl fmt::Display for IcmpCodeRedirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "redirect-net",
            1 => "redirect-host",
            2 => "redirect-net-tos",
            3 => "redirect-host-tos",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMP Code for Time Exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IcmpCodeTimeExceed(pub u8);

impl IcmpCodeTimeExceed {
    pub const EXC_TTL: IcmpCodeTimeExceed = IcmpCodeTimeExceed(0); // TTL count exceeded
    pub const EXC_FRAGTIME: IcmpCodeTimeExceed = IcmpCodeTimeExceed(1); // Fragment Reass time exceeded
}

impl From<u8> for IcmpCodeTimeExceed {
    fn from(value: u8) -> Self {
        IcmpCodeTimeExceed(value)
    }
}

impl From<IcmpCodeTimeExceed> for u8 {
    fn from(value: IcmpCodeTimeExceed) -> Self {
        value.0
    }
}

impl fmt::Display for IcmpCodeTimeExceed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "ttl-exceeded",
            1 => "frag-time-exceeded",
            _ => return write!(f, "unknown-{}", self.0),
        };
        write!(f, "{}", s)
    }
}

/// ICMP Header structure as defined in RFC 792
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct IcmpHeader {
    icmp_type: IcmpType,
    code: u8,
    checksum: U16<BigEndian>,
    // Union data - we represent it as raw bytes
    // Can be interpreted as:
    // - echo: id (u16) + sequence (u16)
    // - gateway: gateway address (u32)
    // - frag: reserved (u16) + mtu (u16)
    un: U32<BigEndian>,
}

impl IcmpHeader {
    pub const FIXED_LEN: usize = mem::size_of::<IcmpHeader>();

    /// Returns the ICMP message type
    #[inline]
    pub fn icmp_type(&self) -> IcmpType {
        self.icmp_type
    }

    /// Returns the ICMP code
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

    /// For Redirect: returns the gateway address
    #[inline]
    pub fn gateway(&self) -> u32 {
        self.un.get()
    }

    /// For Fragmentation Needed: returns the MTU
    #[inline]
    pub fn frag_mtu(&self) -> u16 {
        (self.un.get() & 0xFFFF) as u16
    }

    /// Validates the ICMP header
    #[inline]
    pub fn is_valid(&self) -> bool {
        // Basic validation - all ICMP headers are valid structurally
        // Additional validation can be done based on type/code combinations
        true
    }

    /// Compute ICMP checksum
    pub fn compute_checksum(icmp_data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        let mut i = 0;
        while i < icmp_data.len() {
            if i + 1 < icmp_data.len() {
                let word = u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]);
                sum += word as u32;
                i += 2;
            } else {
                // Odd length: pad with zero
                let word = u16::from_be_bytes([icmp_data[i], 0]);
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

    /// Verify ICMP checksum
    pub fn verify_checksum(&self, icmp_data: &[u8]) -> bool {
        let computed = Self::compute_checksum(icmp_data);
        computed == 0 || computed == 0xFFFF
    }
}

impl PacketHeader for IcmpHeader {
    const NAME: &'static str = "IcmpHeader";
    type InnerType = IcmpType;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.icmp_type
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

impl HeaderParser for IcmpHeader {
    type Output<'a> = &'a IcmpHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for IcmpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ICMP {}", self.icmp_type())?;

        // Add type-specific information
        match self.icmp_type() {
            IcmpType::ECHO | IcmpType::ECHO_REPLY => {
                write!(f, " id={} seq={}", self.echo_id(), self.echo_sequence())?;
            }
            IcmpType::DEST_UNREACH => {
                let code = IcmpCodeUnreachable::from(self.code());
                write!(f, " code={}", code)?;
                if self.code() == IcmpCodeUnreachable::FRAG_NEEDED.into() {
                    write!(f, " mtu={}", self.frag_mtu())?;
                }
            }
            IcmpType::REDIRECT => {
                let code = IcmpCodeRedirect::from(self.code());
                write!(f, " code={} gateway={}", code, self.gateway())?;
            }
            IcmpType::TIME_EXCEEDED => {
                let code = IcmpCodeTimeExceed::from(self.code());
                write!(f, " code={}", code)?;
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
    fn test_icmp_type_constants() {
        assert_eq!(IcmpType::ECHO_REPLY.0, 0);
        assert_eq!(IcmpType::DEST_UNREACH.0, 3);
        assert_eq!(IcmpType::ECHO.0, 8);
        assert_eq!(IcmpType::TIME_EXCEEDED.0, 11);
    }

    #[test]
    fn test_icmp_type_as_str() {
        assert_eq!(format!("{}", IcmpType::ECHO), "echo-request");
        assert_eq!(format!("{}", IcmpType::ECHO_REPLY), "echo-reply");
        assert_eq!(format!("{}", IcmpType::DEST_UNREACH), "dest-unreachable");
        assert_eq!(format!("{}", IcmpType::TIME_EXCEEDED), "time-exceeded");
        assert_eq!(format!("{}", IcmpType::from(99)), "unknown-99");
    }

    #[test]
    fn test_icmp_code_constants() {
        assert_eq!(IcmpCodeUnreachable::NET_UNREACH.0, 0);
        assert_eq!(IcmpCodeUnreachable::HOST_UNREACH.0, 1);
        assert_eq!(IcmpCodeUnreachable::PORT_UNREACH.0, 3);

        assert_eq!(IcmpCodeRedirect::REDIR_NET.0, 0);
        assert_eq!(IcmpCodeRedirect::REDIR_HOST.0, 1);

        assert_eq!(IcmpCodeTimeExceed::EXC_TTL.0, 0);
        assert_eq!(IcmpCodeTimeExceed::EXC_FRAGTIME.0, 1);
    }

    #[test]
    fn test_icmp_code_display() {
        assert_eq!(
            format!("{}", IcmpCodeUnreachable::PORT_UNREACH),
            "port-unreachable"
        );
        assert_eq!(
            format!("{}", IcmpCodeUnreachable::HOST_UNREACH),
            "host-unreachable"
        );
        assert_eq!(format!("{}", IcmpCodeUnreachable::from(99)), "unknown-99");

        assert_eq!(format!("{}", IcmpCodeRedirect::REDIR_HOST), "redirect-host");
        assert_eq!(format!("{}", IcmpCodeRedirect::from(99)), "unknown-99");

        assert_eq!(format!("{}", IcmpCodeTimeExceed::EXC_TTL), "ttl-exceeded");
        assert_eq!(format!("{}", IcmpCodeTimeExceed::from(99)), "unknown-99");
    }

    #[test]
    fn test_icmp_header_size() {
        assert_eq!(mem::size_of::<IcmpHeader>(), 8);
        assert_eq!(IcmpHeader::FIXED_LEN, 8);
    }

    #[test]
    fn test_icmp_echo_request() {
        let mut packet = Vec::new();

        // ICMP Echo Request
        packet.push(8); // Type: Echo Request
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (will be computed)
        packet.extend_from_slice(&1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&5678u16.to_be_bytes()); // Sequence

        let result = IcmpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, _) = result.unwrap();
        assert_eq!(header.icmp_type(), IcmpType::ECHO);
        assert_eq!(header.code(), 0);
        assert_eq!(header.echo_id(), 1234);
        assert_eq!(header.echo_sequence(), 5678);
        assert!(header.is_valid());
    }

    #[test]
    fn test_icmp_echo_reply() {
        let mut packet = Vec::new();

        // ICMP Echo Reply
        packet.push(0); // Type: Echo Reply
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&5678u16.to_be_bytes()); // Sequence

        let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp_type(), IcmpType::ECHO_REPLY);
        assert_eq!(header.code(), 0);
        assert_eq!(header.echo_id(), 1234);
        assert_eq!(header.echo_sequence(), 5678);
    }

    #[test]
    fn test_icmp_dest_unreachable() {
        let mut packet = Vec::new();

        // ICMP Destination Unreachable - Port Unreachable
        packet.push(3); // Type: Dest Unreachable
        packet.push(IcmpCodeUnreachable::PORT_UNREACH.0); // Code: Port Unreachable
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&0u32.to_be_bytes()); // Unused

        let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp_type(), IcmpType::DEST_UNREACH);
        assert_eq!(header.code(), IcmpCodeUnreachable::PORT_UNREACH.0);
    }

    #[test]
    fn test_icmp_time_exceeded() {
        let mut packet = Vec::new();

        // ICMP Time Exceeded - TTL exceeded
        packet.push(11); // Type: Time Exceeded
        packet.push(IcmpCodeTimeExceed::EXC_TTL.0); // Code: TTL exceeded
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&0u32.to_be_bytes()); // Unused

        let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp_type(), IcmpType::TIME_EXCEEDED);
        assert_eq!(header.code(), IcmpCodeTimeExceed::EXC_TTL.0);
    }

    #[test]
    fn test_icmp_redirect() {
        let mut packet = Vec::new();

        // ICMP Redirect - Redirect for Host
        packet.push(5); // Type: Redirect
        packet.push(IcmpCodeRedirect::REDIR_HOST.0); // Code: Redirect Host
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum

        // Gateway address: 192.168.1.1
        let gateway = 0xC0A80101u32;
        packet.extend_from_slice(&gateway.to_be_bytes());

        let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp_type(), IcmpType::REDIRECT);
        assert_eq!(header.code(), IcmpCodeRedirect::REDIR_HOST.0);
        assert_eq!(header.gateway(), gateway);
    }

    #[test]
    fn test_icmp_frag_needed() {
        let mut packet = Vec::new();

        // ICMP Destination Unreachable - Fragmentation Needed
        packet.push(3); // Type: Dest Unreachable
        packet.push(IcmpCodeUnreachable::FRAG_NEEDED.0); // Code: Frag Needed
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&0u16.to_be_bytes()); // Reserved
        packet.extend_from_slice(&1500u16.to_be_bytes()); // MTU

        let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();

        assert_eq!(header.icmp_type(), IcmpType::DEST_UNREACH);
        assert_eq!(header.code(), IcmpCodeUnreachable::FRAG_NEEDED.0);
        assert_eq!(header.frag_mtu(), 1500);
    }

    #[test]
    fn test_icmp_parsing_too_small() {
        let packet = vec![0u8; 7]; // Only 7 bytes, need 8

        let result = IcmpHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_icmp_total_len() {
        let packet = create_test_echo_packet();
        let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();

        // ICMP header is always 8 bytes (no variable length like TCP)
        assert_eq!(header.total_len(&packet), 8);
    }

    #[test]
    fn test_icmp_checksum_computation() {
        let mut packet = Vec::new();

        // ICMP Echo Request
        packet.push(8); // Type
        packet.push(0); // Code
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (zero for computation)
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&0x5678u16.to_be_bytes()); // Sequence

        // Add some payload
        packet.extend_from_slice(b"test data");

        let checksum = IcmpHeader::compute_checksum(&packet);

        // Checksum should be non-zero
        assert_ne!(checksum, 0);

        // Now set the checksum in the packet
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        // Verify should pass
        let (header, _) = IcmpHeader::from_bytes(&packet).unwrap();
        assert!(header.verify_checksum(&packet));
    }

    #[test]
    fn test_icmp_from_bytes_with_payload() {
        let mut packet = Vec::new();

        // ICMP Echo Request
        packet.push(8); // Type: Echo Request
        packet.push(0); // Code: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        packet.extend_from_slice(&1u16.to_be_bytes()); // ID
        packet.extend_from_slice(&1u16.to_be_bytes()); // Sequence

        // Add payload
        let payload_data = b"Hello ICMP!";
        packet.extend_from_slice(payload_data);

        let result = IcmpHeader::from_bytes(&packet);
        assert!(result.is_ok());

        let (header, payload) = result.unwrap();

        // Verify header fields
        assert_eq!(header.icmp_type(), IcmpType::ECHO);
        assert_eq!(header.code(), 0);
        assert_eq!(header.echo_id(), 1);
        assert_eq!(header.echo_sequence(), 1);

        // Verify payload separation
        assert_eq!(payload.len(), payload_data.len());
        assert_eq!(payload, payload_data);
    }

    // Helper function to create a test ICMP Echo packet
    fn create_test_echo_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Type: Echo Request
        packet.push(8);

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
