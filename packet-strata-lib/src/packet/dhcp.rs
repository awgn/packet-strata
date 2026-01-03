//! DHCP (Dynamic Host Configuration Protocol) packet parsing
//!
//! This module implements parsing for DHCP packets as defined in RFC 2131.
//! DHCP is used to automatically assign IP addresses and network configuration
//! to hosts on a network.
//!
//! # DHCP Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            xid (4)                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           secs (2)            |           flags (2)           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          ciaddr (4)                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          yiaddr (4)                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          siaddr (4)                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          giaddr (4)                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          chaddr (16)                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          sname (64)                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          file (128)                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       options (variable)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Fixed header size: 236 bytes (before options)
//! - op: 1 (BOOTREQUEST), 2 (BOOTREPLY)
//! - Magic cookie: 0x63825363 marks start of options
//! - Common ports: 67 (server), 68 (client)
//!
//! # Examples
//!
//! ```no_run
//! use packet_strata::packet::dhcp::{DhcpHeader, DhcpOpCode, DhcpMessageType, DhcpOption};
//! use packet_strata::packet::HeaderParser;
//! use std::net::Ipv4Addr;
//!
//! # fn main() {
//! # let packet_bytes: Vec<u8> = vec![]; // DHCP packet data
//! let (dhcp, _) = DhcpHeader::from_bytes(&packet_bytes).unwrap();
//!
//! // Check if it's a request or reply
//! match dhcp.op() {
//!     DhcpOpCode::BOOTREQUEST => println!("DHCP Request"),
//!     DhcpOpCode::BOOTREPLY => println!("DHCP Reply"),
//!     _ => println!("Unknown"),
//! }
//!
//! // Access DHCP options
//! for option in dhcp.options() {
//!     if let DhcpOption::MessageType(msg_type) = option {
//!         println!("Message Type: {:?}", msg_type);
//!     }
//! }
//! # }
//! ```

use core::fmt;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use std::ops::Deref;
use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::ether::EthAddr;
use crate::packet::{HeaderParser, PacketHeader};

/// DHCP Magic Cookie (0x63825363)
pub const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

/// DHCP server port
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Maximum DHCP packet size
pub const DHCP_MAX_PACKET_SIZE: usize = 576;

/// DHCP Operation Code
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DhcpOpCode {
    BOOTREQUEST = 1, // Client to Server
    BOOTREPLY = 2,   // Server to Client
}

impl DhcpOpCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DhcpOpCode::BOOTREQUEST),
            2 => Some(DhcpOpCode::BOOTREPLY),
            _ => None,
        }
    }
}

impl Display for DhcpOpCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DhcpOpCode::BOOTREQUEST => write!(f, "BOOTREQUEST"),
            DhcpOpCode::BOOTREPLY => write!(f, "BOOTREPLY"),
        }
    }
}

/// DHCP Hardware Type (same as ARP)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DhcpHardwareType {
    ETHERNET = 1,
    IEEE802 = 6,
}

impl DhcpHardwareType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DhcpHardwareType::ETHERNET),
            6 => Some(DhcpHardwareType::IEEE802),
            _ => None,
        }
    }
}

impl Display for DhcpHardwareType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DhcpHardwareType::ETHERNET => write!(f, "ethernet"),
            DhcpHardwareType::IEEE802 => write!(f, "ieee802"),
        }
    }
}

/// DHCP Message Type (Option 53)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DhcpMessageType {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    DECLINE = 4,
    ACK = 5,
    NAK = 6,
    RELEASE = 7,
    INFORM = 8,
}

impl DhcpMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DhcpMessageType::DISCOVER),
            2 => Some(DhcpMessageType::OFFER),
            3 => Some(DhcpMessageType::REQUEST),
            4 => Some(DhcpMessageType::DECLINE),
            5 => Some(DhcpMessageType::ACK),
            6 => Some(DhcpMessageType::NAK),
            7 => Some(DhcpMessageType::RELEASE),
            8 => Some(DhcpMessageType::INFORM),
            _ => None,
        }
    }
}

impl Display for DhcpMessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DhcpMessageType::DISCOVER => write!(f, "DISCOVER"),
            DhcpMessageType::OFFER => write!(f, "OFFER"),
            DhcpMessageType::REQUEST => write!(f, "REQUEST"),
            DhcpMessageType::DECLINE => write!(f, "DECLINE"),
            DhcpMessageType::ACK => write!(f, "ACK"),
            DhcpMessageType::NAK => write!(f, "NAK"),
            DhcpMessageType::RELEASE => write!(f, "RELEASE"),
            DhcpMessageType::INFORM => write!(f, "INFORM"),
        }
    }
}

/// DHCP Fixed Header (236 bytes)
///
/// This represents the fixed portion of a DHCP packet as defined in RFC 2131.
/// The options field follows this header and is variable length.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout, Debug, Clone, Copy)]
pub struct DhcpHeader {
    op: u8,                 // Message op code / message type (1 = BOOTREQUEST, 2 = BOOTREPLY)
    htype: u8,              // Hardware address type (1 = Ethernet)
    hlen: u8,               // Hardware address length (6 for Ethernet)
    hops: u8,               // Client sets to zero, optionally used by relay agents
    xid: U32<BigEndian>,    // Transaction ID, a random number chosen by the client
    secs: U16<BigEndian>,   // Seconds elapsed since client began address acquisition/renewal
    flags: U16<BigEndian>,  // Flags (bit 0 = broadcast flag)
    ciaddr: U32<BigEndian>, // Client IP address (if client is in BOUND, RENEW or REBINDING)
    yiaddr: U32<BigEndian>, // 'Your' (client) IP address
    siaddr: U32<BigEndian>, // IP address of next server to use in bootstrap
    giaddr: U32<BigEndian>, // Relay agent IP address
    chaddr: [u8; 16],       // Client hardware address (padded to 16 bytes)
    sname: [u8; 64],        // Optional server host name, null terminated string
    file: [u8; 128],        // Boot file name, null terminated string
    magic_cookie: U32<BigEndian>, // Magic cookie: 0x63825363
}

impl DhcpHeader {
    /// Returns the operation code
    #[inline]
    pub fn op(&self) -> DhcpOpCode {
        DhcpOpCode::from_u8(self.op).unwrap_or(DhcpOpCode::BOOTREQUEST)
    }

    /// Returns the hardware type
    #[inline]
    pub fn htype(&self) -> u8 {
        self.htype
    }

    /// Returns the hardware address length
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    /// Returns the hop count
    #[inline]
    pub fn hops(&self) -> u8 {
        self.hops
    }

    /// Returns the transaction ID
    #[inline]
    pub fn xid(&self) -> u32 {
        self.xid.get()
    }

    /// Returns the seconds elapsed
    #[inline]
    pub fn secs(&self) -> u16 {
        self.secs.get()
    }

    /// Returns the flags
    #[inline]
    pub fn flags(&self) -> u16 {
        self.flags.get()
    }

    /// Returns true if broadcast flag is set
    #[inline]
    pub fn is_broadcast(&self) -> bool {
        (self.flags.get() & 0x8000) != 0
    }

    /// Returns the client IP address
    #[inline]
    pub fn ciaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ciaddr.get())
    }

    /// Returns the 'your' (client) IP address
    #[inline]
    pub fn yiaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.yiaddr.get())
    }

    /// Returns the server IP address
    #[inline]
    pub fn siaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.siaddr.get())
    }

    /// Returns the relay agent IP address
    #[inline]
    pub fn giaddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.giaddr.get())
    }

    /// Returns the client hardware address (raw bytes)
    #[inline]
    pub fn chaddr_raw(&self) -> &[u8] {
        &self.chaddr[..self.hlen as usize]
    }

    /// For Ethernet, returns the client MAC address
    #[inline]
    pub fn chaddr_eth(&self) -> Option<&EthAddr> {
        if self.htype == 1 && self.hlen == 6 {
            zerocopy::Ref::<_, EthAddr>::from_prefix(&self.chaddr[..6])
                .ok()
                .map(|(r, _)| zerocopy::Ref::into_ref(r))
        } else {
            None
        }
    }

    /// Returns the server name (null-terminated)
    #[inline]
    pub fn sname(&self) -> &[u8] {
        // Find null terminator
        let end = self.sname.iter().position(|&b| b == 0).unwrap_or(64);
        &self.sname[..end]
    }

    /// Returns the boot file name (null-terminated)
    #[inline]
    pub fn file(&self) -> &[u8] {
        // Find null terminator
        let end = self.file.iter().position(|&b| b == 0).unwrap_or(128);
        &self.file[..end]
    }

    /// Returns the magic cookie
    #[inline]
    pub fn magic_cookie(&self) -> u32 {
        self.magic_cookie.get()
    }

    /// Validates the DHCP header
    #[inline]
    fn is_valid(&self) -> bool {
        // Check magic cookie
        if self.magic_cookie.get() != DHCP_MAGIC_COOKIE {
            return false;
        }

        // Check op code
        if self.op != 1 && self.op != 2 {
            return false;
        }

        // Check hardware address length is reasonable
        if self.hlen > 16 {
            return false;
        }

        true
    }
}

impl PacketHeader for DhcpHeader {
    const NAME: &'static str = "DhcpHeader";
    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}

    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for DhcpHeader {
    type Output<'a> = DhcpHeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, options: &'a [u8]) -> Self::Output<'a> {
        DhcpHeaderOpt { header, options }
    }

    // Custom implementation to consume all remaining bytes as options
    fn from_bytes<'a>(
        buf: &'a [u8],
    ) -> Result<(Self::Output<'a>, &'a [u8]), crate::packet::PacketHeaderError> {
        // Parse fixed header
        let (header_ref, rest) = zerocopy::Ref::<_, Self>::from_prefix(buf)
            .map_err(|_| crate::packet::PacketHeaderError::TooShort(Self::NAME))?;

        let header = zerocopy::Ref::into_ref(header_ref);

        if !header.is_valid() {
            return Err(crate::packet::PacketHeaderError::Invalid(Self::NAME));
        }

        // All remaining bytes are DHCP options
        let view = Self::into_view(header, rest);

        // Return empty slice as payload since DHCP options consumed everything
        Ok((view, &[]))
    }
}

/// DHCP Header with options
///
/// This is the proxy object returned by the parser. It provides access to both
/// the fixed header and the variable-length options field.
pub struct DhcpHeaderOpt<'a> {
    pub header: &'a DhcpHeader,
    pub options: &'a [u8],
}

impl<'a> DhcpHeaderOpt<'a> {
    /// Returns an iterator over DHCP options
    pub fn options(&self) -> DhcpOptionsIter<'a> {
        DhcpOptionsIter::new(self.options)
    }

    /// Find a specific option by code
    pub fn find_option(&self, code: u8) -> Option<DhcpOption<'a>> {
        self.options().find(|opt| opt.code() == Some(code))
    }

    /// Get the DHCP message type (option 53)
    pub fn message_type(&self) -> Option<DhcpMessageType> {
        self.find_option(53).and_then(|opt| {
            if let DhcpOption::MessageType(mt) = opt {
                Some(mt)
            } else {
                None
            }
        })
    }

    /// Get the requested IP address (option 50)
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.find_option(50).and_then(|opt| {
            if let DhcpOption::RequestedIpAddress(ip) = opt {
                Some(ip)
            } else {
                None
            }
        })
    }

    /// Get the subnet mask (option 1)
    pub fn subnet_mask(&self) -> Option<Ipv4Addr> {
        self.find_option(1).and_then(|opt| {
            if let DhcpOption::SubnetMask(mask) = opt {
                Some(mask)
            } else {
                None
            }
        })
    }

    /// Get the router/gateway (option 3)
    pub fn router(&self) -> Option<Vec<Ipv4Addr>> {
        self.find_option(3).and_then(|opt| {
            if let DhcpOption::Router(routers) = opt {
                Some(routers)
            } else {
                None
            }
        })
    }

    /// Get DNS servers (option 6)
    pub fn dns_servers(&self) -> Option<Vec<Ipv4Addr>> {
        self.find_option(6).and_then(|opt| {
            if let DhcpOption::DomainNameServer(dns) = opt {
                Some(dns)
            } else {
                None
            }
        })
    }

    /// Get the lease time (option 51)
    pub fn lease_time(&self) -> Option<u32> {
        self.find_option(51).and_then(|opt| {
            if let DhcpOption::IpAddressLeaseTime(time) = opt {
                Some(time)
            } else {
                None
            }
        })
    }

    /// Get the DHCP server identifier (option 54)
    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        self.find_option(54).and_then(|opt| {
            if let DhcpOption::ServerIdentifier(ip) = opt {
                Some(ip)
            } else {
                None
            }
        })
    }
}

impl Deref for DhcpHeaderOpt<'_> {
    type Target = DhcpHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl Display for DhcpHeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "DHCP {} xid=0x{:08x}", self.op(), self.xid())?;

        if let Some(msg_type) = self.message_type() {
            write!(f, " type={}", msg_type)?;
        }

        if let Some(chaddr) = self.chaddr_eth() {
            write!(f, " chaddr={}", chaddr)?;
        }

        Ok(())
    }
}

/// DHCP Option
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpOption<'a> {
    Pad,
    End,
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DomainNameServer(Vec<Ipv4Addr>),
    HostName(&'a [u8]),
    DomainName(&'a [u8]),
    RequestedIpAddress(Ipv4Addr),
    IpAddressLeaseTime(u32),
    MessageType(DhcpMessageType),
    ServerIdentifier(Ipv4Addr),
    ParameterRequestList(&'a [u8]),
    RenewalTime(u32),
    RebindingTime(u32),
    ClientIdentifier(&'a [u8]),
    Unknown { code: u8, data: &'a [u8] },
}

impl<'a> DhcpOption<'a> {
    /// Returns the option code, if available
    pub fn code(&self) -> Option<u8> {
        match self {
            DhcpOption::Pad => Some(0),
            DhcpOption::End => Some(255),
            DhcpOption::SubnetMask(_) => Some(1),
            DhcpOption::Router(_) => Some(3),
            DhcpOption::DomainNameServer(_) => Some(6),
            DhcpOption::HostName(_) => Some(12),
            DhcpOption::DomainName(_) => Some(15),
            DhcpOption::RequestedIpAddress(_) => Some(50),
            DhcpOption::IpAddressLeaseTime(_) => Some(51),
            DhcpOption::MessageType(_) => Some(53),
            DhcpOption::ServerIdentifier(_) => Some(54),
            DhcpOption::ParameterRequestList(_) => Some(55),
            DhcpOption::RenewalTime(_) => Some(58),
            DhcpOption::RebindingTime(_) => Some(59),
            DhcpOption::ClientIdentifier(_) => Some(61),
            DhcpOption::Unknown { code, .. } => Some(*code),
        }
    }

    /// Parse a single DHCP option from bytes
    fn parse(data: &'a [u8]) -> Option<(Self, &'a [u8])> {
        if data.is_empty() {
            return None;
        }

        let code = data[0];

        // Pad and End have no length field
        if code == 0 {
            return Some((DhcpOption::Pad, &data[1..]));
        }
        if code == 255 {
            return Some((DhcpOption::End, &data[1..]));
        }

        if data.len() < 2 {
            return None;
        }

        let length = data[1] as usize;
        if data.len() < 2 + length {
            return None;
        }

        let option_data = &data[2..2 + length];
        let remaining = &data[2 + length..];

        let option = match code {
            1 if length == 4 => DhcpOption::SubnetMask(Ipv4Addr::from(u32::from_be_bytes(
                option_data.try_into().ok()?,
            ))),
            3 if length.is_multiple_of(4) => {
                let routers = option_data
                    .chunks_exact(4)
                    .map(|chunk| Ipv4Addr::from(u32::from_be_bytes(chunk.try_into().unwrap())))
                    .collect();
                DhcpOption::Router(routers)
            }
            6 if length.is_multiple_of(4) => {
                let servers = option_data
                    .chunks_exact(4)
                    .map(|chunk| Ipv4Addr::from(u32::from_be_bytes(chunk.try_into().unwrap())))
                    .collect();
                DhcpOption::DomainNameServer(servers)
            }
            12 => DhcpOption::HostName(option_data),
            15 => DhcpOption::DomainName(option_data),
            50 if length == 4 => DhcpOption::RequestedIpAddress(Ipv4Addr::from(
                u32::from_be_bytes(option_data.try_into().ok()?),
            )),
            51 if length == 4 => {
                DhcpOption::IpAddressLeaseTime(u32::from_be_bytes(option_data.try_into().ok()?))
            }
            53 if length == 1 => DhcpOption::MessageType(DhcpMessageType::from_u8(option_data[0])?),
            54 if length == 4 => DhcpOption::ServerIdentifier(Ipv4Addr::from(u32::from_be_bytes(
                option_data.try_into().ok()?,
            ))),
            55 => DhcpOption::ParameterRequestList(option_data),
            58 if length == 4 => {
                DhcpOption::RenewalTime(u32::from_be_bytes(option_data.try_into().ok()?))
            }
            59 if length == 4 => {
                DhcpOption::RebindingTime(u32::from_be_bytes(option_data.try_into().ok()?))
            }
            61 => DhcpOption::ClientIdentifier(option_data),
            _ => DhcpOption::Unknown {
                code,
                data: option_data,
            },
        };

        Some((option, remaining))
    }
}

/// Iterator over DHCP options
pub struct DhcpOptionsIter<'a> {
    data: &'a [u8],
    done: bool,
}

impl<'a> DhcpOptionsIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, done: false }
    }
}

impl<'a> Iterator for DhcpOptionsIter<'a> {
    type Item = DhcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.data.is_empty() {
            return None;
        }

        let (option, remaining) = DhcpOption::parse(self.data)?;
        self.data = remaining;

        if matches!(option, DhcpOption::End) {
            self.done = true;
        }

        Some(option)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_basic_dhcp_discover() -> Vec<u8> {
        let mut packet = vec![
            1, // op: BOOTREQUEST
            1, // htype: Ethernet
            6, // hlen: 6
            0, // hops: 0
        ];

        // Fixed header
        packet.extend_from_slice(&0x12345678u32.to_be_bytes()); // xid
        packet.extend_from_slice(&0u16.to_be_bytes()); // secs
        packet.extend_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
        packet.extend_from_slice(&[0; 4]); // ciaddr: 0.0.0.0
        packet.extend_from_slice(&[0; 4]); // yiaddr: 0.0.0.0
        packet.extend_from_slice(&[0; 4]); // siaddr: 0.0.0.0
        packet.extend_from_slice(&[0; 4]); // giaddr: 0.0.0.0

        // chaddr: MAC address + padding
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        packet.extend_from_slice(&[0; 10]);

        // sname: server name (64 bytes)
        packet.extend_from_slice(&[0; 64]);

        // file: boot file name (128 bytes)
        packet.extend_from_slice(&[0; 128]);

        // magic cookie
        packet.extend_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());

        packet
    }

    #[test]
    fn test_dhcp_discover_basic() {
        let mut packet = create_basic_dhcp_discover();

        // Add DHCP Message Type option (DISCOVER)
        packet.push(53); // option code
        packet.push(1); // length
        packet.push(1); // DISCOVER

        // End option
        packet.push(255);

        let (dhcp, remaining) = DhcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(remaining.len(), 0); // All options consumed
        assert_eq!(dhcp.op(), DhcpOpCode::BOOTREQUEST);
        assert_eq!(dhcp.htype(), 1);
        assert_eq!(dhcp.hlen(), 6);
        assert_eq!(dhcp.xid(), 0x12345678);
        assert!(dhcp.is_broadcast());
        assert_eq!(dhcp.ciaddr(), Ipv4Addr::new(0, 0, 0, 0));

        // Check MAC address
        assert_eq!(
            dhcp.chaddr_eth().unwrap(),
            &EthAddr::from_str("aa:bb:cc:dd:ee:ff").unwrap()
        );

        // Check message type from options
        let msg_type = dhcp.options().find_map(|opt| {
            if let DhcpOption::MessageType(mt) = opt {
                Some(mt)
            } else {
                None
            }
        });
        assert_eq!(msg_type, Some(DhcpMessageType::DISCOVER));
    }

    #[test]
    fn test_dhcp_offer() {
        let mut packet = create_basic_dhcp_discover();
        packet[0] = 2; // op: BOOTREPLY

        // Set yiaddr: 192.168.1.100
        packet[16..20].copy_from_slice(&[192, 168, 1, 100]);

        // Add DHCP Message Type option (OFFER)
        packet.push(53);
        packet.push(1);
        packet.push(2); // OFFER

        // Add Server Identifier
        packet.push(54);
        packet.push(4);
        packet.extend_from_slice(&[192, 168, 1, 1]);

        // Add Subnet Mask
        packet.push(1);
        packet.push(4);
        packet.extend_from_slice(&[255, 255, 255, 0]);

        // Add Router
        packet.push(3);
        packet.push(4);
        packet.extend_from_slice(&[192, 168, 1, 1]);

        // Add DNS Server
        packet.push(6);
        packet.push(4);
        packet.extend_from_slice(&[8, 8, 8, 8]);

        // Add Lease Time (86400 seconds = 1 day)
        packet.push(51);
        packet.push(4);
        packet.extend_from_slice(&86400u32.to_be_bytes());

        // End option
        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(dhcp.op(), DhcpOpCode::BOOTREPLY);
        assert_eq!(dhcp.yiaddr(), Ipv4Addr::new(192, 168, 1, 100));

        // Collect all options to verify they're parsed
        let options: Vec<_> = dhcp.options().collect();

        // Verify message type
        assert!(options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::MessageType(DhcpMessageType::OFFER))));

        // Verify server identifier
        assert!(options.iter().any(|opt| matches!(opt, DhcpOption::ServerIdentifier(ip) if *ip == Ipv4Addr::new(192, 168, 1, 1))));

        // Verify subnet mask
        assert!(options.iter().any(|opt| matches!(opt, DhcpOption::SubnetMask(mask) if *mask == Ipv4Addr::new(255, 255, 255, 0))));

        // Verify router
        assert!(options.iter().any(|opt| matches!(opt, DhcpOption::Router(routers) if routers.len() == 1 && routers[0] == Ipv4Addr::new(192, 168, 1, 1))));

        // Verify DNS
        assert!(options.iter().any(|opt| matches!(opt, DhcpOption::DomainNameServer(dns) if dns.len() == 1 && dns[0] == Ipv4Addr::new(8, 8, 8, 8))));

        // Verify lease time
        assert!(options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::IpAddressLeaseTime(86400))));
    }

    #[test]
    fn test_dhcp_request() {
        let mut packet = create_basic_dhcp_discover();

        // Add Message Type (REQUEST)
        packet.push(53);
        packet.push(1);
        packet.push(3); // REQUEST

        // Add Requested IP Address
        packet.push(50);
        packet.push(4);
        packet.extend_from_slice(&[192, 168, 1, 100]);

        // Add Server Identifier
        packet.push(54);
        packet.push(4);
        packet.extend_from_slice(&[192, 168, 1, 1]);

        // End option
        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        let options: Vec<_> = dhcp.options().collect();

        assert!(options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::MessageType(DhcpMessageType::REQUEST))));
        assert!(options.iter().any(|opt| matches!(opt, DhcpOption::RequestedIpAddress(ip) if *ip == Ipv4Addr::new(192, 168, 1, 100))));
        assert!(options.iter().any(|opt| matches!(opt, DhcpOption::ServerIdentifier(ip) if *ip == Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_dhcp_ack() {
        let mut packet = create_basic_dhcp_discover();
        packet[0] = 2; // BOOTREPLY

        // Set yiaddr
        packet[16..20].copy_from_slice(&[192, 168, 1, 100]);

        // Add Message Type (ACK)
        packet.push(53);
        packet.push(1);
        packet.push(5); // ACK

        // End option
        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(dhcp.op(), DhcpOpCode::BOOTREPLY);
        assert_eq!(dhcp.yiaddr(), Ipv4Addr::new(192, 168, 1, 100));

        // Check message type from options
        let msg_type = dhcp.options().find_map(|opt| {
            if let DhcpOption::MessageType(mt) = opt {
                Some(mt)
            } else {
                None
            }
        });
        assert_eq!(msg_type, Some(DhcpMessageType::ACK));
    }

    #[test]
    fn test_dhcp_nak() {
        let mut packet = create_basic_dhcp_discover();
        packet[0] = 2; // BOOTREPLY

        // Add Message Type (NAK)
        packet.push(53);
        packet.push(1);
        packet.push(6); // NAK

        // End option
        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        let msg_type = dhcp.options().find_map(|opt| {
            if let DhcpOption::MessageType(mt) = opt {
                Some(mt)
            } else {
                None
            }
        });
        assert_eq!(msg_type, Some(DhcpMessageType::NAK));
    }

    #[test]
    fn test_dhcp_invalid_magic_cookie() {
        let mut packet = create_basic_dhcp_discover();

        // Corrupt magic cookie
        let magic_offset = 236;
        packet[magic_offset..magic_offset + 4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let result = DhcpHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_dhcp_packet_too_short() {
        let packet = vec![0u8; 100]; // Too short
        let result = DhcpHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_dhcp_options_iterator() {
        let mut packet = create_basic_dhcp_discover();

        // Add multiple options
        packet.push(53);
        packet.push(1);
        packet.push(1); // DISCOVER

        packet.push(12); // Hostname
        packet.push(4);
        packet.extend_from_slice(b"test");

        packet.push(61); // Client Identifier
        packet.push(7);
        packet.push(1); // hardware type
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        packet.push(255); // End

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        let options: Vec<_> = dhcp.options().collect();
        // Should have: MessageType, HostName, ClientIdentifier, End = at least 4
        assert!(options.len() >= 4, "Got {} options", options.len());

        // Check message type
        assert!(matches!(
            options.iter().find(|opt| opt.code() == Some(53)),
            Some(DhcpOption::MessageType(DhcpMessageType::DISCOVER))
        ));

        // Check hostname
        assert!(matches!(
            options.iter().find(|opt| opt.code() == Some(12)),
            Some(DhcpOption::HostName(b"test"))
        ));
    }

    #[test]
    fn test_dhcp_multiple_dns_servers() {
        let mut packet = create_basic_dhcp_discover();

        // Add multiple DNS servers
        packet.push(6);
        packet.push(8); // 2 DNS servers
        packet.extend_from_slice(&[8, 8, 8, 8]); // Google DNS
        packet.extend_from_slice(&[8, 8, 4, 4]); // Google DNS 2

        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        let options: Vec<_> = dhcp.options().collect();

        let dns_opt = options.iter().find_map(|opt| {
            if let DhcpOption::DomainNameServer(dns) = opt {
                Some(dns)
            } else {
                None
            }
        });

        assert!(dns_opt.is_some());
        let dns = dns_opt.unwrap();
        assert_eq!(dns.len(), 2);
        assert_eq!(dns[0], Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(dns[1], Ipv4Addr::new(8, 8, 4, 4));
    }

    #[test]
    fn test_dhcp_display() {
        let mut packet = create_basic_dhcp_discover();
        packet.push(53);
        packet.push(1);
        packet.push(1); // DISCOVER
        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();
        let display_str = format!("{}", dhcp);

        assert!(
            display_str.contains("BOOTREQUEST"),
            "Display string: {}",
            display_str
        );
        assert!(
            display_str.contains("0x12345678"),
            "Display string: {}",
            display_str
        );
        // Message type is displayed from options
        let has_discover = dhcp
            .options()
            .any(|opt| matches!(opt, DhcpOption::MessageType(DhcpMessageType::DISCOVER)));
        assert!(has_discover);
        assert!(
            display_str.contains("aa:bb:cc:dd:ee:ff"),
            "Display string: {}",
            display_str
        );
    }

    #[test]
    fn test_dhcp_broadcast_flag() {
        let mut packet = create_basic_dhcp_discover();
        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();
        assert!(dhcp.is_broadcast());

        // Test without broadcast flag
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());
        let (dhcp2, _) = DhcpHeader::from_bytes(&packet).unwrap();
        assert!(!dhcp2.is_broadcast());
    }

    #[test]
    fn test_dhcp_size_constants() {
        assert_eq!(std::mem::size_of::<DhcpHeader>(), 240);
        assert_eq!(DhcpHeader::FIXED_LEN, 240);
    }

    #[test]
    fn test_dhcp_deref() {
        let mut packet = create_basic_dhcp_discover();
        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        // Test that Deref works
        assert_eq!(dhcp.op(), DhcpOpCode::BOOTREQUEST);
        assert_eq!(dhcp.xid(), 0x12345678);
    }

    #[test]
    fn test_dhcp_unknown_option() {
        let mut packet = create_basic_dhcp_discover();

        // Add unknown option
        packet.push(200); // unknown code
        packet.push(3);
        packet.extend_from_slice(&[1, 2, 3]);

        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        let options: Vec<_> = dhcp.options().collect();
        assert!(options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::Unknown { code: 200, .. })));
    }

    #[test]
    fn test_dhcp_renewal_rebinding_times() {
        let mut packet = create_basic_dhcp_discover();

        // Add Renewal Time (T1)
        packet.push(58);
        packet.push(4);
        packet.extend_from_slice(&43200u32.to_be_bytes()); // 12 hours

        // Add Rebinding Time (T2)
        packet.push(59);
        packet.push(4);
        packet.extend_from_slice(&75600u32.to_be_bytes()); // 21 hours

        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        let options: Vec<_> = dhcp.options().collect();

        assert!(options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::RenewalTime(43200))));
        assert!(options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::RebindingTime(75600))));
    }

    #[test]
    fn test_dhcp_real_world_discover() {
        // Simulate a real DHCP DISCOVER packet
        let mut packet = vec![
            1, // BOOTREQUEST
            1, // Ethernet
            6, // hlen
            0, // hops
        ];

        packet.extend_from_slice(&0xABCDEF01u32.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0x8000u16.to_be_bytes());
        packet.extend_from_slice(&[0; 4]); // ciaddr
        packet.extend_from_slice(&[0; 4]); // yiaddr
        packet.extend_from_slice(&[0; 4]); // siaddr
        packet.extend_from_slice(&[0; 4]); // giaddr
        packet.extend_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        packet.extend_from_slice(&[0; 10]);
        packet.extend_from_slice(&[0; 64]);
        packet.extend_from_slice(&[0; 128]);
        packet.extend_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());

        // Options
        packet.push(53);
        packet.push(1);
        packet.push(1); // DISCOVER

        packet.push(55); // Parameter Request List
        packet.push(4);
        packet.extend_from_slice(&[1, 3, 6, 15]); // subnet, router, dns, domain

        packet.push(255);

        let (dhcp, _) = DhcpHeader::from_bytes(&packet).unwrap();

        assert_eq!(dhcp.op(), DhcpOpCode::BOOTREQUEST);
        assert_eq!(dhcp.xid(), 0xABCDEF01);
        assert!(dhcp.is_broadcast());

        let msg_type = dhcp.options().find_map(|opt| {
            if let DhcpOption::MessageType(mt) = opt {
                Some(mt)
            } else {
                None
            }
        });
        assert_eq!(msg_type, Some(DhcpMessageType::DISCOVER));
    }
}
