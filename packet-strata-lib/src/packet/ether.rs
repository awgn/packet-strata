//! Ethernet frame header parser
//!
//! This module implements parsing for Ethernet II frames as defined in IEEE 802.3.
//! Ethernet is the most widely used local area network (LAN) technology.
//!
//! # Ethernet II Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                    Destination MAC Address                    +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                      Source MAC Address                       +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           EtherType           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Header size: 14 bytes (fixed)
//! - MAC addresses: 6 bytes each
//! - EtherType: 2 bytes (identifies encapsulated protocol)
//! - Common EtherTypes: 0x0800 (IPv4), 0x86DD (IPv6), 0x0806 (ARP), 0x8100 (VLAN)
//!
//! # Examples
//!
//! ## Basic Ethernet parsing
//!
//! ```
//! use packet_strata::packet::ether::EtherHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // Ethernet frame with IPv4 payload
//! let packet = vec![
//!     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination: broadcast
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Source MAC
//!     0x08, 0x00,                          // EtherType: IPv4
//!     // IPv4 payload follows...
//! ];
//!
//! let (header, payload) = EtherHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.proto(), EtherProto::IPV4);
//! assert_eq!(format!("{}", header.dest()), "ff:ff:ff:ff:ff:ff");
//! assert_eq!(format!("{}", header.source()), "00:11:22:33:44:55");
//! ```
//!
//! ## Ethernet with ARP payload
//!
//! ```
//! use packet_strata::packet::ether::EtherHeader;
//! use packet_strata::packet::protocol::EtherProto;
//! use packet_strata::packet::HeaderParser;
//!
//! // Ethernet frame with ARP payload
//! let packet = vec![
//!     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination: broadcast
//!     0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,  // Source MAC
//!     0x08, 0x06,                          // EtherType: ARP
//!     // ARP payload follows...
//! ];
//!
//! let (header, payload) = EtherHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.proto(), EtherProto::ARP);
//! assert_eq!(payload.len(), 0);
//! ```

#![allow(dead_code)]

use core::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, U16};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

use std::ops::Deref;

const ETH_ALEN: usize = 6; // Ethernet address length
const ETH_HLEN: usize = 14; // Ethernet header length without VLAN
const ETH_ZLEN: usize = 60; // Minimum Ethernet frame length without FCS
const ETH_DATA_LEN: usize = 1500; // Maximum Ethernet payload length
const ETH_FRAME_LEN: usize = 1514; // Maximum Ethernet frame length without FCS
const VLAN_TAG_LEN: usize = 4; // VLAN tag length

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    Immutable,
    KnownLayout,
    Serialize,
    Deserialize
)]
#[serde(into = "String")]
#[serde(try_from = "String")]
pub struct EthAddr([u8; ETH_ALEN]);

impl Default for EthAddr {
    fn default() -> Self {
        EthAddr([0u8; ETH_ALEN])
    }
}

impl Display for EthAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Debug, Clone, Error)]
pub enum EtherError {
    #[error("Invalid Ethernet address format")]
    InvalidAddressFormat,
}

impl FromStr for EthAddr {
    type Err = EtherError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<u8> = s.split(':')
            .map(|part| u8::from_str_radix(part, 16).map_err(|_| EtherError::InvalidAddressFormat))
            .collect::<Result<Vec<u8>, _>>()?;

        if bytes.len() != ETH_ALEN {
            return Err(EtherError::InvalidAddressFormat);
        }

        let mut addr = [0u8; ETH_ALEN];
        addr.copy_from_slice(&bytes);
        Ok(EthAddr(addr))
    }
}

impl From<EthAddr> for String {
    #[inline]
    fn from(addr: EthAddr) -> Self {
        addr.to_string()
    }
}

impl TryFrom<String> for EthAddr {
    type Error = EtherError;
    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        EthAddr::from_str(&s)
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout, Debug, Clone, Copy)]
pub struct EtherHeader {
    dest: EthAddr,
    source: EthAddr,
    proto: EtherProto,
}

impl EtherHeader {
    pub fn dest(&self) -> &EthAddr {
        &self.dest
    }

    pub fn source(&self) -> &EthAddr {
        &self.source
    }

    pub fn protocol(&self) -> EtherProto {
        self.proto
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout, Debug, Clone, Copy)]
struct EtherHeaderFixed(EtherHeader);

impl PacketHeader for EtherHeaderFixed {
    const NAME: &'static str = "EtherHeaderFixed";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.0.proto
    }
}

impl HeaderParser for EtherHeaderFixed {
    type Output<'a> = &'a EtherHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        &header.0
    }
}

impl PacketHeader for EtherHeader {
    const NAME: &'static str = "EtherHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.proto
    }
}

impl HeaderParser for EtherHeader {
    type Output<'a> = EtherHeaderVlan<'a>;

    #[inline]
    fn into_view<'a>(_: &'a Self, _: &'a [u8]) -> Self::Output<'a> {
        unreachable!()
    }

    #[inline]
    fn from_bytes<'a>(
        buf: &'a [u8],
    ) -> Result<(Self::Output<'a>, &'a [u8]), super::PacketHeaderError> {
        let (eth_header, mut rest) = EtherHeaderFixed::from_bytes(buf)?;

        let mut ethernet_header = EtherHeaderVlan::Standard(eth_header);

        while ethernet_header.inner_type() == EtherProto::VLAN_8021Q {
            let (vlan_header, vlan_rest) = Ether8021qHeader::from_bytes(rest)?;
            rest = vlan_rest;

            ethernet_header = match &ethernet_header {
                EtherHeaderVlan::Standard(eth) => EtherHeaderVlan::VLAN8021Q(eth, vlan_header),
                EtherHeaderVlan::VLAN8021Q(eth, vlan) => {
                    EtherHeaderVlan::VLAN8021QNested(eth, vlan, vlan_header)
                }
                EtherHeaderVlan::VLAN8021QNested(_, _, _) => {
                    return Err(super::PacketHeaderError::Other(
                        "More than two nested VLAN tags are not supported",
                    ));
                }
            };
        }

        Ok((ethernet_header, rest))
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout, Debug, Clone, Copy)]
pub struct Ether8021qHeader {
    tci: U16<BigEndian>,
    proto: EtherProto,
}

impl Ether8021qHeader {
    pub fn vlan_id(&self) -> u16 {
        self.tci.get() & 0x0FFF
    }

    pub fn vlan_pcp(&self) -> u8 {
        ((self.tci.get() >> 13) & 0x07) as u8
    }

    pub fn vlan_dei(&self) -> bool {
        ((self.tci.get() >> 12) & 0x01) != 0
    }
}

impl Display for Ether8021qHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "802.1Q vid={} pcp={} dei={} proto={}",
            self.vlan_id(),
            self.vlan_pcp(),
            self.vlan_dei(),
            self.proto
        )
    }
}

impl PacketHeader for Ether8021qHeader {
    const NAME: &'static str = "Ether8021qHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.proto
    }
}

impl HeaderParser for Ether8021qHeader {
    type Output<'a> = &'a Ether8021qHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

#[derive(Debug, Clone)]
pub enum EtherHeaderVlan<'a> {
    Standard(&'a EtherHeader),
    VLAN8021Q(&'a EtherHeader, &'a Ether8021qHeader),
    VLAN8021QNested(&'a EtherHeader, &'a Ether8021qHeader, &'a Ether8021qHeader),
}

impl Display for EtherHeaderVlan<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EtherHeaderVlan::Standard(eth) => {
                write!(
                    f,
                    "Ethernet {} -> {} proto={}",
                    eth.source, eth.dest, eth.proto
                )
            }
            EtherHeaderVlan::VLAN8021Q(eth, vlan) => {
                write!(
                    f,
                    "Ethernet {} -> {} proto={} [{}]",
                    eth.source, eth.dest, eth.proto, vlan
                )
            }
            EtherHeaderVlan::VLAN8021QNested(eth, vlan1, vlan2) => {
                write!(
                    f,
                    "Ethernet {} -> {} proto={} [{}] [{}]",
                    eth.source, eth.dest, eth.proto, vlan1, vlan2
                )
            }
        }
    }
}

impl Deref for EtherHeaderVlan<'_> {
    type Target = EtherHeader;

    fn deref(&self) -> &Self::Target {
        match self {
            EtherHeaderVlan::Standard(eth) => eth,
            EtherHeaderVlan::VLAN8021Q(eth, _) => eth,
            EtherHeaderVlan::VLAN8021QNested(eth, _, _) => eth,
        }
    }
}

impl<'a> EtherHeaderVlan<'a> {
    pub fn dest(&self) -> &EthAddr {
        match self {
            EtherHeaderVlan::Standard(eth) => &eth.dest,
            EtherHeaderVlan::VLAN8021Q(eth, _) => &eth.dest,
            EtherHeaderVlan::VLAN8021QNested(eth, _, _) => &eth.dest,
        }
    }

    pub fn source(&self) -> &EthAddr {
        match self {
            EtherHeaderVlan::Standard(eth) => &eth.source,
            EtherHeaderVlan::VLAN8021Q(eth, _) => &eth.source,
            EtherHeaderVlan::VLAN8021QNested(eth, _, _) => &eth.source,
        }
    }

    pub fn inner_type(&self) -> EtherProto {
        match self {
            EtherHeaderVlan::Standard(eth) => eth.proto,
            EtherHeaderVlan::VLAN8021Q(_, vlan) => vlan.proto,
            EtherHeaderVlan::VLAN8021QNested(_, _, vlan) => vlan.proto,
        }
    }
}

impl PacketHeader for EtherHeaderVlan<'_> {
    const NAME: &'static str = "EtherHeaderVlan";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.inner_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ether_header_parse_ipv4() {
        let packet_bytes: [u8; 14] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dest MAC
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, // source MAC
            0x08, 0x00, // EtherType: IPv4
        ];

        // Parse the header using PacketHeader::from_bytes
        let (header, remaining) =
            EtherHeader::from_bytes(&packet_bytes).expect("Failed to parse EtherHeader");

        // Verify the protocol is IPv4
        assert_eq!(header.proto, EtherProto::IPV4);

        // Verify MAC addresses
        assert_eq!(header.dest.0, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(header.source.0, [0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);

        // Verify MAC addresses to_string()
        assert_eq!(header.dest.to_string(), "01:02:03:04:05:06");
        assert_eq!(header.source.to_string(), "07:08:09:0a:0b:0c");

        // Verify remaining buffer is empty
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_ether_header_parse_vlan() {
        let packet_bytes: [u8; 18] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dest MAC
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // source MAC
            0x81, 0x00, // EtherType: 802.1Q VLAN
            0x00, 0x2a, // TCI: VID=42 (0x002a), PCP=0, DEI=0
            0x08, 0x00, // Inner EtherType: IPv4
        ];

        // Parse the Ethernet header - now automatically parses VLAN headers
        let (eth_header_ext, remaining) =
            EtherHeader::from_bytes(&packet_bytes).expect("Failed to parse EtherHeader");

        // Verify MAC addresses using EtherHeaderVlan methods
        assert_eq!(
            eth_header_ext.dest().0,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(
            eth_header_ext.source().0,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );

        // Verify MAC addresses to_string()
        assert_eq!(eth_header_ext.dest().to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(eth_header_ext.source().to_string(), "11:22:33:44:55:66");

        // Verify the inner protocol (after VLAN) is IPv4
        assert_eq!(eth_header_ext.inner_type(), EtherProto::IPV4);

        // Verify remaining buffer is empty (VLAN header was consumed)
        assert_eq!(remaining.len(), 0);

        // Verify this is a VLAN8021Q variant
        match eth_header_ext {
            EtherHeaderVlan::VLAN8021Q(eth, vlan) => {
                // Verify the outer ethernet protocol is 802.1Q VLAN
                assert_eq!(eth.proto, EtherProto::VLAN_8021Q);

                // Verify VLAN ID is 42
                assert_eq!(vlan.vlan_id(), 42);

                // Verify PCP (Priority Code Point) is 0
                assert_eq!(vlan.vlan_pcp(), 0);

                // Verify DEI (Drop Eligible Indicator) is false
                assert!(!vlan.vlan_dei());

                // Verify the inner protocol is IPv4
                assert_eq!(vlan.proto, EtherProto::IPV4);

                // Verify the Display implementation
                let display_str = vlan.to_string();
                assert!(display_str.contains("vid=42"));
                assert!(display_str.contains("pcp=0"));
                assert!(display_str.contains("dei=false"));
            }
            _ => panic!("Expected VLAN8021Q variant"),
        }
    }
}
