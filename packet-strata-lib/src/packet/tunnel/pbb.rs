//! PBB (Provider Backbone Bridge) / MAC-in-MAC protocol parser
//!
//! This module implements parsing for PBB as defined in IEEE 802.1ah.
//! PBB provides a scalable solution for extending Ethernet networks by
//! encapsulating customer Ethernet frames within provider backbone frames.
//!
//! # PBB Frame Format (IEEE 802.1ah)
//!
//! ```text
//! +-------------------+-------------------+-------+-------+-----------------+
//! | B-DA (6 bytes)    | B-SA (6 bytes)    | B-Tag | I-Tag | Customer Frame  |
//! +-------------------+-------------------+-------+-------+-----------------+
//!
//! B-Tag (4 bytes) - Backbone VLAN Tag:
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         EtherType (0x88A8)    |PCP|D|         B-VID           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! I-Tag (6 bytes) - Instance Service Tag:
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         EtherType (0x88E7)    |I-PCP|D|U|Res|    I-SID        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    I-SID (continued)        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - B-Tag EtherType: 0x88A8 (same as 802.1ad S-Tag)
//! - I-Tag EtherType: 0x88E7
//! - I-SID (Service Instance Identifier): 24 bits, supports up to 16 million service instances
//! - Encapsulates complete customer Ethernet frames (including customer VLANs)
//!
//! # Examples
//!
//! ## Basic I-Tag parsing
//!
//! ```
//! use packet_strata::packet::tunnel::pbb::PbbITag;
//! use packet_strata::packet::HeaderParser;
//!
//! // I-Tag with I-SID = 100
//! let packet = vec![
//!     0x88, 0xE7,              // EtherType
//!     0x00, 0x00, 0x00, 0x64,  // Flags + I-SID = 100
//!     // Customer Ethernet frame follows...
//!     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//! ];
//!
//! let (itag, payload) = PbbITag::from_bytes(&packet).unwrap();
//! assert_eq!(itag.isid(), 100);
//! ```
//!
//! ## I-Tag with priority
//!
//! ```
//! use packet_strata::packet::tunnel::pbb::PbbITag;
//! use packet_strata::packet::HeaderParser;
//!
//! // I-Tag with I-PCP = 5, I-DEI = 1, I-SID = 0x123456
//! let packet = vec![
//!     0x88, 0xE7,              // EtherType
//!     0xB0, 0x12, 0x34, 0x56,  // I-PCP=5, DEI=1, I-SID=0x123456
//!     // Payload
//!     0x00, 0x00,
//! ];
//!
//! let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
//! assert_eq!(itag.ipcp(), 5);
//! assert!(itag.dei());
//! assert_eq!(itag.isid(), 0x123456);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// I-Tag EtherType (802.1ah Backbone Service Tag)
pub const PBB_ITAG_ETHERTYPE: u16 = 0x88E7;

/// B-Tag EtherType (802.1ad Provider Bridge / S-Tag)
pub const PBB_BTAG_ETHERTYPE: u16 = 0x88A8;

/// Maximum I-SID value (24-bit field)
pub const PBB_MAX_ISID: u32 = 0xFFFFFF;

/// Check if EtherType is I-Tag (PBB)
#[inline]
pub fn is_pbb_itag_ethertype(ethertype: u16) -> bool {
    ethertype == PBB_ITAG_ETHERTYPE
}

/// Check if EtherType is B-Tag
#[inline]
pub fn is_pbb_btag_ethertype(ethertype: u16) -> bool {
    ethertype == PBB_BTAG_ETHERTYPE
}

/// PBB I-Tag (Instance Service Tag) as defined in IEEE 802.1ah
///
/// The I-Tag is 6 bytes and contains the service instance identifier (I-SID)
/// that identifies the service instance for customer traffic.
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         EtherType (0x88E7)    |I-PCP|D|U|Res|    I-SID (high) |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          I-SID (low)          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Fields:
/// - I-PCP (3 bits): Priority Code Point
/// - I-DEI (1 bit): Drop Eligible Indicator
/// - UCA (1 bit): Use Customer Address
/// - Reserved (3 bits): Reserved for future use
/// - I-SID (24 bits): Service Instance Identifier
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, KnownLayout, Immutable)]
pub struct PbbITag {
    ethertype: U16<BigEndian>,
    tci_isid_high: U16<BigEndian>,
    isid_low: U16<BigEndian>,
}

impl PbbITag {
    /// I-Tag EtherType value
    pub const ETHERTYPE: u16 = PBB_ITAG_ETHERTYPE;

    /// Header size in bytes
    pub const HEADER_LEN: usize = 6;

    // TCI field masks (in the tci_isid_high field)
    const IPCP_MASK: u16 = 0xE000;
    const IPCP_SHIFT: u32 = 13;
    const DEI_MASK: u16 = 0x1000;
    const UCA_MASK: u16 = 0x0800;
    const RESERVED_MASK: u16 = 0x0700;
    const ISID_HIGH_MASK: u16 = 0x00FF;

    #[allow(unused)]
    const NAME: &'static str = "PBB-I-Tag";

    /// Returns the EtherType field
    #[inline]
    pub fn ethertype(&self) -> u16 {
        self.ethertype.get()
    }

    /// Returns the Priority Code Point (I-PCP) - 3 bits
    ///
    /// Values 0-7 indicate the priority level for the frame.
    #[inline]
    pub fn ipcp(&self) -> u8 {
        ((self.tci_isid_high.get() & Self::IPCP_MASK) >> Self::IPCP_SHIFT) as u8
    }

    /// Returns the Drop Eligible Indicator (I-DEI)
    ///
    /// When true, the frame may be dropped in case of congestion.
    #[inline]
    pub fn dei(&self) -> bool {
        (self.tci_isid_high.get() & Self::DEI_MASK) != 0
    }

    /// Returns the Use Customer Address (UCA) flag
    ///
    /// When true, the customer destination address is used for forwarding decisions.
    #[inline]
    pub fn uca(&self) -> bool {
        (self.tci_isid_high.get() & Self::UCA_MASK) != 0
    }

    /// Returns the reserved bits (should be 0)
    #[inline]
    pub fn reserved(&self) -> u8 {
        ((self.tci_isid_high.get() & Self::RESERVED_MASK) >> 8) as u8
    }

    /// Returns the Service Instance Identifier (I-SID) - 24 bits
    ///
    /// The I-SID identifies the service instance. Valid values are 0 to 16,777,215.
    #[inline]
    pub fn isid(&self) -> u32 {
        let high = (self.tci_isid_high.get() & Self::ISID_HIGH_MASK) as u32;
        let low = self.isid_low.get() as u32;
        (high << 16) | low
    }

    /// Validates the I-Tag header
    #[inline]
    fn is_valid(&self) -> bool {
        self.ethertype.get() == Self::ETHERTYPE
    }

    /// Returns a string representation of the flags
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();
        if self.dei() {
            flags.push("DEI");
        }
        if self.uca() {
            flags.push("UCA");
        }
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join("|")
        }
    }
}

impl PacketHeader for PbbITag {
    const NAME: &'static str = "PBB-I-Tag";

    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        // I-Tag encapsulates customer Ethernet frames
        EtherProto::TEB
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::HEADER_LEN
    }

    #[inline]
    fn is_valid(&self) -> bool {
        PbbITag::is_valid(self)
    }
}

impl HeaderParser for PbbITag {
    type Output<'a> = &'a PbbITag;

    #[inline]
    fn into_view<'a>(header: &'a Self, _raw_options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for PbbITag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PBB I-Tag I-SID={} I-PCP={} flags=[{}]",
            self.isid(),
            self.ipcp(),
            self.flags_string()
        )
    }
}

/// PBB B-Tag (Backbone VLAN Tag) as defined in IEEE 802.1ah
///
/// The B-Tag is essentially an 802.1ad S-Tag used in the provider backbone.
/// It is 4 bytes and contains the Backbone VLAN ID (B-VID).
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         EtherType (0x88A8)    |PCP|D|         B-VID           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, KnownLayout, Immutable)]
pub struct PbbBTag {
    ethertype: U16<BigEndian>,
    tci: U16<BigEndian>,
}

impl PbbBTag {
    /// B-Tag EtherType value
    pub const ETHERTYPE: u16 = PBB_BTAG_ETHERTYPE;

    /// Header size in bytes
    pub const HEADER_LEN: usize = 4;

    // TCI field masks
    const PCP_MASK: u16 = 0xE000;
    const PCP_SHIFT: u32 = 13;
    const DEI_MASK: u16 = 0x1000;
    const VID_MASK: u16 = 0x0FFF;

    #[allow(unused)]
    const NAME: &'static str = "PBB-B-Tag";

    /// Returns the EtherType field
    #[inline]
    pub fn ethertype(&self) -> u16 {
        self.ethertype.get()
    }

    /// Returns the Priority Code Point (PCP) - 3 bits
    #[inline]
    pub fn pcp(&self) -> u8 {
        ((self.tci.get() & Self::PCP_MASK) >> Self::PCP_SHIFT) as u8
    }

    /// Returns the Drop Eligible Indicator (DEI)
    #[inline]
    pub fn dei(&self) -> bool {
        (self.tci.get() & Self::DEI_MASK) != 0
    }

    /// Returns the Backbone VLAN ID (B-VID) - 12 bits
    #[inline]
    pub fn bvid(&self) -> u16 {
        self.tci.get() & Self::VID_MASK
    }

    /// Returns the raw TCI field
    #[inline]
    pub fn tci(&self) -> u16 {
        self.tci.get()
    }

    /// Validates the B-Tag header
    #[inline]
    fn is_valid(&self) -> bool {
        self.ethertype.get() == Self::ETHERTYPE
    }
}

impl PacketHeader for PbbBTag {
    const NAME: &'static str = "PBB-B-Tag";

    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        // B-Tag is followed by I-Tag
        EtherProto::VLAN_8021AH
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::HEADER_LEN
    }

    #[inline]
    fn is_valid(&self) -> bool {
        PbbBTag::is_valid(self)
    }
}

impl HeaderParser for PbbBTag {
    type Output<'a> = &'a PbbBTag;

    #[inline]
    fn into_view<'a>(header: &'a Self, _raw_options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for PbbBTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PBB B-Tag B-VID={} PCP={}{}",
            self.bvid(),
            self.pcp(),
            if self.dei() { " DEI" } else { "" }
        )
    }
}

/// Complete PBB header combining B-Tag and I-Tag
///
/// This structure represents the full PBB encapsulation header
/// (excluding the outer Ethernet addresses which are part of the
/// backbone Ethernet header).
#[derive(Debug, Clone)]
pub struct PbbHeader<'a> {
    /// B-Tag (Backbone VLAN Tag) - optional
    pub btag: Option<&'a PbbBTag>,
    /// I-Tag (Instance Service Tag)
    pub itag: &'a PbbITag,
}

impl<'a> PbbHeader<'a> {
    /// Get the I-SID from the I-Tag
    #[inline]
    pub fn isid(&self) -> u32 {
        self.itag.isid()
    }

    /// Get the B-VID from the B-Tag (if present)
    #[inline]
    pub fn bvid(&self) -> Option<u16> {
        self.btag.map(|b| b.bvid())
    }

    /// Get the I-PCP from the I-Tag
    #[inline]
    pub fn ipcp(&self) -> u8 {
        self.itag.ipcp()
    }

    /// Check if DEI is set on the I-Tag
    #[inline]
    pub fn dei(&self) -> bool {
        self.itag.dei()
    }

    /// Check if UCA is set on the I-Tag
    #[inline]
    pub fn uca(&self) -> bool {
        self.itag.uca()
    }

    /// Get the total header length
    #[inline]
    pub fn header_len(&self) -> usize {
        let btag_len = if self.btag.is_some() {
            PbbBTag::HEADER_LEN
        } else {
            0
        };
        btag_len + PbbITag::HEADER_LEN
    }

    /// Parse PBB headers from a buffer
    ///
    /// This function attempts to parse both B-Tag and I-Tag.
    /// The buffer should start at the EtherType field after the
    /// outer (backbone) Ethernet addresses.
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8]), crate::packet::PacketHeaderError> {
        use crate::packet::PacketHeaderError;

        if buf.len() < 2 {
            return Err(PacketHeaderError::TooShort("PBB"));
        }

        let first_ethertype = u16::from_be_bytes([buf[0], buf[1]]);

        // Check if we have a B-Tag first
        if first_ethertype == PBB_BTAG_ETHERTYPE {
            // Parse B-Tag
            if buf.len() < PbbBTag::HEADER_LEN {
                return Err(PacketHeaderError::TooShort("PBB-B-Tag"));
            }

            let btag = zerocopy::Ref::<_, PbbBTag>::from_prefix(buf)
                .map_err(|_| PacketHeaderError::TooShort("PBB-B-Tag"))?;
            let btag = zerocopy::Ref::into_ref(btag.0);

            if !btag.is_valid() {
                return Err(PacketHeaderError::Invalid("PBB-B-Tag"));
            }

            // Parse I-Tag after B-Tag
            let itag_buf = &buf[PbbBTag::HEADER_LEN..];
            if itag_buf.len() < PbbITag::HEADER_LEN {
                return Err(PacketHeaderError::TooShort("PBB-I-Tag"));
            }

            let itag = zerocopy::Ref::<_, PbbITag>::from_prefix(itag_buf)
                .map_err(|_| PacketHeaderError::TooShort("PBB-I-Tag"))?;
            let itag = zerocopy::Ref::into_ref(itag.0);

            if !itag.is_valid() {
                return Err(PacketHeaderError::Invalid("PBB-I-Tag"));
            }

            let payload = &itag_buf[PbbITag::HEADER_LEN..];

            Ok((
                PbbHeader {
                    btag: Some(btag),
                    itag,
                },
                payload,
            ))
        } else if first_ethertype == PBB_ITAG_ETHERTYPE {
            // Only I-Tag, no B-Tag
            if buf.len() < PbbITag::HEADER_LEN {
                return Err(PacketHeaderError::TooShort("PBB-I-Tag"));
            }

            let itag = zerocopy::Ref::<_, PbbITag>::from_prefix(buf)
                .map_err(|_| PacketHeaderError::TooShort("PBB-I-Tag"))?;
            let itag = zerocopy::Ref::into_ref(itag.0);

            if !itag.is_valid() {
                return Err(PacketHeaderError::Invalid("PBB-I-Tag"));
            }

            let payload = &buf[PbbITag::HEADER_LEN..];

            Ok((PbbHeader { btag: None, itag }, payload))
        } else {
            Err(PacketHeaderError::Invalid("PBB: unknown EtherType"))
        }
    }
}

impl fmt::Display for PbbHeader<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(btag) = self.btag {
            write!(f, "{} -> {}", btag, self.itag)
        } else {
            write!(f, "{}", self.itag)
        }
    }
}

/// PBB-TE (Provider Backbone Bridge - Traffic Engineering) support
///
/// PBB-TE (IEEE 802.1Qay) extends PBB with traffic engineering capabilities
/// by using explicit paths rather than spanning tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbbTeEspType {
    /// Working path
    Working,
    /// Protection path
    Protection,
    /// Unknown ESP type
    Unknown(u8),
}

impl From<u8> for PbbTeEspType {
    fn from(value: u8) -> Self {
        match value {
            0 => PbbTeEspType::Working,
            1 => PbbTeEspType::Protection,
            v => PbbTeEspType::Unknown(v),
        }
    }
}

impl fmt::Display for PbbTeEspType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PbbTeEspType::Working => write!(f, "Working"),
            PbbTeEspType::Protection => write!(f, "Protection"),
            PbbTeEspType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::HeaderParser;

    #[test]
    fn test_pbb_itag_header_size() {
        assert_eq!(std::mem::size_of::<PbbITag>(), 6);
        assert_eq!(PbbITag::HEADER_LEN, 6);
    }

    #[test]
    fn test_pbb_btag_header_size() {
        assert_eq!(std::mem::size_of::<PbbBTag>(), 4);
        assert_eq!(PbbBTag::HEADER_LEN, 4);
    }

    #[test]
    fn test_pbb_itag_basic() {
        // I-Tag with I-SID = 100
        let packet = vec![
            0x88, 0xE7, // EtherType
            0x00, 0x00, 0x00, 0x64, // I-SID = 100
            // Payload
            0xFF, 0xFF,
        ];

        let (itag, payload) = PbbITag::from_bytes(&packet).unwrap();
        assert_eq!(itag.ethertype(), PBB_ITAG_ETHERTYPE);
        assert_eq!(itag.isid(), 100);
        assert_eq!(itag.ipcp(), 0);
        assert!(!itag.dei());
        assert!(!itag.uca());
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_pbb_itag_with_priority() {
        // I-Tag with I-PCP = 5, DEI = 1, I-SID = 0x123456
        let packet = vec![
            0x88, 0xE7, // EtherType
            0xB0, 0x12, // I-PCP=5, DEI=1, UCA=0, I-SID high
            0x34, 0x56, // I-SID low
        ];

        let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
        assert_eq!(itag.ipcp(), 5);
        assert!(itag.dei());
        assert!(!itag.uca());
        assert_eq!(itag.isid(), 0x123456);
    }

    #[test]
    fn test_pbb_itag_with_uca() {
        // I-Tag with UCA = 1
        let packet = vec![
            0x88, 0xE7, // EtherType
            0x08, 0x00, // UCA=1
            0x00, 0x01, // I-SID = 1
        ];

        let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
        assert!(itag.uca());
        assert_eq!(itag.isid(), 1);
    }

    #[test]
    fn test_pbb_itag_max_isid() {
        // I-Tag with max I-SID
        let packet = vec![
            0x88, 0xE7, // EtherType
            0x00, 0xFF, // I-SID high
            0xFF, 0xFF, // I-SID low
        ];

        let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
        assert_eq!(itag.isid(), PBB_MAX_ISID);
    }

    #[test]
    fn test_pbb_itag_invalid_ethertype() {
        let packet = vec![
            0x08, 0x00, // Wrong EtherType (IPv4)
            0x00, 0x00, 0x00, 0x64,
        ];

        let result = PbbITag::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbb_itag_too_short() {
        let packet = vec![0x88, 0xE7, 0x00, 0x00];
        let result = PbbITag::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbb_itag_display() {
        let packet = vec![0x88, 0xE7, 0xA0, 0x00, 0x00, 0x64];

        let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
        let display = format!("{}", itag);
        assert!(display.contains("PBB I-Tag"));
        assert!(display.contains("I-SID=100"));
        assert!(display.contains("I-PCP=5"));
    }

    #[test]
    fn test_pbb_itag_flags_string() {
        // With DEI and UCA
        let packet = vec![0x88, 0xE7, 0x18, 0x00, 0x00, 0x01];

        let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
        let flags = itag.flags_string();
        assert!(flags.contains("DEI"));
        assert!(flags.contains("UCA"));

        // No flags
        let packet2 = vec![0x88, 0xE7, 0x00, 0x00, 0x00, 0x01];
        let (itag2, _) = PbbITag::from_bytes(&packet2).unwrap();
        assert_eq!(itag2.flags_string(), "none");
    }

    #[test]
    fn test_pbb_btag_basic() {
        // B-Tag with B-VID = 100
        let packet = vec![
            0x88, 0xA8, // EtherType
            0x00, 0x64, // B-VID = 100
            // Payload (would be I-Tag)
            0x88, 0xE7,
        ];

        let (btag, payload) = PbbBTag::from_bytes(&packet).unwrap();
        assert_eq!(btag.ethertype(), PBB_BTAG_ETHERTYPE);
        assert_eq!(btag.bvid(), 100);
        assert_eq!(btag.pcp(), 0);
        assert!(!btag.dei());
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_pbb_btag_with_priority() {
        // B-Tag with PCP = 7, DEI = 1, B-VID = 4095
        let packet = vec![
            0x88, 0xA8, // EtherType
            0xFF, 0xFF, // PCP=7, DEI=1, B-VID=4095
        ];

        let (btag, _) = PbbBTag::from_bytes(&packet).unwrap();
        assert_eq!(btag.pcp(), 7);
        assert!(btag.dei());
        assert_eq!(btag.bvid(), 4095);
    }

    #[test]
    fn test_pbb_btag_display() {
        let packet = vec![0x88, 0xA8, 0xA0, 0x64];

        let (btag, _) = PbbBTag::from_bytes(&packet).unwrap();
        let display = format!("{}", btag);
        assert!(display.contains("PBB B-Tag"));
        assert!(display.contains("B-VID=100"));
        assert!(display.contains("PCP=5"));
    }

    #[test]
    fn test_pbb_header_parse_with_btag() {
        // Full PBB header: B-Tag + I-Tag
        let packet = vec![
            // B-Tag
            0x88, 0xA8, // EtherType
            0xA0, 0x64, // PCP=5, B-VID=100
            // I-Tag
            0x88, 0xE7, // EtherType
            0x60, 0x00, 0x01, 0x00, // I-PCP=3, I-SID=256
            // Payload
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let (header, payload) = PbbHeader::parse(&packet).unwrap();
        assert!(header.btag.is_some());
        assert_eq!(header.bvid(), Some(100));
        assert_eq!(header.isid(), 256);
        assert_eq!(header.ipcp(), 3);
        assert_eq!(header.header_len(), 10);
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_pbb_header_parse_itag_only() {
        // I-Tag only (no B-Tag)
        let packet = vec![
            0x88, 0xE7, // EtherType
            0x00, 0x00, 0x00, 0x64, // I-SID = 100
            // Payload
            0xFF, 0xFF,
        ];

        let (header, payload) = PbbHeader::parse(&packet).unwrap();
        assert!(header.btag.is_none());
        assert_eq!(header.bvid(), None);
        assert_eq!(header.isid(), 100);
        assert_eq!(header.header_len(), 6);
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_pbb_header_parse_invalid() {
        // Unknown EtherType
        let packet = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = PbbHeader::parse(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbb_header_display() {
        let packet = vec![
            0x88, 0xA8, 0x00, 0x64, // B-Tag
            0x88, 0xE7, 0x00, 0x00, 0x01, 0x00, // I-Tag
        ];

        let (header, _) = PbbHeader::parse(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("B-Tag"));
        assert!(display.contains("I-Tag"));
        assert!(display.contains("->"));
    }

    #[test]
    fn test_pbb_ethertype_helpers() {
        assert!(is_pbb_itag_ethertype(0x88E7));
        assert!(!is_pbb_itag_ethertype(0x88A8));

        assert!(is_pbb_btag_ethertype(0x88A8));
        assert!(!is_pbb_btag_ethertype(0x88E7));
    }

    #[test]
    fn test_pbb_inner_type() {
        let packet = vec![0x88, 0xE7, 0x00, 0x00, 0x00, 0x01];
        let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
        assert_eq!(itag.inner_type(), EtherProto::TEB);

        let packet2 = vec![0x88, 0xA8, 0x00, 0x01];
        let (btag, _) = PbbBTag::from_bytes(&packet2).unwrap();
        assert_eq!(btag.inner_type(), EtherProto::VLAN_8021AH);
    }

    #[test]
    fn test_pbb_te_esp_type() {
        assert_eq!(PbbTeEspType::from(0), PbbTeEspType::Working);
        assert_eq!(PbbTeEspType::from(1), PbbTeEspType::Protection);
        assert_eq!(PbbTeEspType::from(2), PbbTeEspType::Unknown(2));

        assert_eq!(format!("{}", PbbTeEspType::Working), "Working");
        assert_eq!(format!("{}", PbbTeEspType::Protection), "Protection");
        assert_eq!(format!("{}", PbbTeEspType::Unknown(5)), "Unknown(5)");
    }

    #[test]
    fn test_pbb_real_world_scenario() {
        // Simulate a real PBB frame structure
        // Outer: B-DA, B-SA, B-Tag, I-Tag, Customer frame
        let mut packet = Vec::new();

        // B-Tag: PCP=4, B-VID=1000
        packet.extend_from_slice(&[0x88, 0xA8]);
        packet.extend_from_slice(&[0x83, 0xE8]); // PCP=4, DEI=0, VID=1000

        // I-Tag: I-PCP=6, I-SID=50000
        packet.extend_from_slice(&[0x88, 0xE7]);
        packet.extend_from_slice(&[0xC0, 0x00]); // I-PCP=6, I-SID high
        packet.extend_from_slice(&[0xC3, 0x50]); // I-SID low (50000 = 0x00C350)

        // Customer Ethernet header (14 bytes)
        packet.extend_from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
            0x08, 0x00, // EtherType (IPv4)
        ]);

        let (header, payload) = PbbHeader::parse(&packet).unwrap();
        assert_eq!(header.bvid(), Some(1000));
        assert_eq!(header.isid(), 50000);
        assert_eq!(header.btag.unwrap().pcp(), 4);
        assert_eq!(header.ipcp(), 6);
        assert_eq!(payload.len(), 14); // Customer Ethernet header
    }

    #[test]
    fn test_pbb_itag_all_priorities() {
        for pcp in 0..8u8 {
            // I-PCP is in bits 15-13 of tci_isid_high field
            let tci_high = (pcp as u16) << 13;
            let packet = vec![
                0x88,
                0xE7,
                (tci_high >> 8) as u8,
                (tci_high & 0xFF) as u8,
                0x00,
                0x01,
            ];

            let (itag, _) = PbbITag::from_bytes(&packet).unwrap();
            assert_eq!(itag.ipcp(), pcp);
        }
    }

    #[test]
    fn test_pbb_btag_all_priorities() {
        for pcp in 0..8u8 {
            let tci = (pcp as u16) << 13;
            let packet = vec![0x88, 0xA8, (tci >> 8) as u8, tci as u8];

            let (btag, _) = PbbBTag::from_bytes(&packet).unwrap();
            assert_eq!(btag.pcp(), pcp);
        }
    }
}
