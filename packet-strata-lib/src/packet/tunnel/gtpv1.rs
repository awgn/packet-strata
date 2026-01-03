//! GTPv1 (GPRS Tunneling Protocol version 1) parser
//!
//! This module implements parsing for GTPv1 as defined in 3GPP TS 29.060.
//! GTPv1 is used for tunneling user data (GTP-U) and control signaling (GTP-C)
//! in GPRS and LTE networks.
//!
//! # GTPv1 Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Ver  |PT |(*)|E|S|PN|        Message Type                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Length                                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         TEID                                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       Sequence Number (opt)   |   N-PDU (opt) | Next Ext (opt)|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Ports
//!
//! - GTP-C (Control Plane): UDP port 2123
//! - GTP-U (User Plane): UDP port 2152
//!
//! # Examples
//!
//! ## Basic GTPv1-U parsing
//!
//! ```
//! use packet_strata::packet::tunnel::gtpv1::Gtpv1Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // GTPv1-U packet (G-PDU, message type 0xFF)
//! let packet = vec![
//!     0x30,        // Version 1, PT=1, no optional fields
//!     0xFF,        // Message type: G-PDU
//!     0x00, 0x04,  // Length: 4 bytes
//!     0x00, 0x00, 0x00, 0x01,  // TEID: 1
//!     // payload follows...
//!     0x45, 0x00, 0x00, 0x00,  // Inner IP packet
//! ];
//!
//! let (header, payload) = Gtpv1Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 1);
//! assert!(header.is_gtp());
//! assert_eq!(header.message_type(), 0xFF);
//! assert_eq!(header.teid(), 1);
//! ```
//!
//! ## GTPv1-U with sequence number
//!
//! ```
//! use packet_strata::packet::tunnel::gtpv1::Gtpv1Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // GTPv1-U with sequence number
//! let packet = vec![
//!     0x32,        // Version 1, PT=1, S=1
//!     0xFF,        // Message type: G-PDU
//!     0x00, 0x08,  // Length: 8 bytes (4 optional + 4 payload)
//!     0x00, 0x00, 0x00, 0x01,  // TEID: 1
//!     0x00, 0x01,  // Sequence number: 1
//!     0x00,        // N-PDU number: 0
//!     0x00,        // Next extension: None
//!     // payload follows...
//!     0x45, 0x00, 0x00, 0x00,
//! ];
//!
//! let (header, payload) = Gtpv1Header::from_bytes(&packet).unwrap();
//! assert!(header.has_sequence());
//! assert_eq!(header.sequence_number(), Some(1));
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::{HeaderParser, PacketHeader};

/// GTPv1-C standard port (Control Plane)
pub const GTPV1_C_PORT: u16 = 2123;

/// GTPv1-U standard port (User Plane)
pub const GTPV1_U_PORT: u16 = 2152;

/// Check if port is GTPv1-C
#[inline]
pub fn is_gtpv1_c_port(port: u16) -> bool {
    port == GTPV1_C_PORT
}

/// Check if port is GTPv1-U
#[inline]
pub fn is_gtpv1_u_port(port: u16) -> bool {
    port == GTPV1_U_PORT
}

/// GTPv1 Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtpv1MessageType {
    // Path Management Messages
    EchoRequest = 1,
    EchoResponse = 2,
    VersionNotSupported = 3,

    // Tunnel Management Messages (GTP-C)
    CreatePdpContextRequest = 16,
    CreatePdpContextResponse = 17,
    UpdatePdpContextRequest = 18,
    UpdatePdpContextResponse = 19,
    DeletePdpContextRequest = 20,
    DeletePdpContextResponse = 21,

    // Mobility Management Messages
    SgsnContextRequest = 50,
    SgsnContextResponse = 51,
    SgsnContextAcknowledge = 52,

    // Location Management Messages
    SendRoutingInfoRequest = 32,
    SendRoutingInfoResponse = 33,

    // MBMS Messages
    MbmsNotificationRequest = 96,
    MbmsNotificationResponse = 97,
    MbmsNotificationRejectRequest = 98,
    MbmsNotificationRejectResponse = 99,

    // GTP-U specific
    ErrorIndication = 26,
    SupportedExtensionHeadersNotification = 31,
    EndMarker = 254,
    GPdu = 255,

    // Unknown
    Unknown = 0,
}

impl From<u8> for Gtpv1MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Gtpv1MessageType::EchoRequest,
            2 => Gtpv1MessageType::EchoResponse,
            3 => Gtpv1MessageType::VersionNotSupported,
            16 => Gtpv1MessageType::CreatePdpContextRequest,
            17 => Gtpv1MessageType::CreatePdpContextResponse,
            18 => Gtpv1MessageType::UpdatePdpContextRequest,
            19 => Gtpv1MessageType::UpdatePdpContextResponse,
            20 => Gtpv1MessageType::DeletePdpContextRequest,
            21 => Gtpv1MessageType::DeletePdpContextResponse,
            26 => Gtpv1MessageType::ErrorIndication,
            31 => Gtpv1MessageType::SupportedExtensionHeadersNotification,
            32 => Gtpv1MessageType::SendRoutingInfoRequest,
            33 => Gtpv1MessageType::SendRoutingInfoResponse,
            50 => Gtpv1MessageType::SgsnContextRequest,
            51 => Gtpv1MessageType::SgsnContextResponse,
            52 => Gtpv1MessageType::SgsnContextAcknowledge,
            96 => Gtpv1MessageType::MbmsNotificationRequest,
            97 => Gtpv1MessageType::MbmsNotificationResponse,
            98 => Gtpv1MessageType::MbmsNotificationRejectRequest,
            99 => Gtpv1MessageType::MbmsNotificationRejectResponse,
            254 => Gtpv1MessageType::EndMarker,
            255 => Gtpv1MessageType::GPdu,
            _ => Gtpv1MessageType::Unknown,
        }
    }
}

impl fmt::Display for Gtpv1MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Gtpv1MessageType::EchoRequest => write!(f, "Echo Request"),
            Gtpv1MessageType::EchoResponse => write!(f, "Echo Response"),
            Gtpv1MessageType::VersionNotSupported => write!(f, "Version Not Supported"),
            Gtpv1MessageType::CreatePdpContextRequest => write!(f, "Create PDP Context Request"),
            Gtpv1MessageType::CreatePdpContextResponse => write!(f, "Create PDP Context Response"),
            Gtpv1MessageType::UpdatePdpContextRequest => write!(f, "Update PDP Context Request"),
            Gtpv1MessageType::UpdatePdpContextResponse => write!(f, "Update PDP Context Response"),
            Gtpv1MessageType::DeletePdpContextRequest => write!(f, "Delete PDP Context Request"),
            Gtpv1MessageType::DeletePdpContextResponse => write!(f, "Delete PDP Context Response"),
            Gtpv1MessageType::ErrorIndication => write!(f, "Error Indication"),
            Gtpv1MessageType::SupportedExtensionHeadersNotification => {
                write!(f, "Supported Extension Headers Notification")
            }
            Gtpv1MessageType::SendRoutingInfoRequest => write!(f, "Send Routing Info Request"),
            Gtpv1MessageType::SendRoutingInfoResponse => write!(f, "Send Routing Info Response"),
            Gtpv1MessageType::SgsnContextRequest => write!(f, "SGSN Context Request"),
            Gtpv1MessageType::SgsnContextResponse => write!(f, "SGSN Context Response"),
            Gtpv1MessageType::SgsnContextAcknowledge => write!(f, "SGSN Context Acknowledge"),
            Gtpv1MessageType::MbmsNotificationRequest => write!(f, "MBMS Notification Request"),
            Gtpv1MessageType::MbmsNotificationResponse => write!(f, "MBMS Notification Response"),
            Gtpv1MessageType::MbmsNotificationRejectRequest => {
                write!(f, "MBMS Notification Reject Request")
            }
            Gtpv1MessageType::MbmsNotificationRejectResponse => {
                write!(f, "MBMS Notification Reject Response")
            }
            Gtpv1MessageType::EndMarker => write!(f, "End Marker"),
            Gtpv1MessageType::GPdu => write!(f, "G-PDU"),
            Gtpv1MessageType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// GTPv1 Extension Header Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtpv1ExtensionType {
    /// No more extension headers
    NoMoreExtensions = 0x00,
    /// MBMS support indication
    MbmsSupportIndication = 0x01,
    /// MS Info Change Reporting support indication
    MsInfoChangeReporting = 0x02,
    /// Long PDCP PDU Number
    LongPdcpPduNumber = 0x03,
    /// Service Class Indicator
    ServiceClassIndicator = 0x20,
    /// UDP Port
    UdpPort = 0x40,
    /// RAN Container
    RanContainer = 0x81,
    /// Long PDCP PDU Number (extended)
    LongPdcpPduNumberExt = 0x82,
    /// Xw RAN Container
    XwRanContainer = 0x83,
    /// NR RAN Container
    NrRanContainer = 0x84,
    /// PDU Session Container
    PduSessionContainer = 0x85,
    /// PDCP PDU Number
    PdcpPduNumber = 0xC0,
    /// Unknown extension type
    Unknown = 0xFF,
}

impl From<u8> for Gtpv1ExtensionType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Gtpv1ExtensionType::NoMoreExtensions,
            0x01 => Gtpv1ExtensionType::MbmsSupportIndication,
            0x02 => Gtpv1ExtensionType::MsInfoChangeReporting,
            0x03 => Gtpv1ExtensionType::LongPdcpPduNumber,
            0x20 => Gtpv1ExtensionType::ServiceClassIndicator,
            0x40 => Gtpv1ExtensionType::UdpPort,
            0x81 => Gtpv1ExtensionType::RanContainer,
            0x82 => Gtpv1ExtensionType::LongPdcpPduNumberExt,
            0x83 => Gtpv1ExtensionType::XwRanContainer,
            0x84 => Gtpv1ExtensionType::NrRanContainer,
            0x85 => Gtpv1ExtensionType::PduSessionContainer,
            0xC0 => Gtpv1ExtensionType::PdcpPduNumber,
            _ => Gtpv1ExtensionType::Unknown,
        }
    }
}

/// GTPv1 Header structure (fixed 8 bytes)
///
/// This is the mandatory part of the GTPv1 header.
/// Optional fields (sequence number, N-PDU number, extension header type)
/// are present when E, S, or PN flags are set.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct Gtpv1Header {
    flags: u8,
    message_type: u8,
    length: U16<BigEndian>,
    teid: U32<BigEndian>,
}

impl Gtpv1Header {
    /// Version field mask (bits 5-7)
    pub const VERSION_MASK: u8 = 0xE0;
    pub const VERSION_SHIFT: u8 = 5;

    /// Protocol Type (bit 4): 1 = GTP, 0 = GTP'
    pub const FLAG_PT: u8 = 0x10;

    /// Reserved bit (bit 3) - must be 0 in GTPv1
    pub const FLAG_RESERVED: u8 = 0x08;

    /// Extension Header flag (bit 2)
    pub const FLAG_E: u8 = 0x04;

    /// Sequence Number flag (bit 1)
    pub const FLAG_S: u8 = 0x02;

    /// N-PDU Number flag (bit 0)
    pub const FLAG_PN: u8 = 0x01;

    /// GTPv1 version number
    pub const VERSION_1: u8 = 1;

    /// Minimum header length (no optional fields)
    pub const MIN_HEADER_LEN: usize = 8;

    /// Header length with optional fields
    pub const OPTIONAL_HEADER_LEN: usize = 12;

    #[allow(unused)]
    const NAME: &'static str = "Gtpv1Header";

    /// Returns the flags byte
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the GTP version (should be 1)
    #[inline]
    pub fn version(&self) -> u8 {
        (self.flags & Self::VERSION_MASK) >> Self::VERSION_SHIFT
    }

    /// Returns true if this is GTP (PT=1), false if GTP' (PT=0)
    #[inline]
    pub fn is_gtp(&self) -> bool {
        self.flags & Self::FLAG_PT != 0
    }

    /// Returns true if this is GTP' (PT=0)
    #[inline]
    pub fn is_gtp_prime(&self) -> bool {
        !self.is_gtp()
    }

    /// Returns true if Extension Header flag is set
    #[inline]
    pub fn has_extension(&self) -> bool {
        self.flags & Self::FLAG_E != 0
    }

    /// Returns true if Sequence Number flag is set
    #[inline]
    pub fn has_sequence(&self) -> bool {
        self.flags & Self::FLAG_S != 0
    }

    /// Returns true if N-PDU Number flag is set
    #[inline]
    pub fn has_npdu(&self) -> bool {
        self.flags & Self::FLAG_PN != 0
    }

    /// Returns true if any optional field is present (E, S, or PN set)
    #[inline]
    pub fn has_optional_fields(&self) -> bool {
        self.flags & (Self::FLAG_E | Self::FLAG_S | Self::FLAG_PN) != 0
    }

    /// Returns the message type
    #[inline]
    pub fn message_type(&self) -> u8 {
        self.message_type
    }

    /// Returns the message type as enum
    #[inline]
    pub fn message_type_enum(&self) -> Gtpv1MessageType {
        self.message_type.into()
    }

    /// Returns true if this is a G-PDU (user plane data)
    #[inline]
    pub fn is_gpdu(&self) -> bool {
        self.message_type == 0xFF
    }

    /// Returns true if this is an Echo Request
    #[inline]
    pub fn is_echo_request(&self) -> bool {
        self.message_type == 1
    }

    /// Returns true if this is an Echo Response
    #[inline]
    pub fn is_echo_response(&self) -> bool {
        self.message_type == 2
    }

    /// Returns true if this is a control plane message
    #[inline]
    pub fn is_control_plane(&self) -> bool {
        !self.is_gpdu()
    }

    /// Returns true if this is a user plane message (G-PDU)
    #[inline]
    pub fn is_user_plane(&self) -> bool {
        self.is_gpdu()
    }

    /// Returns the length field (payload length, not including mandatory header)
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.get()
    }

    /// Returns the Tunnel Endpoint Identifier (TEID)
    #[inline]
    pub fn teid(&self) -> u32 {
        self.teid.get()
    }

    /// Calculate the actual header length based on flags
    #[inline]
    pub fn header_length(&self) -> usize {
        if self.has_optional_fields() {
            Self::OPTIONAL_HEADER_LEN
        } else {
            Self::MIN_HEADER_LEN
        }
    }

    /// Validates the GTPv1 header
    #[inline]
    fn is_valid(&self) -> bool {
        // Version must be 1
        if self.version() != Self::VERSION_1 {
            return false;
        }

        // Reserved bit should be 0
        if self.flags & Self::FLAG_RESERVED != 0 {
            return false;
        }

        true
    }

    /// Returns a string representation of active flags
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();

        if self.is_gtp() {
            flags.push("PT");
        }
        if self.has_extension() {
            flags.push("E");
        }
        if self.has_sequence() {
            flags.push("S");
        }
        if self.has_npdu() {
            flags.push("PN");
        }

        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(",")
        }
    }
}

/// GTPv1 Header with optional fields parsed
#[derive(Debug, Clone)]
pub struct Gtpv1HeaderOpt<'a> {
    pub header: &'a Gtpv1Header,
    pub raw_options: &'a [u8],
}

impl<'a> Gtpv1HeaderOpt<'a> {
    /// Get the sequence number if present
    pub fn sequence_number(&self) -> Option<u16> {
        if !self.header.has_optional_fields() {
            return None;
        }

        if self.raw_options.len() < 2 {
            return None;
        }

        Some(u16::from_be_bytes([
            self.raw_options[0],
            self.raw_options[1],
        ]))
    }

    /// Get the N-PDU number if present
    pub fn npdu_number(&self) -> Option<u8> {
        if !self.header.has_optional_fields() {
            return None;
        }

        if self.raw_options.len() < 3 {
            return None;
        }

        Some(self.raw_options[2])
    }

    /// Get the next extension header type if present
    pub fn next_extension_type(&self) -> Option<u8> {
        if !self.header.has_optional_fields() {
            return None;
        }

        if self.raw_options.len() < 4 {
            return None;
        }

        Some(self.raw_options[3])
    }

    /// Get the next extension header type as enum
    pub fn next_extension_type_enum(&self) -> Option<Gtpv1ExtensionType> {
        self.next_extension_type().map(|t| t.into())
    }

    /// Returns true if there are extension headers to parse
    pub fn has_extension_headers(&self) -> bool {
        if !self.header.has_extension() {
            return false;
        }

        self.next_extension_type().map(|t| t != 0).unwrap_or(false)
    }

    /// Returns an iterator over extension headers
    pub fn extension_headers(&self) -> Gtpv1ExtensionIter<'a> {
        let ext_data = if self.header.has_optional_fields() && self.raw_options.len() >= 4 {
            // Extension headers start after the 4-byte optional fields
            // But the actual extension data comes from the payload portion
            // The next_extension_type tells us if there are extensions
            if self.has_extension_headers() {
                // The raw_options only contains the 4 optional bytes
                // Extensions would be in the payload, which we don't have direct access to here
                // This is a limitation - extensions are actually part of the "length" field content
                &[] as &[u8]
            } else {
                &[] as &[u8]
            }
        } else {
            &[] as &[u8]
        };

        Gtpv1ExtensionIter {
            data: ext_data,
            next_type: self.next_extension_type().unwrap_or(0),
        }
    }
}

impl std::ops::Deref for Gtpv1HeaderOpt<'_> {
    type Target = Gtpv1Header;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

/// Represents a single GTPv1 extension header
#[derive(Debug, Clone)]
pub struct Gtpv1Extension<'a> {
    /// Extension header type
    pub extension_type: Gtpv1ExtensionType,
    /// Extension header content (excluding length and next type bytes)
    pub content: &'a [u8],
    /// Next extension header type
    pub next_type: u8,
}

impl<'a> Gtpv1Extension<'a> {
    /// Returns the total length of this extension header in bytes
    pub fn total_length(&self) -> usize {
        // Length field is in units of 4 bytes
        // Format: [length][content...][next_type]
        // where total = length * 4
        self.content.len() + 2 // +1 for length byte, +1 for next_type byte
    }
}

/// Iterator over GTPv1 extension headers
pub struct Gtpv1ExtensionIter<'a> {
    data: &'a [u8],
    next_type: u8,
}

impl<'a> Iterator for Gtpv1ExtensionIter<'a> {
    type Item = Gtpv1Extension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // No more extensions if next_type is 0
        if self.next_type == 0 || self.data.is_empty() {
            return None;
        }

        // Extension header format:
        // [length (1 byte)][content (length*4 - 2 bytes)][next_type (1 byte)]
        // where length is in units of 4 bytes

        if self.data.is_empty() {
            return None;
        }

        let length_units = self.data[0] as usize;
        if length_units == 0 {
            return None;
        }

        let total_len = length_units * 4;
        if self.data.len() < total_len {
            return None;
        }

        let extension_type: Gtpv1ExtensionType = self.next_type.into();
        let content = &self.data[1..total_len - 1];
        let next_type = self.data[total_len - 1];

        let extension = Gtpv1Extension {
            extension_type,
            content,
            next_type,
        };

        self.data = &self.data[total_len..];
        self.next_type = next_type;

        Some(extension)
    }
}

impl PacketHeader for Gtpv1Header {
    const NAME: &'static str = "Gtpv1Header";
    /// Inner type - for G-PDU this would be the encapsulated protocol
    /// For simplicity, we return the message type as u8
    type InnerType = u8;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.message_type
    }

    /// Returns the total header length in bytes (including optional fields)
    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        self.header_length()
    }

    /// Validates the GTPv1 header
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for Gtpv1Header {
    type Output<'a> = Gtpv1HeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, raw_options: &'a [u8]) -> Self::Output<'a> {
        Gtpv1HeaderOpt {
            header,
            raw_options,
        }
    }
}

impl fmt::Display for Gtpv1Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GTPv1 {} msg={} len={} teid=0x{:08x} flags=[{}]",
            if self.is_gtp() { "GTP" } else { "GTP'" },
            self.message_type_enum(),
            self.length(),
            self.teid(),
            self.flags_string()
        )
    }
}

impl fmt::Display for Gtpv1HeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GTPv1 {} msg={} len={} teid=0x{:08x}",
            if self.is_gtp() { "GTP" } else { "GTP'" },
            self.message_type_enum(),
            self.length(),
            self.teid()
        )?;

        if let Some(seq) = self.sequence_number() {
            write!(f, " seq={}", seq)?;
        }

        if let Some(npdu) = self.npdu_number() {
            write!(f, " npdu={}", npdu)?;
        }

        if let Some(next_ext) = self.next_extension_type() {
            if next_ext != 0 {
                write!(f, " next_ext=0x{:02x}", next_ext)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpv1_header_size() {
        assert_eq!(std::mem::size_of::<Gtpv1Header>(), 8);
        assert_eq!(Gtpv1Header::FIXED_LEN, 8);
    }

    #[test]
    fn test_gtpv1_basic_header() {
        // GTPv1-U G-PDU without optional fields
        let packet = vec![
            0x30, // Version 1, PT=1, E=0, S=0, PN=0
            0xFF, // Message type: G-PDU
            0x00, 0x04, // Length: 4 bytes
            0x00, 0x00, 0x00, 0x01, // TEID: 1
            // Payload
            0x45, 0x00, 0x00, 0x00,
        ];

        let (header, payload) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert_eq!(header.version(), 1);
        assert!(header.is_gtp());
        assert!(!header.is_gtp_prime());
        assert_eq!(header.message_type(), 0xFF);
        assert!(header.is_gpdu());
        assert!(header.is_user_plane());
        assert!(!header.is_control_plane());
        assert_eq!(header.length(), 4);
        assert_eq!(header.teid(), 1);
        assert!(!header.has_optional_fields());
        assert_eq!(header.header_length(), 8);
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_gtpv1_with_sequence() {
        // GTPv1-U with sequence number
        let packet = vec![
            0x32, // Version 1, PT=1, S=1
            0xFF, // Message type: G-PDU
            0x00, 0x08, // Length: 8 bytes
            0x00, 0x00, 0x00, 0x01, // TEID: 1
            0x00, 0x42, // Sequence number: 66
            0x00, // N-PDU number: 0
            0x00, // Next extension: None
            // Payload
            0x45, 0x00, 0x00, 0x00,
        ];

        let (header, payload) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(header.has_sequence());
        assert!(header.has_optional_fields());
        assert_eq!(header.header_length(), 12);
        assert_eq!(header.sequence_number(), Some(0x0042));
        assert_eq!(header.npdu_number(), Some(0));
        assert_eq!(header.next_extension_type(), Some(0));
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_gtpv1_with_extension() {
        // GTPv1-U with extension header flag
        let packet = vec![
            0x34, // Version 1, PT=1, E=1
            0xFF, // Message type: G-PDU
            0x00, 0x08, // Length: 8 bytes
            0x00, 0x00, 0x00, 0x01, // TEID: 1
            0x00, 0x00, // Sequence number: 0
            0x00, // N-PDU number: 0
            0x85, // Next extension: PDU Session Container
            // Payload would include extension headers
            0x45, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(header.has_extension());
        assert!(header.has_optional_fields());
        assert_eq!(header.next_extension_type(), Some(0x85));
        assert!(header.has_extension_headers());
    }

    #[test]
    fn test_gtpv1_with_npdu() {
        // GTPv1-U with N-PDU number
        let packet = vec![
            0x31, // Version 1, PT=1, PN=1
            0xFF, // Message type: G-PDU
            0x00, 0x08, // Length: 8 bytes
            0x00, 0x00, 0x00, 0x01, // TEID: 1
            0x00, 0x00, // Sequence number: 0
            0x42, // N-PDU number: 66
            0x00, // Next extension: None
            // Payload
            0x45, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(header.has_npdu());
        assert!(header.has_optional_fields());
        assert_eq!(header.npdu_number(), Some(0x42));
    }

    #[test]
    fn test_gtpv1_echo_request() {
        // GTPv1 Echo Request
        let packet = vec![
            0x32, // Version 1, PT=1, S=1
            0x01, // Message type: Echo Request
            0x00, 0x04, // Length: 4 bytes
            0x00, 0x00, 0x00, 0x00, // TEID: 0 (not used for echo)
            0x00, 0x01, // Sequence number: 1
            0x00, // N-PDU number
            0x00, // Next extension
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(header.is_echo_request());
        assert!(!header.is_gpdu());
        assert!(header.is_control_plane());
        assert_eq!(header.message_type_enum(), Gtpv1MessageType::EchoRequest);
    }

    #[test]
    fn test_gtpv1_echo_response() {
        // GTPv1 Echo Response
        let packet = vec![
            0x32, // Version 1, PT=1, S=1
            0x02, // Message type: Echo Response
            0x00, 0x06, // Length: 6 bytes (includes recovery IE)
            0x00, 0x00, 0x00, 0x00, // TEID: 0
            0x00, 0x01, // Sequence number: 1
            0x00, // N-PDU number
            0x00, // Next extension
            0x0E, 0x01, // Recovery IE
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(header.is_echo_response());
        assert_eq!(header.message_type_enum(), Gtpv1MessageType::EchoResponse);
    }

    #[test]
    fn test_gtpv1_control_plane_message() {
        // Create PDP Context Request
        let packet = vec![
            0x32, // Version 1, PT=1, S=1
            0x10, // Message type: Create PDP Context Request (16)
            0x00, 0x04, // Length
            0x00, 0x00, 0x00, 0x00, // TEID: 0
            0x00, 0x01, // Sequence number
            0x00, 0x00, // N-PDU, Next ext
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(header.is_control_plane());
        assert!(!header.is_user_plane());
        assert_eq!(
            header.message_type_enum(),
            Gtpv1MessageType::CreatePdpContextRequest
        );
    }

    #[test]
    fn test_gtpv1_gtp_prime() {
        // GTP' (charging) - PT=0
        let packet = vec![
            0x20, // Version 1, PT=0
            0x01, // Message type: Echo Request
            0x00, 0x04, // Length
            0x00, 0x00, 0x00, 0x00, // TEID
            // Payload
            0x00, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(!header.is_gtp());
        assert!(header.is_gtp_prime());
    }

    #[test]
    fn test_gtpv1_invalid_version() {
        // Invalid version (0)
        let packet = vec![
            0x00, // Version 0
            0xFF, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = Gtpv1Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_gtpv1_invalid_version_2() {
        // GTPv2 header (version 2) should fail
        let packet = vec![
            0x48, // Version 2, T=1
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = Gtpv1Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_gtpv1_parsing_too_small() {
        let packet = vec![0x30, 0xFF, 0x00, 0x04]; // Only 4 bytes
        let result = Gtpv1Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_gtpv1_flags_string() {
        let packet = vec![
            0x37, // Version 1, PT=1, E=1, S=1, PN=1
            0xFF, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        let flags = header.flags_string();
        assert!(flags.contains("PT"));
        assert!(flags.contains("E"));
        assert!(flags.contains("S"));
        assert!(flags.contains("PN"));
    }

    #[test]
    fn test_gtpv1_display() {
        let packet = vec![
            0x30, // Version 1, PT=1
            0xFF, // G-PDU
            0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x45, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        let display = format!("{}", *header);
        assert!(display.contains("GTPv1"));
        assert!(display.contains("G-PDU"));
    }

    #[test]
    fn test_gtpv1_message_types() {
        assert_eq!(Gtpv1MessageType::from(1), Gtpv1MessageType::EchoRequest);
        assert_eq!(Gtpv1MessageType::from(2), Gtpv1MessageType::EchoResponse);
        assert_eq!(Gtpv1MessageType::from(255), Gtpv1MessageType::GPdu);
        assert_eq!(Gtpv1MessageType::from(254), Gtpv1MessageType::EndMarker);
        assert_eq!(Gtpv1MessageType::from(200), Gtpv1MessageType::Unknown);
    }

    #[test]
    fn test_gtpv1_extension_types() {
        assert_eq!(
            Gtpv1ExtensionType::from(0x00),
            Gtpv1ExtensionType::NoMoreExtensions
        );
        assert_eq!(
            Gtpv1ExtensionType::from(0x85),
            Gtpv1ExtensionType::PduSessionContainer
        );
        assert_eq!(
            Gtpv1ExtensionType::from(0xC0),
            Gtpv1ExtensionType::PdcpPduNumber
        );
        assert_eq!(Gtpv1ExtensionType::from(0xAA), Gtpv1ExtensionType::Unknown);
    }

    #[test]
    fn test_gtpv1_ports() {
        assert!(is_gtpv1_c_port(2123));
        assert!(is_gtpv1_u_port(2152));
        assert!(!is_gtpv1_c_port(2152));
        assert!(!is_gtpv1_u_port(2123));
    }

    #[test]
    fn test_gtpv1_large_teid() {
        let packet = vec![
            0x30, 0xFF, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, // TEID: max value
            0x00, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert_eq!(header.teid(), 0xFFFFFFFF);
    }

    #[test]
    fn test_gtpv1_end_marker() {
        let packet = vec![
            0x30, // Version 1, PT=1
            0xFE, // Message type: End Marker
            0x00, 0x00, // Length: 0
            0x00, 0x00, 0x00, 0x01, // TEID
        ];

        let (header, payload) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert_eq!(header.message_type(), 254);
        assert_eq!(header.message_type_enum(), Gtpv1MessageType::EndMarker);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_gtpv1_error_indication() {
        let packet = vec![
            0x32, // Version 1, PT=1, S=1
            0x1A, // Message type: Error Indication (26)
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            // IEs would follow
            0x00, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert_eq!(
            header.message_type_enum(),
            Gtpv1MessageType::ErrorIndication
        );
    }

    #[test]
    fn test_gtpv1_header_opt_display() {
        let packet = vec![
            0x32, // Version 1, PT=1, S=1
            0xFF, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x42, // seq=66
            0x05, // npdu=5
            0x85, // next_ext=0x85
            0x00, 0x00, 0x00, 0x00,
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("seq=66"));
        assert!(display.contains("npdu=5"));
        assert!(display.contains("next_ext=0x85"));
    }

    #[test]
    fn test_gtpv1_all_flags_set() {
        let packet = vec![
            0x37, // Version 1, PT=1, E=1, S=1, PN=1
            0xFF, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, // seq
            0x02, // npdu
            0x85, // next_ext
        ];

        let (header, _) = Gtpv1Header::from_bytes(&packet).unwrap();
        assert!(header.is_gtp());
        assert!(header.has_extension());
        assert!(header.has_sequence());
        assert!(header.has_npdu());
        assert!(header.has_optional_fields());
        assert_eq!(header.header_length(), 12);
    }
}
