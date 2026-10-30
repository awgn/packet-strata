//! PPPoE (Point-to-Point Protocol over Ethernet) protocol parser
//!
//! This module implements parsing for PPPoE headers as defined in RFC 2516.
//! PPPoE encapsulates PPP frames inside Ethernet frames using two distinct stages
//! and Ethernet protocol numbers:
//! - **Discovery Stage** (`EtherProto::PPP_DISC` = `0x8863`): Stateless client-server
//!   discovery to establish a 16-bit `SESSION_ID` (PADI, PADO, PADR, PADS, PADT).
//! - **Session Stage** (`EtherProto::PPP_SES` = `0x8864`): Point-to-point PPP data session
//!   (`CODE = 0x00`) carrying PPP frames without HDLC Address/Control bytes.
//!
//! # PPPoE Header Format (RFC 2516)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  VER  | TYPE  |      CODE     |          SESSION_ID           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            LENGTH             |           payload             ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Key characteristics
//!
//! - Fixed header length: 6 bytes
//! - `VER` (4 bits): MUST be `0x1`
//! - `TYPE` (4 bits): MUST be `0x1`
//! - `CODE` (8 bits): `0x00` for Session Data, non-zero for Discovery packets
//! - `SESSION_ID` (16 bits): Identifies the PPPoE session (`0x0000` during PADI/PADO/PADR)
//! - `LENGTH` (16 bits): Length of the PPPoE payload in bytes (excluding Ethernet & PPPoE headers)
//!
//! # Examples
//!
//! ```
//! use packet_strata::packet::tunnel::pppoe::{PppoeHeader, PPPOE_CODE_SESSION};
//! use packet_strata::packet::HeaderParser;
//!
//! // PPPoE Session Data packet with session_id = 0x1234, length = 6
//! let packet = [
//!     0x11,       // VER=1, TYPE=1
//!     0x00,       // CODE=0x00 (Session Data)
//!     0x12, 0x34, // SESSION_ID = 0x1234
//!     0x00, 0x06, // LENGTH = 6
//!     0x00, 0x21, // PPP Protocol: IPv4
//!     0x45, 0x00, 0x00, 0x14,
//! ];
//!
//! let (header, payload) = PppoeHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 1);
//! assert_eq!(header.type_id(), 1);
//! assert_eq!(header.code(), PPPOE_CODE_SESSION);
//! assert!(header.is_session_data());
//! assert_eq!(header.session_id(), 0x1234);
//! assert_eq!(header.length(), 6);
//! assert_eq!(payload.len(), 6);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::protocol::EtherProto;
use crate::packet::{HeaderParser, PacketHeader};

/// PPPoE Session Data code (`0x00`)
pub const PPPOE_CODE_SESSION: u8 = 0x00;
/// PPPoE Active Discovery Initiation (`0x09`)
pub const PPPOE_CODE_PADI: u8 = 0x09;
/// PPPoE Active Discovery Offer (`0x07`)
pub const PPPOE_CODE_PADO: u8 = 0x07;
/// PPPoE Active Discovery Request (`0x19`)
pub const PPPOE_CODE_PADR: u8 = 0x19;
/// PPPoE Active Discovery Session-confirmation (`0x65`)
pub const PPPOE_CODE_PADS: u8 = 0x65;
/// PPPoE Active Discovery Terminate (`0xA7`)
pub const PPPOE_CODE_PADT: u8 = 0xA7;

/// PPPoE fixed 6-byte header as defined in RFC 2516
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, KnownLayout, Immutable, PartialEq, Eq,
)]
pub struct PppoeHeader {
    ver_type: u8,
    code: u8,
    session_id: U16<BigEndian>,
    length: U16<BigEndian>,
}

impl PppoeHeader {
    /// Expected version (1) and type (1) byte (`0x11`)
    pub const VER_TYPE_V1: u8 = 0x11;

    /// Returns the 4-bit version field (MUST be 1 per RFC 2516)
    #[inline]
    pub fn version(&self) -> u8 {
        (self.ver_type >> 4) & 0x0F
    }

    /// Returns the 4-bit type field (MUST be 1 per RFC 2516)
    #[inline]
    pub fn type_id(&self) -> u8 {
        self.ver_type & 0x0F
    }

    /// Returns the 8-bit PPPoE code field
    #[inline]
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Returns the human-readable name of the PPPoE code
    #[inline]
    pub fn code_name(&self) -> &'static str {
        match self.code {
            PPPOE_CODE_SESSION => "Session",
            PPPOE_CODE_PADI => "PADI",
            PPPOE_CODE_PADO => "PADO",
            PPPOE_CODE_PADR => "PADR",
            PPPOE_CODE_PADS => "PADS",
            PPPOE_CODE_PADT => "PADT",
            _ => "Unknown",
        }
    }

    /// Returns `true` if this is a PPPoE Session Data packet (`code == 0x00`)
    #[inline]
    pub fn is_session_data(&self) -> bool {
        self.code == PPPOE_CODE_SESSION
    }

    /// Returns `true` if this is a PPPoE Discovery packet (`code != 0x00`)
    #[inline]
    pub fn is_discovery(&self) -> bool {
        self.code != PPPOE_CODE_SESSION
    }

    /// Returns the 16-bit PPPoE Session ID
    #[inline]
    pub fn session_id(&self) -> u16 {
        self.session_id.get()
    }

    /// Returns the 16-bit PPPoE payload length
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.get()
    }
}

impl PacketHeader for PppoeHeader {
    const NAME: &'static str = "PppoeHeader";
    type InnerType = EtherProto;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        EtherProto::PPP
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::FIXED_LEN
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.ver_type == Self::VER_TYPE_V1
    }
}

impl HeaderParser for PppoeHeader {
    type Output<'a> = &'a PppoeHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _raw_options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for PppoeHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PPPoE {} session=0x{:04x} len={}",
            self.code_name(),
            self.session_id(),
            self.length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pppoe_header_size() {
        assert_eq!(std::mem::size_of::<PppoeHeader>(), 6);
        assert_eq!(PppoeHeader::FIXED_LEN, 6);
    }

    #[test]
    fn test_pppoe_session_header() {
        let bytes = [0x11, 0x00, 0x00, 0x2A, 0x00, 0x1E, 0x00, 0x21];
        let (hdr, rest) = PppoeHeader::from_bytes(&bytes).unwrap();
        assert_eq!(hdr.version(), 1);
        assert_eq!(hdr.type_id(), 1);
        assert_eq!(hdr.code(), PPPOE_CODE_SESSION);
        assert_eq!(hdr.code_name(), "Session");
        assert!(hdr.is_session_data());
        assert!(!hdr.is_discovery());
        assert_eq!(hdr.session_id(), 42);
        assert_eq!(hdr.length(), 30);
        assert_eq!(hdr.inner_type(), EtherProto::PPP);
        assert_eq!(rest, &[0x00, 0x21]);
        assert_eq!(format!("{}", hdr), "PPPoE Session session=0x002a len=30");
    }

    #[test]
    fn test_pppoe_discovery_padi() {
        let bytes = [0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00];
        let (hdr, rest) = PppoeHeader::from_bytes(&bytes).unwrap();
        assert_eq!(hdr.code(), PPPOE_CODE_PADI);
        assert_eq!(hdr.code_name(), "PADI");
        assert!(hdr.is_discovery());
        assert!(!hdr.is_session_data());
        assert_eq!(hdr.session_id(), 0);
        assert_eq!(hdr.length(), 4);
        assert_eq!(rest.len(), 4);
        assert_eq!(format!("{}", hdr), "PPPoE PADI session=0x0000 len=4");
    }

    #[test]
    fn test_pppoe_invalid_version() {
        let bad_ver = [0x21, 0x00, 0x00, 0x01, 0x00, 0x00];
        assert!(PppoeHeader::from_bytes(&bad_ver).is_err());

        let too_short = [0x11, 0x00, 0x00];
        assert!(PppoeHeader::from_bytes(&too_short).is_err());
    }
}
