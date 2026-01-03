//! L2TP (Layer 2 Tunneling Protocol) parser
//!
//! This module implements parsing for L2TP as defined in:
//! - RFC 2661: Layer Two Tunneling Protocol "L2TP" (L2TPv2)
//! - RFC 3931: Layer Two Tunneling Protocol - Version 3 (L2TPv3)
//!
//! L2TP is used to tunnel PPP sessions over an IP network. L2TPv2 is widely
//! deployed for VPN access, while L2TPv3 extends the protocol for tunneling
//! any Layer 2 protocol.
//!
//! # L2TPv2 Header Format (RFC 2661)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Tunnel ID           |           Session ID          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |             Ns (opt)          |             Nr (opt)          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Offset Size (opt)        |    Offset pad... (opt)        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # L2TPv3 Header Format (RFC 3931)
//!
//! L2TPv3 over UDP:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Control Connection ID (opt)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |             Ns (opt)          |             Nr (opt)          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! L2TPv3 Data Session Header:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Session ID (32 bits)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Cookie (optional, 0, 32, or 64 bits)            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Ports
//!
//! - L2TP: UDP port 1701 (both L2TPv2 and L2TPv3 control)
//! - L2TPv3 can also use IP protocol 115 for data sessions
//!
//! # Examples
//!
//! ## Basic L2TPv2 data parsing
//!
//! ```
//! use packet_strata::packet::tunnel::l2tp::L2tpv2Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // L2TPv2 data packet (minimal header)
//! let packet = vec![
//!     0x00, 0x02,  // flags: T=0 (data), L=0, S=0, O=0, P=0, Ver=2
//!     0x00, 0x01,  // Tunnel ID: 1
//!     0x00, 0x02,  // Session ID: 2
//!     // PPP payload follows...
//!     0xFF, 0x03, 0x00, 0x21,
//! ];
//!
//! let (header, payload) = L2tpv2Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 2);
//! assert!(!header.is_control());
//! assert_eq!(header.tunnel_id(), 1);
//! assert_eq!(header.session_id(), 2);
//! ```
//!
//! ## L2TPv2 control message parsing
//!
//! ```
//! use packet_strata::packet::tunnel::l2tp::L2tpv2Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // L2TPv2 control message with length and sequence
//! let packet = vec![
//!     0xC8, 0x02,  // flags: T=1, L=1, S=1, Ver=2
//!     0x00, 0x14,  // Length: 20 bytes
//!     0x00, 0x01,  // Tunnel ID: 1
//!     0x00, 0x00,  // Session ID: 0 (control)
//!     0x00, 0x01,  // Ns: 1
//!     0x00, 0x00,  // Nr: 0
//!     // AVPs follow...
//!     0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//! ];
//!
//! let (header, payload) = L2tpv2Header::from_bytes(&packet).unwrap();
//! assert!(header.is_control());
//! assert!(header.has_length());
//! assert!(header.has_sequence());
//! assert_eq!(header.ns(), Some(1));
//! assert_eq!(header.nr(), Some(0));
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::{HeaderParser, PacketHeader, PacketHeaderError};

/// L2TP standard port (UDP)
pub const L2TP_PORT: u16 = 1701;

/// L2TPv3 IP protocol number
pub const L2TPV3_IP_PROTO: u8 = 115;

/// Check if port is L2TP
#[inline]
pub fn is_l2tp_port(port: u16) -> bool {
    port == L2TP_PORT
}

/// Check if IP protocol is L2TPv3
#[inline]
pub fn is_l2tpv3_proto(proto: u8) -> bool {
    proto == L2TPV3_IP_PROTO
}

/// L2TPv2 Message Types (from RFC 2661)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2tpv2MessageType {
    /// Start-Control-Connection-Request
    Sccrq,
    /// Start-Control-Connection-Reply
    Sccrp,
    /// Start-Control-Connection-Connected
    Scccn,
    /// Stop-Control-Connection-Notification
    StopCcn,
    /// Hello (keep-alive)
    Hello,
    /// Outgoing-Call-Request
    Ocrq,
    /// Outgoing-Call-Reply
    Ocrp,
    /// Outgoing-Call-Connected
    Occn,
    /// Incoming-Call-Request
    Icrq,
    /// Incoming-Call-Reply
    Icrp,
    /// Incoming-Call-Connected
    Iccn,
    /// Call-Disconnect-Notify
    Cdn,
    /// WAN-Error-Notify
    Wen,
    /// Set-Link-Info
    Sli,
    /// Zero-Length Body (ZLB) ACK
    Zlb,
    /// Unknown message type
    Unknown(u16),
}

impl From<u16> for L2tpv2MessageType {
    fn from(value: u16) -> Self {
        match value {
            1 => L2tpv2MessageType::Sccrq,
            2 => L2tpv2MessageType::Sccrp,
            3 => L2tpv2MessageType::Scccn,
            4 => L2tpv2MessageType::StopCcn,
            6 => L2tpv2MessageType::Hello,
            7 => L2tpv2MessageType::Ocrq,
            8 => L2tpv2MessageType::Ocrp,
            9 => L2tpv2MessageType::Occn,
            10 => L2tpv2MessageType::Icrq,
            11 => L2tpv2MessageType::Icrp,
            12 => L2tpv2MessageType::Iccn,
            14 => L2tpv2MessageType::Cdn,
            15 => L2tpv2MessageType::Wen,
            16 => L2tpv2MessageType::Sli,
            0 => L2tpv2MessageType::Zlb,
            v => L2tpv2MessageType::Unknown(v),
        }
    }
}

impl fmt::Display for L2tpv2MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            L2tpv2MessageType::Sccrq => write!(f, "SCCRQ"),
            L2tpv2MessageType::Sccrp => write!(f, "SCCRP"),
            L2tpv2MessageType::Scccn => write!(f, "SCCCN"),
            L2tpv2MessageType::StopCcn => write!(f, "StopCCN"),
            L2tpv2MessageType::Hello => write!(f, "Hello"),
            L2tpv2MessageType::Ocrq => write!(f, "OCRQ"),
            L2tpv2MessageType::Ocrp => write!(f, "OCRP"),
            L2tpv2MessageType::Occn => write!(f, "OCCN"),
            L2tpv2MessageType::Icrq => write!(f, "ICRQ"),
            L2tpv2MessageType::Icrp => write!(f, "ICRP"),
            L2tpv2MessageType::Iccn => write!(f, "ICCN"),
            L2tpv2MessageType::Cdn => write!(f, "CDN"),
            L2tpv2MessageType::Wen => write!(f, "WEN"),
            L2tpv2MessageType::Sli => write!(f, "SLI"),
            L2tpv2MessageType::Zlb => write!(f, "ZLB"),
            L2tpv2MessageType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// L2TPv3 Message Types (from RFC 3931)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2tpv3MessageType {
    /// Start-Control-Connection-Request
    Sccrq,
    /// Start-Control-Connection-Reply
    Sccrp,
    /// Start-Control-Connection-Connected
    Scccn,
    /// Stop-Control-Connection-Notification
    StopCcn,
    /// Hello (keep-alive)
    Hello,
    /// Incoming-Call-Request
    Icrq,
    /// Incoming-Call-Reply
    Icrp,
    /// Incoming-Call-Connected
    Iccn,
    /// Outgoing-Call-Request
    Ocrq,
    /// Outgoing-Call-Reply
    Ocrp,
    /// Outgoing-Call-Connected
    Occn,
    /// Call-Disconnect-Notify
    Cdn,
    /// Set-Link-Info
    Sli,
    /// Explicit Acknowledgement
    Ack,
    /// Zero-Length Body
    Zlb,
    /// Unknown message type
    Unknown(u16),
}

impl From<u16> for L2tpv3MessageType {
    fn from(value: u16) -> Self {
        match value {
            1 => L2tpv3MessageType::Sccrq,
            2 => L2tpv3MessageType::Sccrp,
            3 => L2tpv3MessageType::Scccn,
            4 => L2tpv3MessageType::StopCcn,
            6 => L2tpv3MessageType::Hello,
            7 => L2tpv3MessageType::Ocrq,
            8 => L2tpv3MessageType::Ocrp,
            9 => L2tpv3MessageType::Occn,
            10 => L2tpv3MessageType::Icrq,
            11 => L2tpv3MessageType::Icrp,
            12 => L2tpv3MessageType::Iccn,
            14 => L2tpv3MessageType::Cdn,
            16 => L2tpv3MessageType::Sli,
            20 => L2tpv3MessageType::Ack,
            0 => L2tpv3MessageType::Zlb,
            v => L2tpv3MessageType::Unknown(v),
        }
    }
}

impl fmt::Display for L2tpv3MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            L2tpv3MessageType::Sccrq => write!(f, "SCCRQ"),
            L2tpv3MessageType::Sccrp => write!(f, "SCCRP"),
            L2tpv3MessageType::Scccn => write!(f, "SCCCN"),
            L2tpv3MessageType::StopCcn => write!(f, "StopCCN"),
            L2tpv3MessageType::Hello => write!(f, "Hello"),
            L2tpv3MessageType::Icrq => write!(f, "ICRQ"),
            L2tpv3MessageType::Icrp => write!(f, "ICRP"),
            L2tpv3MessageType::Iccn => write!(f, "ICCN"),
            L2tpv3MessageType::Ocrq => write!(f, "OCRQ"),
            L2tpv3MessageType::Ocrp => write!(f, "OCRP"),
            L2tpv3MessageType::Occn => write!(f, "OCCN"),
            L2tpv3MessageType::Cdn => write!(f, "CDN"),
            L2tpv3MessageType::Sli => write!(f, "SLI"),
            L2tpv3MessageType::Ack => write!(f, "ACK"),
            L2tpv3MessageType::Zlb => write!(f, "ZLB"),
            L2tpv3MessageType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// L2TP AVP (Attribute Value Pair) Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2tpAvpType {
    /// Message Type AVP
    MessageType,
    /// Result Code AVP
    ResultCode,
    /// Protocol Version AVP
    ProtocolVersion,
    /// Framing Capabilities AVP
    FramingCapabilities,
    /// Bearer Capabilities AVP
    BearerCapabilities,
    /// Tie Breaker AVP
    TieBreaker,
    /// Firmware Revision AVP
    FirmwareRevision,
    /// Host Name AVP
    HostName,
    /// Vendor Name AVP
    VendorName,
    /// Assigned Tunnel ID AVP
    AssignedTunnelId,
    /// Receive Window Size AVP
    ReceiveWindowSize,
    /// Challenge AVP
    Challenge,
    /// Cause Code AVP (Q.931)
    Q931CauseCode,
    /// Challenge Response AVP
    ChallengeResponse,
    /// Assigned Session ID AVP
    AssignedSessionId,
    /// Call Serial Number AVP
    CallSerialNumber,
    /// Minimum BPS AVP
    MinimumBps,
    /// Maximum BPS AVP
    MaximumBps,
    /// Bearer Type AVP
    BearerType,
    /// Framing Type AVP
    FramingType,
    /// Called Number AVP
    CalledNumber,
    /// Calling Number AVP
    CallingNumber,
    /// Sub-Address AVP
    SubAddress,
    /// Tx Connect Speed AVP
    TxConnectSpeed,
    /// Physical Channel ID AVP
    PhysicalChannelId,
    /// Initial Received LCP CONFREQ AVP
    InitialReceivedLcpConfreq,
    /// Last Sent LCP CONFREQ AVP
    LastSentLcpConfreq,
    /// Last Received LCP CONFREQ AVP
    LastReceivedLcpConfreq,
    /// Proxy Authen Type AVP
    ProxyAuthenType,
    /// Proxy Authen Name AVP
    ProxyAuthenName,
    /// Proxy Authen Challenge AVP
    ProxyAuthenChallenge,
    /// Proxy Authen ID AVP
    ProxyAuthenId,
    /// Proxy Authen Response AVP
    ProxyAuthenResponse,
    /// Call Errors AVP
    CallErrors,
    /// ACCM AVP
    Accm,
    /// Random Vector AVP
    RandomVector,
    /// Private Group ID AVP
    PrivateGroupId,
    /// Rx Connect Speed AVP
    RxConnectSpeed,
    /// Sequencing Required AVP
    SequencingRequired,
    /// Unknown AVP type
    Unknown(u16),
}

impl From<u16> for L2tpAvpType {
    fn from(value: u16) -> Self {
        match value {
            0 => L2tpAvpType::MessageType,
            1 => L2tpAvpType::ResultCode,
            2 => L2tpAvpType::ProtocolVersion,
            3 => L2tpAvpType::FramingCapabilities,
            4 => L2tpAvpType::BearerCapabilities,
            5 => L2tpAvpType::TieBreaker,
            6 => L2tpAvpType::FirmwareRevision,
            7 => L2tpAvpType::HostName,
            8 => L2tpAvpType::VendorName,
            9 => L2tpAvpType::AssignedTunnelId,
            10 => L2tpAvpType::ReceiveWindowSize,
            11 => L2tpAvpType::Challenge,
            12 => L2tpAvpType::Q931CauseCode,
            13 => L2tpAvpType::ChallengeResponse,
            14 => L2tpAvpType::AssignedSessionId,
            15 => L2tpAvpType::CallSerialNumber,
            16 => L2tpAvpType::MinimumBps,
            17 => L2tpAvpType::MaximumBps,
            18 => L2tpAvpType::BearerType,
            19 => L2tpAvpType::FramingType,
            21 => L2tpAvpType::CalledNumber,
            22 => L2tpAvpType::CallingNumber,
            23 => L2tpAvpType::SubAddress,
            24 => L2tpAvpType::TxConnectSpeed,
            25 => L2tpAvpType::PhysicalChannelId,
            26 => L2tpAvpType::InitialReceivedLcpConfreq,
            27 => L2tpAvpType::LastSentLcpConfreq,
            28 => L2tpAvpType::LastReceivedLcpConfreq,
            29 => L2tpAvpType::ProxyAuthenType,
            30 => L2tpAvpType::ProxyAuthenName,
            31 => L2tpAvpType::ProxyAuthenChallenge,
            32 => L2tpAvpType::ProxyAuthenId,
            33 => L2tpAvpType::ProxyAuthenResponse,
            34 => L2tpAvpType::CallErrors,
            35 => L2tpAvpType::Accm,
            36 => L2tpAvpType::RandomVector,
            37 => L2tpAvpType::PrivateGroupId,
            38 => L2tpAvpType::RxConnectSpeed,
            39 => L2tpAvpType::SequencingRequired,
            v => L2tpAvpType::Unknown(v),
        }
    }
}

impl fmt::Display for L2tpAvpType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            L2tpAvpType::MessageType => write!(f, "Message Type"),
            L2tpAvpType::ResultCode => write!(f, "Result Code"),
            L2tpAvpType::ProtocolVersion => write!(f, "Protocol Version"),
            L2tpAvpType::FramingCapabilities => write!(f, "Framing Capabilities"),
            L2tpAvpType::BearerCapabilities => write!(f, "Bearer Capabilities"),
            L2tpAvpType::TieBreaker => write!(f, "Tie Breaker"),
            L2tpAvpType::FirmwareRevision => write!(f, "Firmware Revision"),
            L2tpAvpType::HostName => write!(f, "Host Name"),
            L2tpAvpType::VendorName => write!(f, "Vendor Name"),
            L2tpAvpType::AssignedTunnelId => write!(f, "Assigned Tunnel ID"),
            L2tpAvpType::ReceiveWindowSize => write!(f, "Receive Window Size"),
            L2tpAvpType::Challenge => write!(f, "Challenge"),
            L2tpAvpType::Q931CauseCode => write!(f, "Q.931 Cause Code"),
            L2tpAvpType::ChallengeResponse => write!(f, "Challenge Response"),
            L2tpAvpType::AssignedSessionId => write!(f, "Assigned Session ID"),
            L2tpAvpType::CallSerialNumber => write!(f, "Call Serial Number"),
            L2tpAvpType::MinimumBps => write!(f, "Minimum BPS"),
            L2tpAvpType::MaximumBps => write!(f, "Maximum BPS"),
            L2tpAvpType::BearerType => write!(f, "Bearer Type"),
            L2tpAvpType::FramingType => write!(f, "Framing Type"),
            L2tpAvpType::CalledNumber => write!(f, "Called Number"),
            L2tpAvpType::CallingNumber => write!(f, "Calling Number"),
            L2tpAvpType::SubAddress => write!(f, "Sub-Address"),
            L2tpAvpType::TxConnectSpeed => write!(f, "Tx Connect Speed"),
            L2tpAvpType::PhysicalChannelId => write!(f, "Physical Channel ID"),
            L2tpAvpType::InitialReceivedLcpConfreq => write!(f, "Initial Received LCP CONFREQ"),
            L2tpAvpType::LastSentLcpConfreq => write!(f, "Last Sent LCP CONFREQ"),
            L2tpAvpType::LastReceivedLcpConfreq => write!(f, "Last Received LCP CONFREQ"),
            L2tpAvpType::ProxyAuthenType => write!(f, "Proxy Authen Type"),
            L2tpAvpType::ProxyAuthenName => write!(f, "Proxy Authen Name"),
            L2tpAvpType::ProxyAuthenChallenge => write!(f, "Proxy Authen Challenge"),
            L2tpAvpType::ProxyAuthenId => write!(f, "Proxy Authen ID"),
            L2tpAvpType::ProxyAuthenResponse => write!(f, "Proxy Authen Response"),
            L2tpAvpType::CallErrors => write!(f, "Call Errors"),
            L2tpAvpType::Accm => write!(f, "ACCM"),
            L2tpAvpType::RandomVector => write!(f, "Random Vector"),
            L2tpAvpType::PrivateGroupId => write!(f, "Private Group ID"),
            L2tpAvpType::RxConnectSpeed => write!(f, "Rx Connect Speed"),
            L2tpAvpType::SequencingRequired => write!(f, "Sequencing Required"),
            L2tpAvpType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// L2TPv2 Header (fixed 6 bytes: flags + tunnel ID + session ID)
///
/// The minimum L2TPv2 header contains:
/// - 2 bytes: Flags and Version
/// - 2 bytes: Tunnel ID
/// - 2 bytes: Session ID
///
/// Optional fields (Length, Ns, Nr, Offset) follow based on flags.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct L2tpv2Header {
    flags_version: U16<BigEndian>,
    tunnel_id: U16<BigEndian>,
    session_id: U16<BigEndian>,
}

impl L2tpv2Header {
    // L2TPv2 Flags (in the high byte of flags_version)
    /// Type bit: 1 = Control message, 0 = Data message
    pub const FLAG_TYPE: u16 = 0x8000;
    /// Length bit: Length field present
    pub const FLAG_LENGTH: u16 = 0x4000;
    /// Sequence bit: Ns and Nr fields present
    pub const FLAG_SEQUENCE: u16 = 0x0800;
    /// Offset bit: Offset Size field present
    pub const FLAG_OFFSET: u16 = 0x0200;
    /// Priority bit: Priority delivery required
    pub const FLAG_PRIORITY: u16 = 0x0100;

    /// Version mask (bits 0-3)
    pub const VERSION_MASK: u16 = 0x000F;

    /// L2TPv2 version number
    pub const VERSION_2: u16 = 0x0002;

    /// Minimum header length (no optional fields)
    pub const MIN_HEADER_LEN: usize = 6;

    /// Length field size
    pub const LENGTH_FIELD_SIZE: usize = 2;

    /// Sequence fields size (Ns + Nr)
    pub const SEQUENCE_FIELDS_SIZE: usize = 4;

    /// Offset field size
    pub const OFFSET_FIELD_SIZE: usize = 2;

    #[allow(unused)]
    const NAME: &'static str = "L2TPv2";

    /// Get the raw flags and version field
    #[inline]
    pub fn flags_version(&self) -> u16 {
        self.flags_version.get()
    }

    /// Get the protocol version
    #[inline]
    pub fn version(&self) -> u16 {
        self.flags_version.get() & Self::VERSION_MASK
    }

    /// Check if this is a control message (T=1) or data message (T=0)
    #[inline]
    pub fn is_control(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_TYPE) != 0
    }

    /// Check if this is a data message
    #[inline]
    pub fn is_data(&self) -> bool {
        !self.is_control()
    }

    /// Check if length field is present
    #[inline]
    pub fn has_length(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_LENGTH) != 0
    }

    /// Check if sequence fields (Ns, Nr) are present
    #[inline]
    pub fn has_sequence(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_SEQUENCE) != 0
    }

    /// Check if offset field is present
    #[inline]
    pub fn has_offset(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_OFFSET) != 0
    }

    /// Check if priority bit is set
    #[inline]
    pub fn has_priority(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_PRIORITY) != 0
    }

    /// Get the Tunnel ID
    #[inline]
    pub fn tunnel_id(&self) -> u16 {
        self.tunnel_id.get()
    }

    /// Get the Session ID
    #[inline]
    pub fn session_id(&self) -> u16 {
        self.session_id.get()
    }

    /// Check if this header has optional fields
    #[inline]
    pub fn has_optional_fields(&self) -> bool {
        self.has_length() || self.has_sequence() || self.has_offset()
    }

    /// Calculate the total header length including optional fields
    #[inline]
    pub fn header_length(&self) -> usize {
        let mut len = Self::MIN_HEADER_LEN;
        if self.has_length() {
            len += Self::LENGTH_FIELD_SIZE;
        }
        if self.has_sequence() {
            len += Self::SEQUENCE_FIELDS_SIZE;
        }
        if self.has_offset() {
            len += Self::OFFSET_FIELD_SIZE;
        }
        len
    }

    /// Validate the header
    fn is_valid(&self) -> bool {
        // Version must be 2
        if self.version() != Self::VERSION_2 {
            return false;
        }
        // Control messages must have L and S bits set
        if self.is_control() && (!self.has_length() || !self.has_sequence()) {
            return false;
        }
        true
    }

    /// Get a string representation of the flags
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();
        if self.is_control() {
            flags.push("T");
        }
        if self.has_length() {
            flags.push("L");
        }
        if self.has_sequence() {
            flags.push("S");
        }
        if self.has_offset() {
            flags.push("O");
        }
        if self.has_priority() {
            flags.push("P");
        }
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join("|")
        }
    }
}

/// L2TPv2 Header with optional fields
#[derive(Debug, Clone)]
pub struct L2tpv2HeaderOpt<'a> {
    /// The fixed header
    pub header: &'a L2tpv2Header,
    /// Raw bytes of optional fields
    pub raw_options: &'a [u8],
}

impl<'a> L2tpv2HeaderOpt<'a> {
    /// Get the length field value (if L bit is set)
    ///
    /// The length field is inserted between flags_version and tunnel_id
    /// in the wire format, but since we parse tunnel_id/session_id as
    /// part of the fixed header, we need to look at raw_options.
    pub fn length(&self) -> Option<u16> {
        if self.header.has_length() && self.raw_options.len() >= 2 {
            Some(u16::from_be_bytes([
                self.raw_options[0],
                self.raw_options[1],
            ]))
        } else {
            None
        }
    }

    /// Get the sequence number Ns (if S bit is set)
    pub fn ns(&self) -> Option<u16> {
        if !self.header.has_sequence() {
            return None;
        }
        let offset = if self.header.has_length() { 2 } else { 0 };
        if self.raw_options.len() >= offset + 2 {
            Some(u16::from_be_bytes([
                self.raw_options[offset],
                self.raw_options[offset + 1],
            ]))
        } else {
            None
        }
    }

    /// Get the expected sequence number Nr (if S bit is set)
    pub fn nr(&self) -> Option<u16> {
        if !self.header.has_sequence() {
            return None;
        }
        let offset = if self.header.has_length() { 4 } else { 2 };
        if self.raw_options.len() >= offset + 2 {
            Some(u16::from_be_bytes([
                self.raw_options[offset],
                self.raw_options[offset + 1],
            ]))
        } else {
            None
        }
    }

    /// Get the offset size (if O bit is set)
    pub fn offset_size(&self) -> Option<u16> {
        if !self.header.has_offset() {
            return None;
        }
        let mut offset = 0;
        if self.header.has_length() {
            offset += 2;
        }
        if self.header.has_sequence() {
            offset += 4;
        }
        if self.raw_options.len() >= offset + 2 {
            Some(u16::from_be_bytes([
                self.raw_options[offset],
                self.raw_options[offset + 1],
            ]))
        } else {
            None
        }
    }

    /// Get an iterator over AVPs (for control messages)
    pub fn avps(&self) -> L2tpAvpIter<'a> {
        if !self.header.is_control() {
            return L2tpAvpIter { data: &[] };
        }
        // AVPs start after the header
        L2tpAvpIter { data: &[] } // AVPs are in the payload, not raw_options
    }
}

impl std::ops::Deref for L2tpv2HeaderOpt<'_> {
    type Target = L2tpv2Header;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

/// L2TP AVP Header (6 bytes minimum)
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct L2tpAvpHeader {
    flags_length: U16<BigEndian>,
    vendor_id: U16<BigEndian>,
    attribute_type: U16<BigEndian>,
}

impl L2tpAvpHeader {
    /// Mandatory bit
    pub const FLAG_MANDATORY: u16 = 0x8000;
    /// Hidden bit (value is hidden)
    pub const FLAG_HIDDEN: u16 = 0x4000;
    /// Length mask (bits 0-9)
    pub const LENGTH_MASK: u16 = 0x03FF;

    /// Minimum AVP header size
    pub const HEADER_SIZE: usize = 6;

    /// Check if this AVP is mandatory
    #[inline]
    pub fn is_mandatory(&self) -> bool {
        (self.flags_length.get() & Self::FLAG_MANDATORY) != 0
    }

    /// Check if this AVP value is hidden
    #[inline]
    pub fn is_hidden(&self) -> bool {
        (self.flags_length.get() & Self::FLAG_HIDDEN) != 0
    }

    /// Get the total length of this AVP (including header)
    #[inline]
    pub fn length(&self) -> u16 {
        self.flags_length.get() & Self::LENGTH_MASK
    }

    /// Get the vendor ID (0 for IETF-defined AVPs)
    #[inline]
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id.get()
    }

    /// Get the attribute type
    #[inline]
    pub fn attribute_type(&self) -> u16 {
        self.attribute_type.get()
    }

    /// Get the attribute type as enum
    #[inline]
    pub fn attribute_type_enum(&self) -> L2tpAvpType {
        L2tpAvpType::from(self.attribute_type.get())
    }

    /// Get the value length (total length - header size)
    #[inline]
    pub fn value_length(&self) -> usize {
        let total = self.length() as usize;
        total.saturating_sub(Self::HEADER_SIZE)
    }
}

/// A parsed L2TP AVP
#[derive(Debug, Clone)]
pub struct L2tpAvp<'a> {
    /// AVP header
    pub header: &'a L2tpAvpHeader,
    /// AVP value
    pub value: &'a [u8],
}

impl<'a> L2tpAvp<'a> {
    /// Check if this is a Message Type AVP
    #[inline]
    pub fn is_message_type(&self) -> bool {
        self.header.vendor_id() == 0 && self.header.attribute_type() == 0
    }

    /// Get the message type value (if this is a Message Type AVP)
    pub fn message_type(&self) -> Option<L2tpv2MessageType> {
        if self.is_message_type() && self.value.len() >= 2 {
            let msg_type = u16::from_be_bytes([self.value[0], self.value[1]]);
            Some(L2tpv2MessageType::from(msg_type))
        } else {
            None
        }
    }
}

/// Iterator over L2TP AVPs
#[derive(Debug, Clone)]
pub struct L2tpAvpIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for L2tpAvpIter<'a> {
    type Item = L2tpAvp<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < L2tpAvpHeader::HEADER_SIZE {
            return None;
        }

        // Parse the AVP header
        let header = zerocopy::Ref::<_, L2tpAvpHeader>::from_prefix(self.data)
            .ok()
            .map(|(header_ref, _)| zerocopy::Ref::into_ref(header_ref))?;

        let total_len = header.length() as usize;
        if total_len < L2tpAvpHeader::HEADER_SIZE || total_len > self.data.len() {
            self.data = &[];
            return None;
        }

        let value_start = L2tpAvpHeader::HEADER_SIZE;
        let value = &self.data[value_start..total_len];

        // Advance to next AVP
        self.data = &self.data[total_len..];

        Some(L2tpAvp { header, value })
    }
}

impl PacketHeader for L2tpv2Header {
    const NAME: &'static str = "L2TPv2";

    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        self.header_length()
    }

    #[inline]
    fn is_valid(&self) -> bool {
        L2tpv2Header::is_valid(self)
    }
}

impl HeaderParser for L2tpv2Header {
    type Output<'a> = L2tpv2HeaderOpt<'a>;

    fn into_view<'a>(header: &'a Self, options: &'a [u8]) -> Self::Output<'a> {
        L2tpv2HeaderOpt {
            header,
            raw_options: options,
        }
    }
}

impl fmt::Display for L2tpv2Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "L2TPv{} {} tunnel={} session={} flags=[{}]",
            self.version(),
            if self.is_control() { "CTRL" } else { "DATA" },
            self.tunnel_id(),
            self.session_id(),
            self.flags_string()
        )
    }
}

impl fmt::Display for L2tpv2HeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "L2TPv{} {} tunnel={} session={} flags=[{}]",
            self.version(),
            if self.is_control() { "CTRL" } else { "DATA" },
            self.tunnel_id(),
            self.session_id(),
            self.flags_string()
        )?;
        if let Some(len) = self.length() {
            write!(f, " len={}", len)?;
        }
        if let Some(ns) = self.ns() {
            write!(f, " Ns={}", ns)?;
        }
        if let Some(nr) = self.nr() {
            write!(f, " Nr={}", nr)?;
        }
        if let Some(offset) = self.offset_size() {
            write!(f, " offset={}", offset)?;
        }
        Ok(())
    }
}

// ============================================================================
// L2TPv3 Support
// ============================================================================

/// L2TPv3 Session Header for data messages (over IP or UDP)
///
/// When L2TPv3 data is sent directly over IP (protocol 115), or over UDP
/// with a zero Session ID in the first 4 bytes indicating a data message,
/// this simple header is used.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Session ID (32 bits)                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Cookie (optional, variable length)              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct L2tpv3SessionHeader {
    session_id: U32<BigEndian>,
}

impl L2tpv3SessionHeader {
    /// Minimum header size (just session ID)
    pub const MIN_HEADER_LEN: usize = 4;

    #[allow(unused)]
    const NAME: &'static str = "L2TPv3-Session";

    /// Get the session ID
    #[inline]
    pub fn session_id(&self) -> u32 {
        self.session_id.get()
    }

    /// Check if this is a valid L2TPv3 data session header
    /// Session ID of 0 indicates a control message, not data
    #[inline]
    fn is_valid(&self) -> bool {
        self.session_id.get() != 0
    }
}

/// L2TPv3 Session Header with optional cookie
#[derive(Debug, Clone)]
pub struct L2tpv3SessionHeaderCookie<'a> {
    /// The fixed header
    pub header: &'a L2tpv3SessionHeader,
    /// Cookie bytes (0, 4, or 8 bytes depending on configuration)
    pub cookie: &'a [u8],
}

impl<'a> L2tpv3SessionHeaderCookie<'a> {
    /// Get the cookie as a 32-bit value (if 4-byte cookie)
    pub fn cookie_32(&self) -> Option<u32> {
        if self.cookie.len() >= 4 {
            Some(u32::from_be_bytes([
                self.cookie[0],
                self.cookie[1],
                self.cookie[2],
                self.cookie[3],
            ]))
        } else {
            None
        }
    }

    /// Get the cookie as a 64-bit value (if 8-byte cookie)
    pub fn cookie_64(&self) -> Option<u64> {
        if self.cookie.len() >= 8 {
            Some(u64::from_be_bytes([
                self.cookie[0],
                self.cookie[1],
                self.cookie[2],
                self.cookie[3],
                self.cookie[4],
                self.cookie[5],
                self.cookie[6],
                self.cookie[7],
            ]))
        } else {
            None
        }
    }
}

impl std::ops::Deref for L2tpv3SessionHeaderCookie<'_> {
    type Target = L2tpv3SessionHeader;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for L2tpv3SessionHeader {
    const NAME: &'static str = "L2TPv3-Session";

    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        // Cookie length is negotiated out-of-band, so we return minimum
        // The caller should use parse_with_cookie_len for proper parsing
        Self::MIN_HEADER_LEN
    }

    #[inline]
    fn is_valid(&self) -> bool {
        L2tpv3SessionHeader::is_valid(self)
    }
}

impl HeaderParser for L2tpv3SessionHeader {
    type Output<'a> = L2tpv3SessionHeaderCookie<'a>;

    fn into_view<'a>(header: &'a Self, options: &'a [u8]) -> Self::Output<'a> {
        L2tpv3SessionHeaderCookie {
            header,
            cookie: options,
        }
    }
}

impl L2tpv3SessionHeader {
    /// Parse L2TPv3 session header with a known cookie length
    ///
    /// Cookie length (0, 4, or 8 bytes) is negotiated during session setup.
    pub fn parse_with_cookie_len(
        buf: &[u8],
        cookie_len: usize,
    ) -> Result<(L2tpv3SessionHeaderCookie<'_>, &[u8]), PacketHeaderError> {
        if buf.len() < Self::MIN_HEADER_LEN + cookie_len {
            return Err(PacketHeaderError::TooShort("L2TPv3-Session"));
        }

        let (header_ref, rest) = zerocopy::Ref::<_, Self>::from_prefix(buf)
            .map_err(|_| PacketHeaderError::TooShort("L2TPv3-Session"))?;

        let header = zerocopy::Ref::into_ref(header_ref);

        if !header.is_valid() {
            return Err(PacketHeaderError::Invalid("L2TPv3-Session"));
        }

        let (cookie, payload) = rest.split_at(cookie_len);

        Ok((L2tpv3SessionHeaderCookie { header, cookie }, payload))
    }
}

impl fmt::Display for L2tpv3SessionHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "L2TPv3 Session ID={}", self.session_id())
    }
}

impl fmt::Display for L2tpv3SessionHeaderCookie<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "L2TPv3 Session ID={}", self.session_id())?;
        if let Some(cookie) = self.cookie_64() {
            write!(f, " Cookie=0x{:016x}", cookie)?;
        } else if let Some(cookie) = self.cookie_32() {
            write!(f, " Cookie=0x{:08x}", cookie)?;
        }
        Ok(())
    }
}

/// L2TPv3 Control Message Header (for UDP encapsulation)
///
/// L2TPv3 control messages over UDP use a format similar to L2TPv2
/// but with version 3 and some differences.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |T|L|x|x|S|x|x|x|x|x|x|x|  Ver  |          Length               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Control Connection ID                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Ns              |               Nr              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct L2tpv3ControlHeader {
    flags_version: U16<BigEndian>,
    length: U16<BigEndian>,
    control_connection_id: U32<BigEndian>,
    ns: U16<BigEndian>,
    nr: U16<BigEndian>,
}

impl L2tpv3ControlHeader {
    /// Type bit: must be 1 for control messages
    pub const FLAG_TYPE: u16 = 0x8000;
    /// Length bit: must be 1 for control messages
    pub const FLAG_LENGTH: u16 = 0x4000;
    /// Sequence bit: must be 1 for control messages
    pub const FLAG_SEQUENCE: u16 = 0x0800;

    /// Version mask (bits 0-3)
    pub const VERSION_MASK: u16 = 0x000F;

    /// L2TPv3 version number
    pub const VERSION_3: u16 = 0x0003;

    /// Fixed header size
    pub const HEADER_LEN: usize = 12;

    #[allow(unused)]
    const NAME: &'static str = "L2TPv3-Control";

    /// Get the raw flags and version field
    #[inline]
    pub fn flags_version(&self) -> u16 {
        self.flags_version.get()
    }

    /// Get the protocol version
    #[inline]
    pub fn version(&self) -> u16 {
        self.flags_version.get() & Self::VERSION_MASK
    }

    /// Check if this is a control message (T=1)
    #[inline]
    pub fn is_control(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_TYPE) != 0
    }

    /// Check if length field is present
    #[inline]
    pub fn has_length(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_LENGTH) != 0
    }

    /// Check if sequence fields are present
    #[inline]
    pub fn has_sequence(&self) -> bool {
        (self.flags_version.get() & Self::FLAG_SEQUENCE) != 0
    }

    /// Get the length field
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.get()
    }

    /// Get the Control Connection ID
    #[inline]
    pub fn control_connection_id(&self) -> u32 {
        self.control_connection_id.get()
    }

    /// Get the sequence number Ns
    #[inline]
    pub fn ns(&self) -> u16 {
        self.ns.get()
    }

    /// Get the expected sequence number Nr
    #[inline]
    pub fn nr(&self) -> u16 {
        self.nr.get()
    }

    /// Validate the header
    fn is_valid(&self) -> bool {
        // Version must be 3
        if self.version() != Self::VERSION_3 {
            return false;
        }
        // Control messages must have T, L, and S bits set
        if !self.is_control() || !self.has_length() || !self.has_sequence() {
            return false;
        }
        true
    }

    /// Get a string representation of the flags
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();
        if self.is_control() {
            flags.push("T");
        }
        if self.has_length() {
            flags.push("L");
        }
        if self.has_sequence() {
            flags.push("S");
        }
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join("|")
        }
    }
}

impl PacketHeader for L2tpv3ControlHeader {
    const NAME: &'static str = "L2TPv3-Control";

    type InnerType = ();

    #[inline]
    fn inner_type(&self) -> Self::InnerType {}

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::HEADER_LEN
    }

    #[inline]
    fn is_valid(&self) -> bool {
        L2tpv3ControlHeader::is_valid(self)
    }
}

impl HeaderParser for L2tpv3ControlHeader {
    type Output<'a> = &'a L2tpv3ControlHeader;

    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for L2tpv3ControlHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "L2TPv3 CTRL CCID={} Ns={} Nr={} len={} flags=[{}]",
            self.control_connection_id(),
            self.ns(),
            self.nr(),
            self.length(),
            self.flags_string()
        )
    }
}

/// Helper to distinguish L2TPv2 vs L2TPv3 by looking at the version field
pub fn detect_l2tp_version(buf: &[u8]) -> Option<u16> {
    if buf.len() < 2 {
        return None;
    }
    let flags_version = u16::from_be_bytes([buf[0], buf[1]]);
    Some(flags_version & 0x000F)
}

/// Check if this looks like an L2TPv3 data session (Session ID != 0 in first 4 bytes)
/// This is used when parsing L2TPv3 over IP (protocol 115)
pub fn is_l2tpv3_data_session(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    session_id != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::HeaderParser;

    #[test]
    fn test_l2tpv2_header_size() {
        assert_eq!(std::mem::size_of::<L2tpv2Header>(), 6);
        assert_eq!(L2tpv2Header::MIN_HEADER_LEN, 6);
    }

    #[test]
    fn test_l2tpv2_data_basic() {
        // L2TPv2 data packet (minimal)
        let packet = vec![
            0x00, 0x02, // flags: T=0, L=0, S=0, O=0, P=0, Ver=2
            0x00, 0x01, // Tunnel ID: 1
            0x00, 0x02, // Session ID: 2
            // PPP payload
            0xFF, 0x03, 0x00, 0x21,
        ];

        let (header, payload) = L2tpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(header.version(), 2);
        assert!(!header.is_control());
        assert!(header.is_data());
        assert!(!header.has_length());
        assert!(!header.has_sequence());
        assert!(!header.has_offset());
        assert!(!header.has_priority());
        assert_eq!(header.tunnel_id(), 1);
        assert_eq!(header.session_id(), 2);
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_l2tpv2_control_with_sequence() {
        // L2TPv2 control message with L and S bits
        let packet = vec![
            0xC8, 0x02, // flags: T=1, L=1, S=1, Ver=2
            0x00, 0x01, // Tunnel ID: 1
            0x00, 0x00, // Session ID: 0 (control)
            // Optional fields
            0x00, 0x10, // Length: 16
            0x00, 0x01, // Ns: 1
            0x00, 0x02, // Nr: 2
            // AVP payload
            0x00, 0x08, 0x00, 0x00,
        ];

        let (header, _payload) = L2tpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(header.version(), 2);
        assert!(header.is_control());
        assert!(header.has_length());
        assert!(header.has_sequence());
        assert_eq!(header.tunnel_id(), 1);
        assert_eq!(header.session_id(), 0);
        assert_eq!(header.length(), Some(16));
        assert_eq!(header.ns(), Some(1));
        assert_eq!(header.nr(), Some(2));
    }

    #[test]
    fn test_l2tpv2_with_offset() {
        // L2TPv2 data with offset field
        let packet = vec![
            0x02, 0x02, // flags: O=1, Ver=2
            0x00, 0x01, // Tunnel ID: 1
            0x00, 0x02, // Session ID: 2
            // Optional fields
            0x00, 0x04, // Offset Size: 4
            // Payload
            0xFF, 0x03,
        ];

        let (header, _payload) = L2tpv2Header::from_bytes(&packet).unwrap();
        assert!(header.has_offset());
        assert_eq!(header.offset_size(), Some(4));
    }

    #[test]
    fn test_l2tpv2_with_priority() {
        // L2TPv2 data with priority bit
        let packet = vec![
            0x01, 0x02, // flags: P=1, Ver=2
            0x00, 0x01, // Tunnel ID: 1
            0x00, 0x02, // Session ID: 2
            // Payload
            0xFF, 0x03,
        ];

        let (header, _payload) = L2tpv2Header::from_bytes(&packet).unwrap();
        assert!(header.has_priority());
        assert!(header.is_data());
    }

    #[test]
    fn test_l2tpv2_invalid_version() {
        // Invalid version (not 2)
        let packet = vec![
            0x00, 0x03, // flags: Ver=3 (invalid for L2TPv2Header)
            0x00, 0x01, // Tunnel ID: 1
            0x00, 0x02, // Session ID: 2
        ];

        let result = L2tpv2Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_l2tpv2_control_missing_length() {
        // Control message without L bit (invalid)
        let packet = vec![
            0x88, 0x02, // flags: T=1, S=1, Ver=2 (missing L)
            0x00, 0x01, // Tunnel ID: 1
            0x00, 0x00, // Session ID: 0
        ];

        let result = L2tpv2Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_l2tpv2_flags_string() {
        // Control with all common flags
        let packet = vec![
            0xC9, 0x02, // flags: T=1, L=1, S=0, O=0, P=1, Ver=2
            0x00, 0x01, // Tunnel ID
            0x00, 0x00, // Session ID
            0x00, 0x10, // Length
            0x00, 0x01, // Ns
            0x00, 0x00, // Nr
        ];

        let (header, _) = L2tpv2Header::from_bytes(&packet).unwrap();
        let flags = header.flags_string();
        assert!(flags.contains("T"));
        assert!(flags.contains("L"));
        assert!(flags.contains("P"));
    }

    #[test]
    fn test_l2tpv2_display() {
        let packet = vec![
            0x00, 0x02, // flags: Ver=2
            0x00, 0x0A, // Tunnel ID: 10
            0x00, 0x14, // Session ID: 20
            0xFF, 0x03,
        ];

        let (header, _) = L2tpv2Header::from_bytes(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("L2TPv2"));
        assert!(display.contains("DATA"));
        assert!(display.contains("tunnel=10"));
        assert!(display.contains("session=20"));
    }

    #[test]
    fn test_l2tpv2_too_short() {
        let packet = vec![0x00, 0x02, 0x00];
        let result = L2tpv2Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_l2tpv2_message_types() {
        assert_eq!(L2tpv2MessageType::from(1), L2tpv2MessageType::Sccrq);
        assert_eq!(L2tpv2MessageType::from(2), L2tpv2MessageType::Sccrp);
        assert_eq!(L2tpv2MessageType::from(3), L2tpv2MessageType::Scccn);
        assert_eq!(L2tpv2MessageType::from(4), L2tpv2MessageType::StopCcn);
        assert_eq!(L2tpv2MessageType::from(6), L2tpv2MessageType::Hello);
        assert_eq!(L2tpv2MessageType::from(14), L2tpv2MessageType::Cdn);
        assert_eq!(L2tpv2MessageType::from(0), L2tpv2MessageType::Zlb);
        assert_eq!(
            L2tpv2MessageType::from(255),
            L2tpv2MessageType::Unknown(255)
        );
    }

    #[test]
    fn test_l2tpv2_message_type_display() {
        assert_eq!(format!("{}", L2tpv2MessageType::Sccrq), "SCCRQ");
        assert_eq!(format!("{}", L2tpv2MessageType::Hello), "Hello");
        assert_eq!(format!("{}", L2tpv2MessageType::Unknown(99)), "Unknown(99)");
    }

    #[test]
    fn test_l2tp_avp_types() {
        assert_eq!(L2tpAvpType::from(0), L2tpAvpType::MessageType);
        assert_eq!(L2tpAvpType::from(7), L2tpAvpType::HostName);
        assert_eq!(L2tpAvpType::from(9), L2tpAvpType::AssignedTunnelId);
        assert_eq!(L2tpAvpType::from(100), L2tpAvpType::Unknown(100));
    }

    #[test]
    fn test_l2tp_port() {
        assert_eq!(L2TP_PORT, 1701);
        assert!(is_l2tp_port(1701));
        assert!(!is_l2tp_port(1702));
    }

    #[test]
    fn test_l2tpv3_ip_proto() {
        assert_eq!(L2TPV3_IP_PROTO, 115);
        assert!(is_l2tpv3_proto(115));
        assert!(!is_l2tpv3_proto(114));
    }

    // L2TPv3 Tests

    #[test]
    fn test_l2tpv3_session_header_size() {
        assert_eq!(std::mem::size_of::<L2tpv3SessionHeader>(), 4);
    }

    #[test]
    fn test_l2tpv3_session_basic() {
        // L2TPv3 data session (over IP)
        let packet = vec![
            0x00, 0x00, 0x12, 0x34, // Session ID: 0x1234
            // L2 payload follows
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let (header, payload) = L2tpv3SessionHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.session_id(), 0x1234);
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_l2tpv3_session_with_cookie_32() {
        let packet = vec![
            0x00, 0x00, 0x12, 0x34, // Session ID: 0x1234
            0xDE, 0xAD, 0xBE, 0xEF, // 32-bit cookie
            // Payload
            0xFF, 0xFF,
        ];

        let (header, payload) = L2tpv3SessionHeader::parse_with_cookie_len(&packet, 4).unwrap();
        assert_eq!(header.session_id(), 0x1234);
        assert_eq!(header.cookie_32(), Some(0xDEADBEEF));
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_l2tpv3_session_with_cookie_64() {
        let packet = vec![
            0x00, 0x00, 0x12, 0x34, // Session ID: 0x1234
            0xDE, 0xAD, 0xBE, 0xEF, // 64-bit cookie (high)
            0xCA, 0xFE, 0xBA, 0xBE, // 64-bit cookie (low)
            // Payload
            0xFF, 0xFF,
        ];

        let (header, payload) = L2tpv3SessionHeader::parse_with_cookie_len(&packet, 8).unwrap();
        assert_eq!(header.session_id(), 0x1234);
        assert_eq!(header.cookie_64(), Some(0xDEADBEEFCAFEBABE));
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_l2tpv3_session_zero_id_invalid() {
        // Session ID 0 means control message, not data
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, // Session ID: 0 (invalid for data)
            0xFF, 0xFF,
        ];

        let result = L2tpv3SessionHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_l2tpv3_session_display() {
        let packet = vec![
            0x00, 0x00, 0xAB, 0xCD, // Session ID
            0x12, 0x34, 0x56, 0x78, // Cookie
        ];

        let (header, _) = L2tpv3SessionHeader::parse_with_cookie_len(&packet, 4).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("L2TPv3"));
        assert!(display.contains("Session ID"));
        assert!(display.contains("Cookie"));
    }

    #[test]
    fn test_l2tpv3_control_header_size() {
        assert_eq!(std::mem::size_of::<L2tpv3ControlHeader>(), 12);
    }

    #[test]
    fn test_l2tpv3_control_basic() {
        // L2TPv3 control message
        let packet = vec![
            0xC8, 0x03, // flags: T=1, L=1, S=1, Ver=3
            0x00, 0x14, // Length: 20
            0x00, 0x00, 0x00, 0x01, // Control Connection ID: 1
            0x00, 0x05, // Ns: 5
            0x00, 0x04, // Nr: 4
            // AVPs follow
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let (header, payload) = L2tpv3ControlHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.version(), 3);
        assert!(header.is_control());
        assert!(header.has_length());
        assert!(header.has_sequence());
        assert_eq!(header.length(), 20);
        assert_eq!(header.control_connection_id(), 1);
        assert_eq!(header.ns(), 5);
        assert_eq!(header.nr(), 4);
        assert_eq!(payload.len(), 8);
    }

    #[test]
    fn test_l2tpv3_control_invalid_version() {
        // Invalid version
        let packet = vec![
            0xC8, 0x02, // flags: T=1, L=1, S=1, Ver=2 (wrong)
            0x00, 0x14, // Length
            0x00, 0x00, 0x00, 0x01, // CCID
            0x00, 0x05, // Ns
            0x00, 0x04, // Nr
        ];

        let result = L2tpv3ControlHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_l2tpv3_control_display() {
        let packet = vec![
            0xC8, 0x03, // flags
            0x00, 0x0C, // Length: 12
            0x00, 0x00, 0x00, 0x0A, // CCID: 10
            0x00, 0x01, // Ns: 1
            0x00, 0x02, // Nr: 2
        ];

        let (header, _) = L2tpv3ControlHeader::from_bytes(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("L2TPv3"));
        assert!(display.contains("CTRL"));
        assert!(display.contains("CCID=10"));
        assert!(display.contains("Ns=1"));
        assert!(display.contains("Nr=2"));
    }

    #[test]
    fn test_l2tpv3_message_types() {
        assert_eq!(L2tpv3MessageType::from(1), L2tpv3MessageType::Sccrq);
        assert_eq!(L2tpv3MessageType::from(20), L2tpv3MessageType::Ack);
        assert_eq!(L2tpv3MessageType::from(0), L2tpv3MessageType::Zlb);
    }

    #[test]
    fn test_detect_l2tp_version() {
        // L2TPv2
        let v2_packet = vec![0xC8, 0x02, 0x00, 0x10];
        assert_eq!(detect_l2tp_version(&v2_packet), Some(2));

        // L2TPv3
        let v3_packet = vec![0xC8, 0x03, 0x00, 0x10];
        assert_eq!(detect_l2tp_version(&v3_packet), Some(3));

        // Too short
        assert_eq!(detect_l2tp_version(&[0x00]), None);
    }

    #[test]
    fn test_is_l2tpv3_data_session() {
        // Data session (non-zero Session ID)
        let data = vec![0x00, 0x00, 0x12, 0x34];
        assert!(is_l2tpv3_data_session(&data));

        // Control (zero Session ID)
        let ctrl = vec![0x00, 0x00, 0x00, 0x00];
        assert!(!is_l2tpv3_data_session(&ctrl));

        // Too short
        assert!(!is_l2tpv3_data_session(&[0x00, 0x00]));
    }

    #[test]
    fn test_l2tp_avp_header_size() {
        assert_eq!(std::mem::size_of::<L2tpAvpHeader>(), 6);
    }

    #[test]
    fn test_l2tp_avp_parsing() {
        // Message Type AVP (type 0, value = SCCRQ = 1)
        let avp_data = vec![
            0x80, 0x08, // M=1, H=0, Length=8
            0x00, 0x00, // Vendor ID: 0 (IETF)
            0x00, 0x00, // Attribute Type: 0 (Message Type)
            0x00, 0x01, // Value: SCCRQ
        ];

        let mut iter = L2tpAvpIter { data: &avp_data };
        let avp = iter.next().unwrap();

        assert!(avp.header.is_mandatory());
        assert!(!avp.header.is_hidden());
        assert_eq!(avp.header.length(), 8);
        assert_eq!(avp.header.vendor_id(), 0);
        assert_eq!(avp.header.attribute_type(), 0);
        assert!(avp.is_message_type());
        assert_eq!(avp.message_type(), Some(L2tpv2MessageType::Sccrq));
        assert_eq!(avp.value.len(), 2);

        // No more AVPs
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_l2tp_avp_multiple() {
        // Two AVPs
        let avp_data = vec![
            // AVP 1: Message Type
            0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // AVP 2: Protocol Version (type 2)
            0x80, 0x08, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
        ];

        let iter = L2tpAvpIter { data: &avp_data };
        let avps: Vec<_> = iter.collect();

        assert_eq!(avps.len(), 2);
        assert_eq!(avps[0].header.attribute_type(), 0);
        assert_eq!(avps[1].header.attribute_type(), 2);
    }

    #[test]
    fn test_l2tpv2_full_control_message() {
        // Complete SCCRQ message
        let packet = vec![
            // L2TPv2 Header
            0xC8, 0x02, // T=1, L=1, S=1, Ver=2
            0x00, 0x00, // Tunnel ID: 0
            0x00, 0x00, // Session ID: 0
            // Optional fields
            0x00, 0x28, // Length: 40
            0x00, 0x00, // Ns: 0
            0x00, 0x00, // Nr: 0
            // AVP: Message Type (SCCRQ)
            0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // AVP: Protocol Version
            0x80, 0x08, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
            // More AVPs would follow...
        ];

        let (header, payload) = L2tpv2Header::from_bytes(&packet).unwrap();
        assert!(header.is_control());
        assert_eq!(header.tunnel_id(), 0);
        assert_eq!(header.ns(), Some(0));
        assert_eq!(header.nr(), Some(0));

        // Parse AVPs from payload
        let iter = L2tpAvpIter { data: payload };
        let avps: Vec<_> = iter.collect();
        assert_eq!(avps.len(), 2);
    }

    #[test]
    fn test_l2tpv2_header_opt_display() {
        let packet = vec![
            0xC8, 0x02, // T=1, L=1, S=1, Ver=2
            0x00, 0x0A, // Tunnel ID: 10
            0x00, 0x14, // Session ID: 20
            0x00, 0x10, // Length: 16
            0x00, 0x05, // Ns: 5
            0x00, 0x03, // Nr: 3
        ];

        let (header, _) = L2tpv2Header::from_bytes(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("CTRL"));
        assert!(display.contains("tunnel=10"));
        assert!(display.contains("session=20"));
        assert!(display.contains("len=16"));
        assert!(display.contains("Ns=5"));
        assert!(display.contains("Nr=3"));
    }

    #[test]
    fn test_l2tpv2_data_with_all_flags() {
        // Data message with L, S, O, P flags
        let packet = vec![
            0x4B, 0x02, // L=1, S=1, O=1, P=1, Ver=2
            0x00, 0x01, // Tunnel ID
            0x00, 0x02, // Session ID
            0x00, 0x14, // Length
            0x00, 0x01, // Ns
            0x00, 0x02, // Nr
            0x00, 0x00, // Offset Size
            // Payload
            0xFF, 0x03,
        ];

        let (header, _) = L2tpv2Header::from_bytes(&packet).unwrap();
        assert!(header.is_data());
        assert!(header.has_length());
        assert!(header.has_sequence());
        assert!(header.has_offset());
        assert!(header.has_priority());
    }
}
