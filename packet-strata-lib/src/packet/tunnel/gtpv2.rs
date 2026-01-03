//! GTPv2 (GPRS Tunneling Protocol version 2) parser
//!
//! This module implements shallow parsing for GTPv2-C as defined in 3GPP TS 29.274.
//! GTPv2 is used for control plane signaling in LTE/EPC networks.
//!
//! # GTPv2-C Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Ver  |P|T|MP |   Spare       |         Message Type          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Message Length                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         TEID (if T=1)                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Sequence Number                 |    Spare      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Ports
//!
//! - GTPv2-C: UDP port 2123
//!
//! # Examples
//!
//! ## Basic GTPv2-C parsing
//!
//! ```
//! use packet_strata::packet::tunnel::gtpv2::Gtpv2Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // GTPv2-C Echo Request (no TEID)
//! let packet = vec![
//!     0x40,        // Version 2, P=0, T=0
//!     0x01,        // Message type: Echo Request
//!     0x00, 0x04,  // Length: 4 bytes
//!     0x00, 0x00, 0x01,  // Sequence number: 1
//!     0x00,        // Spare
//! ];
//!
//! let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 2);
//! assert!(!header.has_teid());
//! assert_eq!(header.message_type(), 1);
//! ```
//!
//! ## GTPv2-C with TEID
//!
//! ```
//! use packet_strata::packet::tunnel::gtpv2::Gtpv2Header;
//! use packet_strata::packet::HeaderParser;
//!
//! // GTPv2-C Create Session Request (with TEID)
//! let packet = vec![
//!     0x48,        // Version 2, P=0, T=1
//!     0x20,        // Message type: Create Session Request
//!     0x00, 0x08,  // Length: 8 bytes
//!     0x00, 0x00, 0x00, 0x01,  // TEID: 1
//!     0x00, 0x00, 0x01,  // Sequence number: 1
//!     0x00,        // Spare
//! ];
//!
//! let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
//! assert!(header.has_teid());
//! assert_eq!(header.teid(), Some(1));
//! assert_eq!(header.sequence_number(), 1);
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::{HeaderParser, PacketHeader};

/// GTPv2-C standard port
pub const GTPV2_C_PORT: u16 = 2123;

/// Check if port is GTPv2-C
#[inline]
pub fn is_gtpv2_c_port(port: u16) -> bool {
    port == GTPV2_C_PORT
}

/// GTPv2 Message Types (commonly used ones)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtpv2MessageType {
    // Path Management Messages
    EchoRequest = 1,
    EchoResponse = 2,
    VersionNotSupportedIndication = 3,

    // Tunnel Management Messages
    CreateSessionRequest = 32,
    CreateSessionResponse = 33,
    ModifyBearerRequest = 34,
    ModifyBearerResponse = 35,
    DeleteSessionRequest = 36,
    DeleteSessionResponse = 37,
    ChangeNotificationRequest = 38,
    ChangeNotificationResponse = 39,

    // Remote UE Report Messages
    RemoteUeReportNotification = 40,
    RemoteUeReportAcknowledge = 41,

    // Modify Bearer Command / Failure Indication
    ModifyBearerCommand = 64,
    ModifyBearerFailureIndication = 65,
    DeleteBearerCommand = 66,
    DeleteBearerFailureIndication = 67,
    BearerResourceCommand = 68,
    BearerResourceFailureIndication = 69,

    // Downlink Data Notification
    DownlinkDataNotification = 176,
    DownlinkDataNotificationAcknowledge = 177,
    DownlinkDataNotificationFailureIndication = 70,

    // Create Bearer Messages
    CreateBearerRequest = 95,
    CreateBearerResponse = 96,
    UpdateBearerRequest = 97,
    UpdateBearerResponse = 98,
    DeleteBearerRequest = 99,
    DeleteBearerResponse = 100,

    // Delete PDN Connection Set
    DeletePdnConnectionSetRequest = 101,
    DeletePdnConnectionSetResponse = 102,

    // PGW Downlink Triggering
    PgwDownlinkTriggeringNotification = 103,
    PgwDownlinkTriggeringAcknowledge = 104,

    // Identification Messages
    IdentificationRequest = 128,
    IdentificationResponse = 129,

    // Context Messages
    ContextRequest = 130,
    ContextResponse = 131,
    ContextAcknowledge = 132,
    ForwardRelocationRequest = 133,
    ForwardRelocationResponse = 134,
    ForwardRelocationCompleteNotification = 135,
    ForwardRelocationCompleteAcknowledge = 136,
    ForwardAccessContextNotification = 137,
    ForwardAccessContextAcknowledge = 138,
    RelocationCancelRequest = 139,
    RelocationCancelResponse = 140,

    // Configuration Transfer Messages
    ConfigurationTransferTunnel = 141,

    // Detach Notification
    DetachNotification = 149,
    DetachAcknowledge = 150,

    // CS Paging Indication
    CsPagingIndication = 151,
    RanInformationRelay = 152,

    // Alert MME / UE Activity Notification
    AlertMmeNotification = 153,
    AlertMmeAcknowledge = 154,
    UeActivityNotification = 155,
    UeActivityAcknowledge = 156,

    // ISR Status
    IsrStatusIndication = 157,

    // UE Registration Query
    UeRegistrationQueryRequest = 158,
    UeRegistrationQueryResponse = 159,

    // Create Forwarding Tunnel
    CreateForwardingTunnelRequest = 160,
    CreateForwardingTunnelResponse = 161,

    // Suspend / Resume Notification
    SuspendNotification = 162,
    SuspendAcknowledge = 163,
    ResumeNotification = 164,
    ResumeAcknowledge = 165,

    // Create Indirect Data Forwarding Tunnel
    CreateIndirectDataForwardingTunnelRequest = 166,
    CreateIndirectDataForwardingTunnelResponse = 167,
    DeleteIndirectDataForwardingTunnelRequest = 168,
    DeleteIndirectDataForwardingTunnelResponse = 169,

    // Release Access Bearers
    ReleaseAccessBearersRequest = 170,
    ReleaseAccessBearersResponse = 171,

    // Stop Paging Indication
    StopPagingIndication = 173,

    // Modify Access Bearers
    ModifyAccessBearersRequest = 211,
    ModifyAccessBearersResponse = 212,

    // MBMS Session Messages
    MbmsSessionStartRequest = 231,
    MbmsSessionStartResponse = 232,
    MbmsSessionUpdateRequest = 233,
    MbmsSessionUpdateResponse = 234,
    MbmsSessionStopRequest = 235,
    MbmsSessionStopResponse = 236,

    // Unknown message type
    Unknown = 0,
}

impl From<u8> for Gtpv2MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Gtpv2MessageType::EchoRequest,
            2 => Gtpv2MessageType::EchoResponse,
            3 => Gtpv2MessageType::VersionNotSupportedIndication,
            32 => Gtpv2MessageType::CreateSessionRequest,
            33 => Gtpv2MessageType::CreateSessionResponse,
            34 => Gtpv2MessageType::ModifyBearerRequest,
            35 => Gtpv2MessageType::ModifyBearerResponse,
            36 => Gtpv2MessageType::DeleteSessionRequest,
            37 => Gtpv2MessageType::DeleteSessionResponse,
            38 => Gtpv2MessageType::ChangeNotificationRequest,
            39 => Gtpv2MessageType::ChangeNotificationResponse,
            40 => Gtpv2MessageType::RemoteUeReportNotification,
            41 => Gtpv2MessageType::RemoteUeReportAcknowledge,
            64 => Gtpv2MessageType::ModifyBearerCommand,
            65 => Gtpv2MessageType::ModifyBearerFailureIndication,
            66 => Gtpv2MessageType::DeleteBearerCommand,
            67 => Gtpv2MessageType::DeleteBearerFailureIndication,
            68 => Gtpv2MessageType::BearerResourceCommand,
            69 => Gtpv2MessageType::BearerResourceFailureIndication,
            70 => Gtpv2MessageType::DownlinkDataNotificationFailureIndication,
            95 => Gtpv2MessageType::CreateBearerRequest,
            96 => Gtpv2MessageType::CreateBearerResponse,
            97 => Gtpv2MessageType::UpdateBearerRequest,
            98 => Gtpv2MessageType::UpdateBearerResponse,
            99 => Gtpv2MessageType::DeleteBearerRequest,
            100 => Gtpv2MessageType::DeleteBearerResponse,
            101 => Gtpv2MessageType::DeletePdnConnectionSetRequest,
            102 => Gtpv2MessageType::DeletePdnConnectionSetResponse,
            103 => Gtpv2MessageType::PgwDownlinkTriggeringNotification,
            104 => Gtpv2MessageType::PgwDownlinkTriggeringAcknowledge,
            128 => Gtpv2MessageType::IdentificationRequest,
            129 => Gtpv2MessageType::IdentificationResponse,
            130 => Gtpv2MessageType::ContextRequest,
            131 => Gtpv2MessageType::ContextResponse,
            132 => Gtpv2MessageType::ContextAcknowledge,
            133 => Gtpv2MessageType::ForwardRelocationRequest,
            134 => Gtpv2MessageType::ForwardRelocationResponse,
            135 => Gtpv2MessageType::ForwardRelocationCompleteNotification,
            136 => Gtpv2MessageType::ForwardRelocationCompleteAcknowledge,
            137 => Gtpv2MessageType::ForwardAccessContextNotification,
            138 => Gtpv2MessageType::ForwardAccessContextAcknowledge,
            139 => Gtpv2MessageType::RelocationCancelRequest,
            140 => Gtpv2MessageType::RelocationCancelResponse,
            141 => Gtpv2MessageType::ConfigurationTransferTunnel,
            149 => Gtpv2MessageType::DetachNotification,
            150 => Gtpv2MessageType::DetachAcknowledge,
            151 => Gtpv2MessageType::CsPagingIndication,
            152 => Gtpv2MessageType::RanInformationRelay,
            153 => Gtpv2MessageType::AlertMmeNotification,
            154 => Gtpv2MessageType::AlertMmeAcknowledge,
            155 => Gtpv2MessageType::UeActivityNotification,
            156 => Gtpv2MessageType::UeActivityAcknowledge,
            157 => Gtpv2MessageType::IsrStatusIndication,
            158 => Gtpv2MessageType::UeRegistrationQueryRequest,
            159 => Gtpv2MessageType::UeRegistrationQueryResponse,
            160 => Gtpv2MessageType::CreateForwardingTunnelRequest,
            161 => Gtpv2MessageType::CreateForwardingTunnelResponse,
            162 => Gtpv2MessageType::SuspendNotification,
            163 => Gtpv2MessageType::SuspendAcknowledge,
            164 => Gtpv2MessageType::ResumeNotification,
            165 => Gtpv2MessageType::ResumeAcknowledge,
            166 => Gtpv2MessageType::CreateIndirectDataForwardingTunnelRequest,
            167 => Gtpv2MessageType::CreateIndirectDataForwardingTunnelResponse,
            168 => Gtpv2MessageType::DeleteIndirectDataForwardingTunnelRequest,
            169 => Gtpv2MessageType::DeleteIndirectDataForwardingTunnelResponse,
            170 => Gtpv2MessageType::ReleaseAccessBearersRequest,
            171 => Gtpv2MessageType::ReleaseAccessBearersResponse,
            173 => Gtpv2MessageType::StopPagingIndication,
            176 => Gtpv2MessageType::DownlinkDataNotification,
            177 => Gtpv2MessageType::DownlinkDataNotificationAcknowledge,
            211 => Gtpv2MessageType::ModifyAccessBearersRequest,
            212 => Gtpv2MessageType::ModifyAccessBearersResponse,
            231 => Gtpv2MessageType::MbmsSessionStartRequest,
            232 => Gtpv2MessageType::MbmsSessionStartResponse,
            233 => Gtpv2MessageType::MbmsSessionUpdateRequest,
            234 => Gtpv2MessageType::MbmsSessionUpdateResponse,
            235 => Gtpv2MessageType::MbmsSessionStopRequest,
            236 => Gtpv2MessageType::MbmsSessionStopResponse,
            _ => Gtpv2MessageType::Unknown,
        }
    }
}

impl fmt::Display for Gtpv2MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Gtpv2MessageType::EchoRequest => write!(f, "Echo Request"),
            Gtpv2MessageType::EchoResponse => write!(f, "Echo Response"),
            Gtpv2MessageType::VersionNotSupportedIndication => {
                write!(f, "Version Not Supported Indication")
            }
            Gtpv2MessageType::CreateSessionRequest => write!(f, "Create Session Request"),
            Gtpv2MessageType::CreateSessionResponse => write!(f, "Create Session Response"),
            Gtpv2MessageType::ModifyBearerRequest => write!(f, "Modify Bearer Request"),
            Gtpv2MessageType::ModifyBearerResponse => write!(f, "Modify Bearer Response"),
            Gtpv2MessageType::DeleteSessionRequest => write!(f, "Delete Session Request"),
            Gtpv2MessageType::DeleteSessionResponse => write!(f, "Delete Session Response"),
            Gtpv2MessageType::ChangeNotificationRequest => write!(f, "Change Notification Request"),
            Gtpv2MessageType::ChangeNotificationResponse => {
                write!(f, "Change Notification Response")
            }
            Gtpv2MessageType::RemoteUeReportNotification => {
                write!(f, "Remote UE Report Notification")
            }
            Gtpv2MessageType::RemoteUeReportAcknowledge => {
                write!(f, "Remote UE Report Acknowledge")
            }
            Gtpv2MessageType::ModifyBearerCommand => write!(f, "Modify Bearer Command"),
            Gtpv2MessageType::ModifyBearerFailureIndication => {
                write!(f, "Modify Bearer Failure Indication")
            }
            Gtpv2MessageType::DeleteBearerCommand => write!(f, "Delete Bearer Command"),
            Gtpv2MessageType::DeleteBearerFailureIndication => {
                write!(f, "Delete Bearer Failure Indication")
            }
            Gtpv2MessageType::BearerResourceCommand => write!(f, "Bearer Resource Command"),
            Gtpv2MessageType::BearerResourceFailureIndication => {
                write!(f, "Bearer Resource Failure Indication")
            }
            Gtpv2MessageType::DownlinkDataNotification => write!(f, "Downlink Data Notification"),
            Gtpv2MessageType::DownlinkDataNotificationAcknowledge => {
                write!(f, "Downlink Data Notification Acknowledge")
            }
            Gtpv2MessageType::DownlinkDataNotificationFailureIndication => {
                write!(f, "Downlink Data Notification Failure Indication")
            }
            Gtpv2MessageType::CreateBearerRequest => write!(f, "Create Bearer Request"),
            Gtpv2MessageType::CreateBearerResponse => write!(f, "Create Bearer Response"),
            Gtpv2MessageType::UpdateBearerRequest => write!(f, "Update Bearer Request"),
            Gtpv2MessageType::UpdateBearerResponse => write!(f, "Update Bearer Response"),
            Gtpv2MessageType::DeleteBearerRequest => write!(f, "Delete Bearer Request"),
            Gtpv2MessageType::DeleteBearerResponse => write!(f, "Delete Bearer Response"),
            Gtpv2MessageType::DeletePdnConnectionSetRequest => {
                write!(f, "Delete PDN Connection Set Request")
            }
            Gtpv2MessageType::DeletePdnConnectionSetResponse => {
                write!(f, "Delete PDN Connection Set Response")
            }
            Gtpv2MessageType::PgwDownlinkTriggeringNotification => {
                write!(f, "PGW Downlink Triggering Notification")
            }
            Gtpv2MessageType::PgwDownlinkTriggeringAcknowledge => {
                write!(f, "PGW Downlink Triggering Acknowledge")
            }
            Gtpv2MessageType::IdentificationRequest => write!(f, "Identification Request"),
            Gtpv2MessageType::IdentificationResponse => write!(f, "Identification Response"),
            Gtpv2MessageType::ContextRequest => write!(f, "Context Request"),
            Gtpv2MessageType::ContextResponse => write!(f, "Context Response"),
            Gtpv2MessageType::ContextAcknowledge => write!(f, "Context Acknowledge"),
            Gtpv2MessageType::ForwardRelocationRequest => write!(f, "Forward Relocation Request"),
            Gtpv2MessageType::ForwardRelocationResponse => write!(f, "Forward Relocation Response"),
            Gtpv2MessageType::ForwardRelocationCompleteNotification => {
                write!(f, "Forward Relocation Complete Notification")
            }
            Gtpv2MessageType::ForwardRelocationCompleteAcknowledge => {
                write!(f, "Forward Relocation Complete Acknowledge")
            }
            Gtpv2MessageType::ForwardAccessContextNotification => {
                write!(f, "Forward Access Context Notification")
            }
            Gtpv2MessageType::ForwardAccessContextAcknowledge => {
                write!(f, "Forward Access Context Acknowledge")
            }
            Gtpv2MessageType::RelocationCancelRequest => write!(f, "Relocation Cancel Request"),
            Gtpv2MessageType::RelocationCancelResponse => write!(f, "Relocation Cancel Response"),
            Gtpv2MessageType::ConfigurationTransferTunnel => {
                write!(f, "Configuration Transfer Tunnel")
            }
            Gtpv2MessageType::DetachNotification => write!(f, "Detach Notification"),
            Gtpv2MessageType::DetachAcknowledge => write!(f, "Detach Acknowledge"),
            Gtpv2MessageType::CsPagingIndication => write!(f, "CS Paging Indication"),
            Gtpv2MessageType::RanInformationRelay => write!(f, "RAN Information Relay"),
            Gtpv2MessageType::AlertMmeNotification => write!(f, "Alert MME Notification"),
            Gtpv2MessageType::AlertMmeAcknowledge => write!(f, "Alert MME Acknowledge"),
            Gtpv2MessageType::UeActivityNotification => write!(f, "UE Activity Notification"),
            Gtpv2MessageType::UeActivityAcknowledge => write!(f, "UE Activity Acknowledge"),
            Gtpv2MessageType::IsrStatusIndication => write!(f, "ISR Status Indication"),
            Gtpv2MessageType::UeRegistrationQueryRequest => {
                write!(f, "UE Registration Query Request")
            }
            Gtpv2MessageType::UeRegistrationQueryResponse => {
                write!(f, "UE Registration Query Response")
            }
            Gtpv2MessageType::CreateForwardingTunnelRequest => {
                write!(f, "Create Forwarding Tunnel Request")
            }
            Gtpv2MessageType::CreateForwardingTunnelResponse => {
                write!(f, "Create Forwarding Tunnel Response")
            }
            Gtpv2MessageType::SuspendNotification => write!(f, "Suspend Notification"),
            Gtpv2MessageType::SuspendAcknowledge => write!(f, "Suspend Acknowledge"),
            Gtpv2MessageType::ResumeNotification => write!(f, "Resume Notification"),
            Gtpv2MessageType::ResumeAcknowledge => write!(f, "Resume Acknowledge"),
            Gtpv2MessageType::CreateIndirectDataForwardingTunnelRequest => {
                write!(f, "Create Indirect Data Forwarding Tunnel Request")
            }
            Gtpv2MessageType::CreateIndirectDataForwardingTunnelResponse => {
                write!(f, "Create Indirect Data Forwarding Tunnel Response")
            }
            Gtpv2MessageType::DeleteIndirectDataForwardingTunnelRequest => {
                write!(f, "Delete Indirect Data Forwarding Tunnel Request")
            }
            Gtpv2MessageType::DeleteIndirectDataForwardingTunnelResponse => {
                write!(f, "Delete Indirect Data Forwarding Tunnel Response")
            }
            Gtpv2MessageType::ReleaseAccessBearersRequest => {
                write!(f, "Release Access Bearers Request")
            }
            Gtpv2MessageType::ReleaseAccessBearersResponse => {
                write!(f, "Release Access Bearers Response")
            }
            Gtpv2MessageType::StopPagingIndication => write!(f, "Stop Paging Indication"),
            Gtpv2MessageType::ModifyAccessBearersRequest => {
                write!(f, "Modify Access Bearers Request")
            }
            Gtpv2MessageType::ModifyAccessBearersResponse => {
                write!(f, "Modify Access Bearers Response")
            }
            Gtpv2MessageType::MbmsSessionStartRequest => write!(f, "MBMS Session Start Request"),
            Gtpv2MessageType::MbmsSessionStartResponse => write!(f, "MBMS Session Start Response"),
            Gtpv2MessageType::MbmsSessionUpdateRequest => write!(f, "MBMS Session Update Request"),
            Gtpv2MessageType::MbmsSessionUpdateResponse => {
                write!(f, "MBMS Session Update Response")
            }
            Gtpv2MessageType::MbmsSessionStopRequest => write!(f, "MBMS Session Stop Request"),
            Gtpv2MessageType::MbmsSessionStopResponse => write!(f, "MBMS Session Stop Response"),
            Gtpv2MessageType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// GTPv2 Header structure (fixed 4 bytes, variable depending on T flag)
///
/// This is the base GTPv2-C header. The total header size depends on the T flag:
/// - T=0: 8 bytes (no TEID)
/// - T=1: 12 bytes (with TEID)
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct Gtpv2Header {
    flags: u8,
    message_type: u8,
    length: U16<BigEndian>,
}

impl Gtpv2Header {
    /// Version field mask (bits 5-7)
    pub const VERSION_MASK: u8 = 0xE0;
    pub const VERSION_SHIFT: u8 = 5;

    /// Piggybacking flag (bit 4)
    pub const FLAG_P: u8 = 0x10;

    /// TEID flag (bit 3): 1 = TEID present
    pub const FLAG_T: u8 = 0x08;

    /// Message Priority flag (bit 2) - GTPv2 Rel-11+
    pub const FLAG_MP: u8 = 0x04;

    /// Spare bits mask (bits 0-1)
    pub const SPARE_MASK: u8 = 0x03;

    /// GTPv2 version number
    pub const VERSION_2: u8 = 2;

    /// Header length without TEID
    pub const HEADER_LEN_NO_TEID: usize = 8;

    /// Header length with TEID
    pub const HEADER_LEN_WITH_TEID: usize = 12;

    #[allow(unused)]
    const NAME: &'static str = "Gtpv2Header";

    /// Returns the flags byte
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the GTP version (should be 2)
    #[inline]
    pub fn version(&self) -> u8 {
        (self.flags & Self::VERSION_MASK) >> Self::VERSION_SHIFT
    }

    /// Returns true if Piggybacking flag is set
    #[inline]
    pub fn has_piggybacking(&self) -> bool {
        self.flags & Self::FLAG_P != 0
    }

    /// Returns true if TEID flag is set (TEID field is present)
    #[inline]
    pub fn has_teid(&self) -> bool {
        self.flags & Self::FLAG_T != 0
    }

    /// Returns true if Message Priority flag is set
    #[inline]
    pub fn has_message_priority(&self) -> bool {
        self.flags & Self::FLAG_MP != 0
    }

    /// Returns the message type
    #[inline]
    pub fn message_type(&self) -> u8 {
        self.message_type
    }

    /// Returns the message type as enum
    #[inline]
    pub fn message_type_enum(&self) -> Gtpv2MessageType {
        self.message_type.into()
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

    /// Returns the length field (message length excluding first 4 bytes)
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.get()
    }

    /// Calculate the actual header length based on T flag
    #[inline]
    pub fn header_length(&self) -> usize {
        if self.has_teid() {
            Self::HEADER_LEN_WITH_TEID
        } else {
            Self::HEADER_LEN_NO_TEID
        }
    }

    /// Validates the GTPv2 header
    #[inline]
    fn is_valid(&self) -> bool {
        // Version must be 2
        if self.version() != Self::VERSION_2 {
            return false;
        }

        true
    }

    /// Returns a string representation of active flags
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();

        if self.has_piggybacking() {
            flags.push("P");
        }
        if self.has_teid() {
            flags.push("T");
        }
        if self.has_message_priority() {
            flags.push("MP");
        }

        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(",")
        }
    }
}

/// GTPv2 Header with optional fields parsed
#[derive(Debug, Clone)]
pub struct Gtpv2HeaderOpt<'a> {
    pub header: &'a Gtpv2Header,
    pub raw_options: &'a [u8],
}

impl<'a> Gtpv2HeaderOpt<'a> {
    /// Get the TEID if present (when T flag is set)
    pub fn teid(&self) -> Option<u32> {
        if !self.header.has_teid() {
            return None;
        }

        if self.raw_options.len() < 4 {
            return None;
        }

        Some(u32::from_be_bytes([
            self.raw_options[0],
            self.raw_options[1],
            self.raw_options[2],
            self.raw_options[3],
        ]))
    }

    /// Get the sequence number (24 bits)
    pub fn sequence_number(&self) -> u32 {
        let offset = if self.header.has_teid() { 4 } else { 0 };

        if self.raw_options.len() < offset + 3 {
            return 0;
        }

        u32::from_be_bytes([
            0,
            self.raw_options[offset],
            self.raw_options[offset + 1],
            self.raw_options[offset + 2],
        ])
    }

    /// Get the message priority (4 bits, only valid if MP flag is set)
    pub fn message_priority(&self) -> Option<u8> {
        if !self.header.has_message_priority() {
            return None;
        }

        let offset = if self.header.has_teid() { 4 } else { 0 };

        if self.raw_options.len() < offset + 4 {
            return None;
        }

        // Message priority is in bits 4-7 of the spare byte
        Some((self.raw_options[offset + 3] >> 4) & 0x0F)
    }
}

impl std::ops::Deref for Gtpv2HeaderOpt<'_> {
    type Target = Gtpv2Header;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.header
    }
}

impl PacketHeader for Gtpv2Header {
    const NAME: &'static str = "Gtpv2Header";
    /// Inner type - message type
    type InnerType = u8;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.message_type
    }

    /// Returns the total header length in bytes (including optional TEID and seq)
    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        self.header_length()
    }

    /// Validates the GTPv2 header
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for Gtpv2Header {
    type Output<'a> = Gtpv2HeaderOpt<'a>;

    #[inline]
    fn into_view<'a>(header: &'a Self, raw_options: &'a [u8]) -> Self::Output<'a> {
        Gtpv2HeaderOpt {
            header,
            raw_options,
        }
    }
}

impl fmt::Display for Gtpv2Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GTPv2-C msg={} len={} flags=[{}]",
            self.message_type_enum(),
            self.length(),
            self.flags_string()
        )
    }
}

impl fmt::Display for Gtpv2HeaderOpt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "GTPv2-C msg={}", self.message_type_enum())?;

        if let Some(teid) = self.teid() {
            write!(f, " teid=0x{:08x}", teid)?;
        }

        write!(f, " seq={}", self.sequence_number())?;

        if let Some(prio) = self.message_priority() {
            write!(f, " prio={}", prio)?;
        }

        Ok(())
    }
}

/// GTPv2 Information Element (IE) header for shallow parsing
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct Gtpv2IeHeader {
    ie_type: u8,
    length: U16<BigEndian>,
    spare_instance: u8,
}

impl Gtpv2IeHeader {
    /// IE Type
    #[inline]
    pub fn ie_type(&self) -> u8 {
        self.ie_type
    }

    /// IE Length (not including the 4-byte IE header)
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.get()
    }

    /// Spare bits (bits 4-7)
    #[inline]
    pub fn spare(&self) -> u8 {
        (self.spare_instance >> 4) & 0x0F
    }

    /// Instance (bits 0-3)
    #[inline]
    pub fn instance(&self) -> u8 {
        self.spare_instance & 0x0F
    }

    /// Total IE length including header
    #[inline]
    pub fn total_length(&self) -> usize {
        4 + self.length() as usize
    }
}

/// Common GTPv2 IE Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtpv2IeType {
    Imsi = 1,
    Cause = 2,
    Recovery = 3,
    Apn = 71,
    Ambr = 72,
    Ebi = 73,
    Mei = 75,
    Msisdn = 76,
    Indication = 77,
    Pco = 78,
    Paa = 79,
    BearerQos = 80,
    RatType = 82,
    ServingNetwork = 83,
    BearerTft = 84,
    Tad = 85,
    Uli = 86,
    FTeid = 87,
    BearerContext = 93,
    ChargingId = 94,
    ChargingCharacteristics = 95,
    PdnType = 99,
    Pti = 100,
    UeTimeZone = 114,
    ApnRestriction = 127,
    SelectionMode = 128,
    Fqdn = 136,
    Unknown = 255,
}

impl From<u8> for Gtpv2IeType {
    fn from(value: u8) -> Self {
        match value {
            1 => Gtpv2IeType::Imsi,
            2 => Gtpv2IeType::Cause,
            3 => Gtpv2IeType::Recovery,
            71 => Gtpv2IeType::Apn,
            72 => Gtpv2IeType::Ambr,
            73 => Gtpv2IeType::Ebi,
            75 => Gtpv2IeType::Mei,
            76 => Gtpv2IeType::Msisdn,
            77 => Gtpv2IeType::Indication,
            78 => Gtpv2IeType::Pco,
            79 => Gtpv2IeType::Paa,
            80 => Gtpv2IeType::BearerQos,
            82 => Gtpv2IeType::RatType,
            83 => Gtpv2IeType::ServingNetwork,
            84 => Gtpv2IeType::BearerTft,
            85 => Gtpv2IeType::Tad,
            86 => Gtpv2IeType::Uli,
            87 => Gtpv2IeType::FTeid,
            93 => Gtpv2IeType::BearerContext,
            94 => Gtpv2IeType::ChargingId,
            95 => Gtpv2IeType::ChargingCharacteristics,
            99 => Gtpv2IeType::PdnType,
            100 => Gtpv2IeType::Pti,
            114 => Gtpv2IeType::UeTimeZone,
            127 => Gtpv2IeType::ApnRestriction,
            128 => Gtpv2IeType::SelectionMode,
            136 => Gtpv2IeType::Fqdn,
            _ => Gtpv2IeType::Unknown,
        }
    }
}

/// Iterator over GTPv2 Information Elements (shallow parsing)
pub struct Gtpv2IeIter<'a> {
    data: &'a [u8],
}

impl<'a> Gtpv2IeIter<'a> {
    /// Create a new IE iterator from the payload after the GTPv2 header
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

/// A single GTPv2 IE reference (shallow)
#[derive(Debug, Clone)]
pub struct Gtpv2Ie<'a> {
    /// IE type
    pub ie_type: u8,
    /// IE instance
    pub instance: u8,
    /// IE value (raw bytes)
    pub value: &'a [u8],
}

impl<'a> Iterator for Gtpv2IeIter<'a> {
    type Item = Gtpv2Ie<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Need at least 4 bytes for IE header
        if self.data.len() < 4 {
            return None;
        }

        let ie_type = self.data[0];
        let length = u16::from_be_bytes([self.data[1], self.data[2]]) as usize;
        let instance = self.data[3] & 0x0F;

        let total_len = 4 + length;
        if self.data.len() < total_len {
            return None;
        }

        let value = &self.data[4..total_len];

        let ie = Gtpv2Ie {
            ie_type,
            instance,
            value,
        };

        self.data = &self.data[total_len..];

        Some(ie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpv2_header_size() {
        assert_eq!(std::mem::size_of::<Gtpv2Header>(), 4);
        assert_eq!(Gtpv2Header::FIXED_LEN, 4);
    }

    #[test]
    fn test_gtpv2_echo_request_no_teid() {
        // GTPv2-C Echo Request (no TEID)
        let packet = vec![
            0x40, // Version 2, P=0, T=0
            0x01, // Message type: Echo Request
            0x00, 0x04, // Length: 4 bytes
            0x00, 0x00, 0x01, // Sequence number: 1
            0x00, // Spare
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(header.version(), 2);
        assert!(!header.has_piggybacking());
        assert!(!header.has_teid());
        assert!(!header.has_message_priority());
        assert_eq!(header.message_type(), 1);
        assert!(header.is_echo_request());
        assert_eq!(header.length(), 4);
        assert_eq!(header.header_length(), 8);
        assert_eq!(header.teid(), None);
        assert_eq!(header.sequence_number(), 1);
    }

    #[test]
    fn test_gtpv2_echo_response_no_teid() {
        let packet = vec![
            0x40, // Version 2, P=0, T=0
            0x02, // Message type: Echo Response
            0x00, 0x06, // Length: 6 bytes
            0x00, 0x00, 0x01, // Sequence number: 1
            0x00, // Spare
            0x03, 0x00, 0x01, 0x00, // Recovery IE
        ];

        let (header, payload) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert!(header.is_echo_response());
        assert_eq!(header.message_type_enum(), Gtpv2MessageType::EchoResponse);
        // Payload contains the IE
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_gtpv2_create_session_with_teid() {
        // GTPv2-C Create Session Request (with TEID)
        let packet = vec![
            0x48, // Version 2, P=0, T=1
            0x20, // Message type: Create Session Request
            0x00, 0x08, // Length: 8 bytes
            0x00, 0x00, 0x00, 0x01, // TEID: 1
            0x00, 0x00, 0x42, // Sequence number: 66
            0x00, // Spare
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(header.version(), 2);
        assert!(header.has_teid());
        assert!(!header.has_piggybacking());
        assert_eq!(header.message_type(), 0x20);
        assert_eq!(
            header.message_type_enum(),
            Gtpv2MessageType::CreateSessionRequest
        );
        assert_eq!(header.length(), 8);
        assert_eq!(header.header_length(), 12);
        assert_eq!(header.teid(), Some(1));
        assert_eq!(header.sequence_number(), 0x42);
    }

    #[test]
    fn test_gtpv2_with_piggybacking() {
        let packet = vec![
            0x58, // Version 2, P=1, T=1
            0x21, // Message type: Create Session Response
            0x00, 0x08, 0x00, 0x00, 0x00, 0x02, // TEID: 2
            0x00, 0x00, 0x01, // Sequence: 1
            0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert!(header.has_piggybacking());
        assert!(header.has_teid());
        assert_eq!(header.teid(), Some(2));
    }

    #[test]
    fn test_gtpv2_with_message_priority() {
        let packet = vec![
            0x4C, // Version 2, P=0, T=1, MP=1
            0x20, // Message type
            0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x50, // Priority = 5
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert!(header.has_message_priority());
        assert!(header.has_teid());
        assert_eq!(header.message_priority(), Some(5));
    }

    #[test]
    fn test_gtpv2_invalid_version() {
        // GTPv1 header (version 1)
        let packet = vec![
            0x30, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];

        let result = Gtpv2Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_gtpv2_parsing_too_small() {
        let packet = vec![0x40, 0x01]; // Only 2 bytes
        let result = Gtpv2Header::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_gtpv2_flags_string() {
        let packet = vec![
            0x5C, // Version 2, P=1, T=1, MP=1
            0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        let flags = header.flags_string();
        assert!(flags.contains("P"));
        assert!(flags.contains("T"));
        assert!(flags.contains("MP"));
    }

    #[test]
    fn test_gtpv2_display() {
        let packet = vec![
            0x48, 0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x42, 0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        let display = format!("{}", *header);
        assert!(display.contains("GTPv2-C"));
        assert!(display.contains("Create Session Request"));
    }

    #[test]
    fn test_gtpv2_header_opt_display() {
        let packet = vec![
            0x48, 0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x42, 0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("teid=0x00000001"));
        assert!(display.contains("seq=66"));
    }

    #[test]
    fn test_gtpv2_message_types() {
        assert_eq!(Gtpv2MessageType::from(1), Gtpv2MessageType::EchoRequest);
        assert_eq!(Gtpv2MessageType::from(2), Gtpv2MessageType::EchoResponse);
        assert_eq!(
            Gtpv2MessageType::from(32),
            Gtpv2MessageType::CreateSessionRequest
        );
        assert_eq!(
            Gtpv2MessageType::from(36),
            Gtpv2MessageType::DeleteSessionRequest
        );
        assert_eq!(Gtpv2MessageType::from(250), Gtpv2MessageType::Unknown);
    }

    #[test]
    fn test_gtpv2_port() {
        assert!(is_gtpv2_c_port(2123));
        assert!(!is_gtpv2_c_port(2152));
    }

    #[test]
    fn test_gtpv2_large_teid() {
        let packet = vec![
            0x48, 0x20, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, // TEID: max value
            0x00, 0x00, 0x01, 0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(header.teid(), Some(0xFFFFFFFF));
    }

    #[test]
    fn test_gtpv2_large_sequence() {
        let packet = vec![
            0x40, 0x01, 0x00, 0x04, 0xFF, 0xFF, 0xFF, // Sequence: max 24-bit value
            0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(header.sequence_number(), 0xFFFFFF);
    }

    #[test]
    fn test_gtpv2_delete_session() {
        let packet = vec![
            0x48, 0x24, // Delete Session Request
            0x00, 0x08, 0x00, 0x00, 0x00, 0x05, // TEID: 5
            0x00, 0x01, 0x00, 0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(
            header.message_type_enum(),
            Gtpv2MessageType::DeleteSessionRequest
        );
        assert_eq!(header.teid(), Some(5));
    }

    #[test]
    fn test_gtpv2_ie_iterator() {
        // Some IEs after header
        let ies = vec![
            // Recovery IE (type=3, length=1, instance=0, value=0)
            0x03, 0x00, 0x01, 0x00, 0x00,
            // Cause IE (type=2, length=2, instance=0, value=0x10, 0x00)
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
        ];

        let mut iter = Gtpv2IeIter::new(&ies);

        let ie1 = iter.next().unwrap();
        assert_eq!(ie1.ie_type, 3); // Recovery
        assert_eq!(ie1.instance, 0);
        assert_eq!(ie1.value, &[0x00]);

        let ie2 = iter.next().unwrap();
        assert_eq!(ie2.ie_type, 2); // Cause
        assert_eq!(ie2.instance, 0);
        assert_eq!(ie2.value, &[0x10, 0x00]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_gtpv2_ie_types() {
        assert_eq!(Gtpv2IeType::from(1), Gtpv2IeType::Imsi);
        assert_eq!(Gtpv2IeType::from(2), Gtpv2IeType::Cause);
        assert_eq!(Gtpv2IeType::from(87), Gtpv2IeType::FTeid);
        assert_eq!(Gtpv2IeType::from(200), Gtpv2IeType::Unknown);
    }

    #[test]
    fn test_gtpv2_ie_header() {
        let ie_data: [u8; 4] = [0x57, 0x00, 0x09, 0x01]; // F-TEID IE, length 9, instance 1

        let (ie_header_ref, _) =
            zerocopy::Ref::<_, Gtpv2IeHeader>::from_prefix(&ie_data[..]).unwrap();
        let ie_header = zerocopy::Ref::into_ref(ie_header_ref);
        assert_eq!(ie_header.ie_type(), 0x57);
        assert_eq!(ie_header.length(), 9);
        assert_eq!(ie_header.instance(), 1);
        assert_eq!(ie_header.spare(), 0);
        assert_eq!(ie_header.total_length(), 13);
    }

    #[test]
    fn test_gtpv2_modify_bearer() {
        let packet = vec![
            0x48, 0x22, // Modify Bearer Request
            0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(
            header.message_type_enum(),
            Gtpv2MessageType::ModifyBearerRequest
        );
    }

    #[test]
    fn test_gtpv2_version_not_supported() {
        let packet = vec![
            0x40, 0x03, // Version Not Supported Indication
            0x00, 0x04, 0x00, 0x00, 0x01, 0x00,
        ];

        let (header, _) = Gtpv2Header::from_bytes(&packet).unwrap();
        assert_eq!(
            header.message_type_enum(),
            Gtpv2MessageType::VersionNotSupportedIndication
        );
    }
}
