//! STT (Stateless Transport Tunneling) protocol parser
//!
//! This module implements parsing for STT as defined in the VMware STT specification
//! (draft-davie-stt). STT is a tunneling protocol that encapsulates L2 frames using
//! a TCP-like header format for NIC offload compatibility.
//!
//! # STT Header Format
//!
//! STT uses a pseudo-TCP header followed by an STT-specific header:
//!
//! ```text
//! TCP-like header (20 bytes):
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Acknowledgment Number                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Data |           |U|A|P|R|S|F|                               |
//! | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//! |       |           |G|K|H|T|N|N|                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |         Urgent Pointer        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! STT Frame Header (18 bytes):
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Version      | Flags         |  L4 Offset    |  Reserved     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Max Segment Size           |       PCP |V|     VLAN ID     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                       Context ID (64 bits)                    +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Padding   |    Padding    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Ports
//!
//! - STT default port: TCP port 7471
//!
//! # Examples
//!
//! ## Basic STT parsing
//!
//! ```
//! use packet_strata::packet::tunnel::stt::SttHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // STT frame header
//! let packet = vec![
//!     0x00,        // Version: 0
//!     0x00,        // Flags: 0
//!     0x00,        // L4 Offset: 0
//!     0x00,        // Reserved
//!     0x05, 0xDC,  // MSS: 1500
//!     0x00, 0x64,  // VLAN (V=0, VID=100)
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  // Context ID: 1
//!     0x00, 0x00,  // Padding
//!     // Inner Ethernet frame follows...
//! ];
//!
//! let (header, payload) = SttHeader::from_bytes(&packet).unwrap();
//! assert_eq!(header.version(), 0);
//! assert_eq!(header.mss(), 1500);
//! assert_eq!(header.context_id(), 1);
//! ```
//!
//! ## STT with VLAN tag
//!
//! ```
//! use packet_strata::packet::tunnel::stt::SttHeader;
//! use packet_strata::packet::HeaderParser;
//!
//! // STT with VLAN tag present
//! let packet = vec![
//!     0x00,        // Version: 0
//!     0x00,        // Flags
//!     0x00,        // L4 Offset
//!     0x00,        // Reserved
//!     0x05, 0xDC,  // MSS: 1500
//!     0x10, 0x64,  // PCP=0, V=1, VID=100
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A,  // Context ID: 10
//!     0x00, 0x00,  // Padding
//! ];
//!
//! let (header, _) = SttHeader::from_bytes(&packet).unwrap();
//! assert!(header.has_vlan());
//! assert_eq!(header.vlan_id(), Some(100));
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U16, U64};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::{HeaderParser, PacketHeader};

/// STT default TCP port
pub const STT_PORT: u16 = 7471;

/// Check if port is STT
#[inline]
pub fn is_stt_port(port: u16) -> bool {
    port == STT_PORT
}

/// STT Version
pub const STT_VERSION: u8 = 0;

/// STT Flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SttFlags(pub u8);

impl SttFlags {
    /// Checksum verified flag
    pub const CSUM_VERIFIED: u8 = 0x01;
    /// Checksum partial flag (indicates partial checksum in payload)
    pub const CSUM_PARTIAL: u8 = 0x02;
    /// IPv4 payload
    pub const IPV4: u8 = 0x04;
    /// TCP payload
    pub const TCP: u8 = 0x08;
    /// Checksum present in inner header
    pub const CSUM_PRESENT: u8 = 0x10;

    /// Create new flags
    #[inline]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Check if checksum verified flag is set
    #[inline]
    pub fn is_csum_verified(&self) -> bool {
        self.0 & Self::CSUM_VERIFIED != 0
    }

    /// Check if checksum partial flag is set
    #[inline]
    pub fn is_csum_partial(&self) -> bool {
        self.0 & Self::CSUM_PARTIAL != 0
    }

    /// Check if IPv4 flag is set
    #[inline]
    pub fn is_ipv4(&self) -> bool {
        self.0 & Self::IPV4 != 0
    }

    /// Check if TCP flag is set
    #[inline]
    pub fn is_tcp(&self) -> bool {
        self.0 & Self::TCP != 0
    }

    /// Check if checksum present flag is set
    #[inline]
    pub fn is_csum_present(&self) -> bool {
        self.0 & Self::CSUM_PRESENT != 0
    }
}

impl fmt::Display for SttFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();

        if self.is_csum_verified() {
            flags.push("CSUM_VERIFIED");
        }
        if self.is_csum_partial() {
            flags.push("CSUM_PARTIAL");
        }
        if self.is_ipv4() {
            flags.push("IPV4");
        }
        if self.is_tcp() {
            flags.push("TCP");
        }
        if self.is_csum_present() {
            flags.push("CSUM_PRESENT");
        }

        if flags.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", flags.join(","))
        }
    }
}

/// STT Frame Header structure (18 bytes)
///
/// This is the STT-specific header that follows the TCP-like header.
/// The TCP-like header is handled separately as it resembles a standard TCP header.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct SttHeader {
    version: u8,
    flags: u8,
    l4_offset: u8,
    reserved: u8,
    mss: U16<BigEndian>,
    vlan_tci: U16<BigEndian>,
    context_id: U64<BigEndian>,
    padding: U16<BigEndian>,
}

impl SttHeader {
    /// VLAN present flag in vlan_tci (bit 12)
    pub const VLAN_PRESENT: u16 = 0x1000;

    /// VLAN ID mask (bits 0-11)
    pub const VLAN_ID_MASK: u16 = 0x0FFF;

    /// PCP mask (bits 13-15)
    pub const PCP_MASK: u16 = 0xE000;
    pub const PCP_SHIFT: u16 = 13;

    /// Header size
    pub const HEADER_SIZE: usize = 18;

    #[allow(unused)]
    const NAME: &'static str = "SttHeader";

    /// Returns the STT version (should be 0)
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the flags byte
    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    /// Returns the flags as SttFlags struct
    #[inline]
    pub fn flags(&self) -> SttFlags {
        SttFlags::new(self.flags)
    }

    /// Returns the L4 offset (offset to L4 header in inner packet)
    ///
    /// This is the offset from the start of the inner Ethernet frame
    /// to the start of the L4 (TCP/UDP) header, in 2-byte units.
    #[inline]
    pub fn l4_offset(&self) -> u8 {
        self.l4_offset
    }

    /// Returns the L4 offset in bytes
    #[inline]
    pub fn l4_offset_bytes(&self) -> usize {
        self.l4_offset as usize * 2
    }

    /// Returns the Maximum Segment Size (MSS)
    #[inline]
    pub fn mss(&self) -> u16 {
        self.mss.get()
    }

    /// Returns the raw VLAN TCI field
    #[inline]
    pub fn vlan_tci_raw(&self) -> u16 {
        self.vlan_tci.get()
    }

    /// Returns true if VLAN is present
    #[inline]
    pub fn has_vlan(&self) -> bool {
        self.vlan_tci.get() & Self::VLAN_PRESENT != 0
    }

    /// Returns the VLAN ID if present
    #[inline]
    pub fn vlan_id(&self) -> Option<u16> {
        if self.has_vlan() {
            Some(self.vlan_tci.get() & Self::VLAN_ID_MASK)
        } else {
            None
        }
    }

    /// Returns the PCP (Priority Code Point) value
    #[inline]
    pub fn pcp(&self) -> u8 {
        ((self.vlan_tci.get() & Self::PCP_MASK) >> Self::PCP_SHIFT) as u8
    }

    /// Returns the 64-bit Context ID (virtual network identifier)
    #[inline]
    pub fn context_id(&self) -> u64 {
        self.context_id.get()
    }

    /// Validates the STT header
    #[inline]
    fn is_valid(&self) -> bool {
        // Version should be 0
        self.version == STT_VERSION
    }
}

impl PacketHeader for SttHeader {
    const NAME: &'static str = "SttHeader";
    /// Inner type - context ID
    type InnerType = u64;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.context_id()
    }

    /// Returns the total header length (always 18 bytes)
    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::HEADER_SIZE
    }

    /// Validates the STT header
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for SttHeader {
    type Output<'a> = &'a SttHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for SttHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "STT v{} ctx=0x{:016x} mss={} flags=[{}]",
            self.version(),
            self.context_id(),
            self.mss(),
            self.flags()
        )?;

        if let Some(vid) = self.vlan_id() {
            write!(f, " vlan={}", vid)?;
        }

        Ok(())
    }
}

/// STT TCP-like header (pseudo-TCP header used for offloading)
///
/// This header precedes the STT frame header and is designed to
/// leverage NIC TCP segmentation offload (TSO) capabilities.
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct SttTcpHeader {
    src_port: U16<BigEndian>,
    dst_port: U16<BigEndian>,
    seq: [u8; 4], // Used for fragmentation
    ack: [u8; 4], // Used for fragmentation
    data_offset_flags: U16<BigEndian>,
    window: U16<BigEndian>,
    checksum: U16<BigEndian>,
    urgent: U16<BigEndian>,
}

impl SttTcpHeader {
    /// STT TCP header size
    pub const HEADER_SIZE: usize = 20;

    /// Returns the source port
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.src_port.get()
    }

    /// Returns the destination port (should be 7471 for STT)
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.dst_port.get()
    }

    /// Returns the sequence number (used for fragmentation info)
    ///
    /// In STT, this contains fragmentation offset information.
    #[inline]
    pub fn sequence(&self) -> u32 {
        u32::from_be_bytes(self.seq)
    }

    /// Returns the acknowledgment number
    ///
    /// In STT, this contains fragment ID and fragmentation info.
    #[inline]
    pub fn acknowledgment(&self) -> u32 {
        u32::from_be_bytes(self.ack)
    }

    /// Returns the data offset (in 32-bit words)
    #[inline]
    pub fn data_offset(&self) -> u8 {
        ((self.data_offset_flags.get() >> 12) & 0x0F) as u8
    }

    /// Returns the data offset in bytes
    #[inline]
    pub fn data_offset_bytes(&self) -> usize {
        self.data_offset() as usize * 4
    }

    /// Returns the TCP flags
    #[inline]
    pub fn tcp_flags(&self) -> u8 {
        (self.data_offset_flags.get() & 0x003F) as u8
    }

    /// Returns the window size
    #[inline]
    pub fn window(&self) -> u16 {
        self.window.get()
    }

    /// Returns the checksum
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum.get()
    }

    /// Returns the urgent pointer
    #[inline]
    pub fn urgent(&self) -> u16 {
        self.urgent.get()
    }

    /// Check if this is an STT packet (destination port is 7471)
    #[inline]
    pub fn is_stt(&self) -> bool {
        self.dst_port() == STT_PORT
    }

    /// Extract fragment offset from sequence number
    ///
    /// The fragment offset is stored in the sequence number field
    /// and represents the byte offset within the original frame.
    #[inline]
    pub fn fragment_offset(&self) -> u32 {
        self.sequence()
    }

    /// Extract total frame length from acknowledgment number
    ///
    /// The total frame length is stored in bits 16-31 of the ack field.
    #[inline]
    pub fn total_length(&self) -> u16 {
        (self.acknowledgment() >> 16) as u16
    }

    /// Extract fragment ID from acknowledgment number
    ///
    /// The fragment ID is stored in bits 0-15 of the ack field.
    #[inline]
    pub fn fragment_id(&self) -> u16 {
        (self.acknowledgment() & 0xFFFF) as u16
    }
}

impl PacketHeader for SttTcpHeader {
    const NAME: &'static str = "SttTcpHeader";
    type InnerType = u16;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.dst_port()
    }

    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::HEADER_SIZE
    }

    #[inline]
    fn is_valid(&self) -> bool {
        // Data offset must be at least 5 (20 bytes)
        self.data_offset() >= 5
    }
}

impl HeaderParser for SttTcpHeader {
    type Output<'a> = &'a SttTcpHeader;

    #[inline]
    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for SttTcpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "STT-TCP {}:{} frag_id={} frag_off={} total_len={}",
            self.src_port(),
            self.dst_port(),
            self.fragment_id(),
            self.fragment_offset(),
            self.total_length()
        )
    }
}

/// Complete STT packet (TCP-like header + STT header)
#[derive(Debug, Clone)]
pub struct SttPacket<'a> {
    /// The TCP-like header
    pub tcp_header: &'a SttTcpHeader,
    /// The STT frame header
    pub stt_header: &'a SttHeader,
    /// The inner payload (Ethernet frame)
    pub payload: &'a [u8],
}

impl<'a> SttPacket<'a> {
    /// Parse a complete STT packet from buffer
    ///
    /// Expects the buffer to start with the TCP-like header, followed by
    /// the STT frame header, and then the inner Ethernet frame.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < SttTcpHeader::HEADER_SIZE + SttHeader::HEADER_SIZE {
            return None;
        }

        let (tcp_ref, rest) = zerocopy::Ref::<_, SttTcpHeader>::from_prefix(buf).ok()?;
        let tcp_header = zerocopy::Ref::into_ref(tcp_ref);

        let (stt_ref, payload) = zerocopy::Ref::<_, SttHeader>::from_prefix(rest).ok()?;
        let stt_header = zerocopy::Ref::into_ref(stt_ref);

        // Validate
        if stt_header.version() != STT_VERSION {
            return None;
        }

        Some(SttPacket {
            tcp_header,
            stt_header,
            payload,
        })
    }

    /// Returns the context ID (virtual network identifier)
    #[inline]
    pub fn context_id(&self) -> u64 {
        self.stt_header.context_id()
    }

    /// Returns the VLAN ID if present
    #[inline]
    pub fn vlan_id(&self) -> Option<u16> {
        self.stt_header.vlan_id()
    }

    /// Returns true if this is a fragmented packet
    #[inline]
    pub fn is_fragmented(&self) -> bool {
        self.tcp_header.fragment_offset() != 0
            || self.payload.len() < self.tcp_header.total_length() as usize
    }

    /// Returns the total combined header length
    #[inline]
    pub fn header_length(&self) -> usize {
        SttTcpHeader::HEADER_SIZE + SttHeader::HEADER_SIZE
    }
}

impl fmt::Display for SttPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "STT ctx=0x{:016x} mss={} frag_id={}",
            self.stt_header.context_id(),
            self.stt_header.mss(),
            self.tcp_header.fragment_id()
        )?;

        if let Some(vid) = self.vlan_id() {
            write!(f, " vlan={}", vid)?;
        }

        if self.is_fragmented() {
            write!(
                f,
                " frag_off={} total={}",
                self.tcp_header.fragment_offset(),
                self.tcp_header.total_length()
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stt_header_size() {
        assert_eq!(std::mem::size_of::<SttHeader>(), 18);
        assert_eq!(SttHeader::FIXED_LEN, 18);
        assert_eq!(std::mem::size_of::<SttTcpHeader>(), 20);
        assert_eq!(SttTcpHeader::FIXED_LEN, 20);
    }

    #[test]
    fn test_stt_header_basic() {
        let packet = vec![
            0x00, // Version: 0
            0x00, // Flags: 0
            0x00, // L4 Offset: 0
            0x00, // Reserved
            0x05, 0xDC, // MSS: 1500
            0x00, 0x00, // VLAN (V=0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Context ID: 1
            0x00, 0x00, // Padding
            // Payload
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let (header, payload) = SttHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.version(), 0);
        assert_eq!(header.flags_raw(), 0);
        assert_eq!(header.l4_offset(), 0);
        assert_eq!(header.mss(), 1500);
        assert!(!header.has_vlan());
        assert_eq!(header.vlan_id(), None);
        assert_eq!(header.context_id(), 1);
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_stt_header_with_vlan() {
        let packet = vec![
            0x00, // Version
            0x00, // Flags
            0x00, // L4 Offset
            0x00, // Reserved
            0x05, 0xDC, // MSS: 1500
            0x10, 0x64, // VLAN: V=1, VID=100
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, // Context ID: 10
            0x00, 0x00, // Padding
        ];

        let (header, _) = SttHeader::from_bytes(&packet).unwrap();
        assert!(header.has_vlan());
        assert_eq!(header.vlan_id(), Some(100));
        assert_eq!(header.context_id(), 10);
    }

    #[test]
    fn test_stt_header_with_pcp() {
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, 0xF0, 0x64, // PCP=7, V=1, VID=100
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];

        let (header, _) = SttHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.pcp(), 7);
        assert!(header.has_vlan());
        assert_eq!(header.vlan_id(), Some(100));
    }

    #[test]
    fn test_stt_header_flags() {
        let packet = vec![
            0x00, 0x1F, // All flags set
            0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00,
        ];

        let (header, _) = SttHeader::from_bytes(&packet).unwrap();
        let flags = header.flags();
        assert!(flags.is_csum_verified());
        assert!(flags.is_csum_partial());
        assert!(flags.is_ipv4());
        assert!(flags.is_tcp());
        assert!(flags.is_csum_present());
    }

    #[test]
    fn test_stt_header_l4_offset() {
        let packet = vec![
            0x00, 0x00, 0x0A, // L4 Offset: 10 (20 bytes)
            0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00,
        ];

        let (header, _) = SttHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.l4_offset(), 10);
        assert_eq!(header.l4_offset_bytes(), 20);
    }

    #[test]
    fn test_stt_header_large_context_id() {
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, // Max context ID
            0x00, 0x00,
        ];

        let (header, _) = SttHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.context_id(), u64::MAX);
    }

    #[test]
    fn test_stt_header_invalid_version() {
        let packet = vec![
            0x01, // Version: 1 (invalid)
            0x00, 0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00,
        ];

        let result = SttHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_stt_header_too_small() {
        let packet = vec![0x00, 0x00, 0x00, 0x00]; // Only 4 bytes
        let result = SttHeader::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_stt_header_display() {
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, 0x10, 0x64, // VLAN=100
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];

        let (header, _) = SttHeader::from_bytes(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("STT"));
        assert!(display.contains("ctx="));
        assert!(display.contains("vlan=100"));
    }

    #[test]
    fn test_stt_flags_display() {
        let flags = SttFlags::new(0x1F);
        let display = format!("{}", flags);
        assert!(display.contains("CSUM_VERIFIED"));
        assert!(display.contains("IPV4"));
        assert!(display.contains("TCP"));

        let empty_flags = SttFlags::new(0);
        assert_eq!(format!("{}", empty_flags), "none");
    }

    #[test]
    fn test_stt_tcp_header_basic() {
        let packet = vec![
            0x12, 0x34, // Src port: 0x1234
            0x1D, 0x2F, // Dst port: 7471 (STT)
            0x00, 0x00, 0x00, 0x00, // Sequence (frag offset)
            0x05, 0xDC, 0x00, 0x01, // Ack: total_len=1500, frag_id=1
            0x50, 0x00, // Data offset=5, flags=0
            0x00, 0x00, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent
        ];

        let (header, _) = SttTcpHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.src_port(), 0x1234);
        assert_eq!(header.dst_port(), STT_PORT);
        assert!(header.is_stt());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.total_length(), 1500);
        assert_eq!(header.fragment_id(), 1);
        assert_eq!(header.data_offset(), 5);
        assert_eq!(header.data_offset_bytes(), 20);
    }

    #[test]
    fn test_stt_tcp_header_with_fragment() {
        let packet = vec![
            0x12, 0x34, 0x1D, 0x2F, 0x00, 0x00, 0x10, 0x00, // Frag offset: 4096
            0x05, 0xDC, 0x00, 0x02, // total_len=1500, frag_id=2
            0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (header, _) = SttTcpHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.fragment_offset(), 4096);
        assert_eq!(header.fragment_id(), 2);
        assert_eq!(header.total_length(), 1500);
    }

    #[test]
    fn test_stt_tcp_header_display() {
        let packet = vec![
            0x12, 0x34, 0x1D, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, 0x00, 0x01, 0x50, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (header, _) = SttTcpHeader::from_bytes(&packet).unwrap();
        let display = format!("{}", header);
        assert!(display.contains("STT-TCP"));
        assert!(display.contains("7471"));
    }

    #[test]
    fn test_stt_packet_parse() {
        let packet = vec![
            // TCP-like header (20 bytes)
            0x12, 0x34, // Src port
            0x1D, 0x2F, // Dst port: 7471
            0x00, 0x00, 0x00, 0x00, // Sequence
            0x00, 0x1C, 0x00, 0x01, // Ack: total_len=28, frag_id=1
            0x50, 0x00, // Data offset=5
            0x00, 0x00, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent
            // STT header (18 bytes)
            0x00, // Version
            0x04, // Flags: IPv4
            0x00, // L4 Offset
            0x00, // Reserved
            0x05, 0xDC, // MSS: 1500
            0x10, 0x64, // VLAN: V=1, VID=100
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, // Context ID: 10
            0x00, 0x00, // Padding
            // Payload
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dst MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Src MAC
        ];

        let stt_packet = SttPacket::parse(&packet).unwrap();
        assert_eq!(stt_packet.context_id(), 10);
        assert_eq!(stt_packet.vlan_id(), Some(100));
        assert!(stt_packet.stt_header.flags().is_ipv4());
        assert_eq!(stt_packet.header_length(), 38);
        assert_eq!(stt_packet.payload.len(), 12);
    }

    #[test]
    fn test_stt_packet_fragmented() {
        let packet = vec![
            // TCP-like header with fragment offset
            0x12, 0x34, 0x1D, 0x2F, 0x00, 0x00, 0x10, 0x00, // frag offset != 0
            0x10, 0x00, 0x00, 0x01, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // STT header
            0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00,
        ];

        let stt_packet = SttPacket::parse(&packet).unwrap();
        assert!(stt_packet.is_fragmented());
    }

    #[test]
    fn test_stt_packet_too_small() {
        let packet = vec![0x00; 30]; // Less than 38 bytes
        let result = SttPacket::parse(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_stt_packet_display() {
        let packet = vec![
            0x12, 0x34, 0x1D, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x50, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, 0x10, 0x64,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00,
        ];

        let stt_packet = SttPacket::parse(&packet).unwrap();
        let display = format!("{}", stt_packet);
        assert!(display.contains("STT"));
        assert!(display.contains("ctx="));
        assert!(display.contains("vlan=100"));
    }

    #[test]
    fn test_stt_port() {
        assert!(is_stt_port(7471));
        assert!(!is_stt_port(7472));
        assert!(!is_stt_port(4789));
    }

    #[test]
    fn test_stt_inner_type() {
        let packet = vec![
            0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
            0x56, 0x78, // Context ID
            0x00, 0x00,
        ];

        let (header, _) = SttHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.inner_type(), 0x12345678);
    }
}
