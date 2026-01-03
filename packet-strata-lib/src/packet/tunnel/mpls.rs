//! MPLS (Multiprotocol Label Switching) protocol parser
//!
//! This module implements parsing for MPLS as defined in RFC 3032.
//! MPLS uses a label stack where each label is 4 bytes.
//!
//! # MPLS Label Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                Label                  | TC  |S|       TTL     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - Label: 20 bits - Label value
//! - TC: 3 bits - Traffic Class (formerly EXP)
//! - S: 1 bit - Bottom of Stack flag (1 = last label)
//! - TTL: 8 bits - Time to Live
//!
//! # EtherTypes
//!
//! - MPLS Unicast: 0x8847
//! - MPLS Multicast: 0x8848
//!
//! # Examples
//!
//! ## Basic MPLS parsing (single label)
//!
//! ```
//! use packet_strata::packet::tunnel::mpls::MplsLabel;
//! use packet_strata::packet::HeaderParser;
//!
//! // Single MPLS label with bottom-of-stack set
//! let packet = vec![
//!     0x00, 0x01, 0x01, 0x40,  // Label=16, TC=0, S=1, TTL=64
//!     // Inner IP packet follows...
//!     0x45, 0x00, 0x00, 0x00,
//! ];
//!
//! let (label, payload) = MplsLabel::from_bytes(&packet).unwrap();
//! assert_eq!(label.label(), 16);
//! assert!(label.is_bottom_of_stack());
//! assert_eq!(label.ttl(), 64);
//! ```
//!
//! ## MPLS label stack iteration
//!
//! ```
//! use packet_strata::packet::tunnel::mpls::MplsLabelStackIter;
//!
//! // Two MPLS labels stacked
//! let packet = vec![
//!     0x00, 0x01, 0x00, 0x40,  // Label=16, TC=0, S=0, TTL=64
//!     0x00, 0x02, 0x01, 0x3F,  // Label=32, TC=0, S=1, TTL=63
//!     // Inner payload...
//!     0x45, 0x00, 0x00, 0x00,
//! ];
//!
//! let mut iter = MplsLabelStackIter::new(&packet);
//! let first = iter.next().unwrap();
//! assert_eq!(first.label(), 16);
//! assert!(!first.is_bottom_of_stack());
//!
//! let second = iter.next().unwrap();
//! assert_eq!(second.label(), 32);
//! assert!(second.is_bottom_of_stack());
//!
//! assert!(iter.next().is_none());
//! ```

use std::fmt::{self, Formatter};

use zerocopy::byteorder::{BigEndian, U32};
use zerocopy::{FromBytes, IntoBytes, Unaligned};

use crate::packet::{HeaderParser, PacketHeader};

/// MPLS Unicast EtherType
pub const MPLS_ETHERTYPE_UNICAST: u16 = 0x8847;

/// MPLS Multicast EtherType
pub const MPLS_ETHERTYPE_MULTICAST: u16 = 0x8848;

/// Check if EtherType is MPLS
#[inline]
pub fn is_mpls_ethertype(ethertype: u16) -> bool {
    ethertype == MPLS_ETHERTYPE_UNICAST || ethertype == MPLS_ETHERTYPE_MULTICAST
}

/// Reserved MPLS label values (0-15)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MplsReservedLabel {
    /// IPv4 Explicit NULL Label
    Ipv4ExplicitNull = 0,
    /// Router Alert Label
    RouterAlert = 1,
    /// IPv6 Explicit NULL Label
    Ipv6ExplicitNull = 2,
    /// Implicit NULL Label
    ImplicitNull = 3,
    /// Entropy Label Indicator
    EntropyLabelIndicator = 7,
    /// GAL (Generic Associated Channel Label)
    Gal = 13,
    /// OAM Alert Label
    OamAlert = 14,
    /// Extension Label
    Extension = 15,
}

impl MplsReservedLabel {
    /// Check if a label value is reserved (0-15)
    #[inline]
    pub fn is_reserved(label: u32) -> bool {
        label <= 15
    }

    /// Try to convert a label value to a reserved label
    pub fn from_label(label: u32) -> Option<Self> {
        match label {
            0 => Some(MplsReservedLabel::Ipv4ExplicitNull),
            1 => Some(MplsReservedLabel::RouterAlert),
            2 => Some(MplsReservedLabel::Ipv6ExplicitNull),
            3 => Some(MplsReservedLabel::ImplicitNull),
            7 => Some(MplsReservedLabel::EntropyLabelIndicator),
            13 => Some(MplsReservedLabel::Gal),
            14 => Some(MplsReservedLabel::OamAlert),
            15 => Some(MplsReservedLabel::Extension),
            _ => None,
        }
    }
}

impl fmt::Display for MplsReservedLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MplsReservedLabel::Ipv4ExplicitNull => write!(f, "IPv4 Explicit NULL"),
            MplsReservedLabel::RouterAlert => write!(f, "Router Alert"),
            MplsReservedLabel::Ipv6ExplicitNull => write!(f, "IPv6 Explicit NULL"),
            MplsReservedLabel::ImplicitNull => write!(f, "Implicit NULL"),
            MplsReservedLabel::EntropyLabelIndicator => write!(f, "Entropy Label Indicator"),
            MplsReservedLabel::Gal => write!(f, "GAL"),
            MplsReservedLabel::OamAlert => write!(f, "OAM Alert"),
            MplsReservedLabel::Extension => write!(f, "Extension"),
        }
    }
}

/// MPLS Label structure (4 bytes)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                Label                  | TC  |S|       TTL     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(
    FromBytes, IntoBytes, Unaligned, Debug, Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable,
)]
pub struct MplsLabel {
    label_tc_s_ttl: U32<BigEndian>,
}

impl MplsLabel {
    /// Label field mask (bits 0-19)
    pub const LABEL_MASK: u32 = 0xFFFFF000;
    pub const LABEL_SHIFT: u32 = 12;

    /// Traffic Class field mask (bits 20-22)
    pub const TC_MASK: u32 = 0x00000E00;
    pub const TC_SHIFT: u32 = 9;

    /// Bottom of Stack flag (bit 23)
    pub const BOS_MASK: u32 = 0x00000100;
    pub const BOS_SHIFT: u32 = 8;

    /// TTL field mask (bits 24-31)
    pub const TTL_MASK: u32 = 0x000000FF;

    /// Maximum label value (20 bits)
    pub const MAX_LABEL: u32 = 0xFFFFF;

    /// Maximum TC value (3 bits)
    pub const MAX_TC: u8 = 7;

    #[allow(unused)]
    const NAME: &'static str = "MplsLabel";

    /// Returns the raw 32-bit value
    #[inline]
    pub fn raw(&self) -> u32 {
        self.label_tc_s_ttl.get()
    }

    /// Returns the 20-bit label value
    #[inline]
    pub fn label(&self) -> u32 {
        (self.raw() & Self::LABEL_MASK) >> Self::LABEL_SHIFT
    }

    /// Returns the 3-bit Traffic Class (TC) value
    ///
    /// This was formerly called EXP (Experimental) bits.
    /// Used for QoS and ECN purposes.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.raw() & Self::TC_MASK) >> Self::TC_SHIFT) as u8
    }

    /// Alias for traffic_class() - returns the EXP bits
    #[inline]
    pub fn exp(&self) -> u8 {
        self.traffic_class()
    }

    /// Returns true if this is the bottom of the label stack (S=1)
    #[inline]
    pub fn is_bottom_of_stack(&self) -> bool {
        self.raw() & Self::BOS_MASK != 0
    }

    /// Returns the 8-bit TTL value
    #[inline]
    pub fn ttl(&self) -> u8 {
        (self.raw() & Self::TTL_MASK) as u8
    }

    /// Returns true if the label is a reserved label (0-15)
    #[inline]
    pub fn is_reserved(&self) -> bool {
        MplsReservedLabel::is_reserved(self.label())
    }

    /// Returns the reserved label type if this is a reserved label
    #[inline]
    pub fn reserved_label(&self) -> Option<MplsReservedLabel> {
        MplsReservedLabel::from_label(self.label())
    }

    /// Returns true if this is the IPv4 Explicit NULL label
    #[inline]
    pub fn is_ipv4_explicit_null(&self) -> bool {
        self.label() == 0
    }

    /// Returns true if this is the IPv6 Explicit NULL label
    #[inline]
    pub fn is_ipv6_explicit_null(&self) -> bool {
        self.label() == 2
    }

    /// Returns true if this is the Implicit NULL label
    #[inline]
    pub fn is_implicit_null(&self) -> bool {
        self.label() == 3
    }

    /// Returns true if this is the Router Alert label
    #[inline]
    pub fn is_router_alert(&self) -> bool {
        self.label() == 1
    }

    /// Validates the MPLS label
    ///
    /// MPLS labels are always valid structurally, but we check for
    /// reasonable TTL values.
    #[inline]
    fn is_valid(&self) -> bool {
        // All MPLS labels are structurally valid
        // TTL of 0 might indicate an expired packet, but it's still parseable
        true
    }
}

impl PacketHeader for MplsLabel {
    const NAME: &'static str = "MplsLabel";
    /// Inner type - we return the label value
    type InnerType = u32;

    #[inline]
    fn inner_type(&self) -> Self::InnerType {
        self.label()
    }

    /// Returns the total header length (always 4 bytes per label)
    #[inline]
    fn total_len(&self, _buf: &[u8]) -> usize {
        Self::FIXED_LEN // 4 bytes
    }

    /// Validates the MPLS label
    #[inline]
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

impl HeaderParser for MplsLabel {
    type Output<'a> = &'a MplsLabel;

    #[inline]
    fn into_view<'a>(header: &'a Self, _options: &'a [u8]) -> Self::Output<'a> {
        header
    }
}

impl fmt::Display for MplsLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MPLS label={} tc={} s={} ttl={}",
            self.label(),
            self.traffic_class(),
            if self.is_bottom_of_stack() { 1 } else { 0 },
            self.ttl()
        )?;

        if let Some(reserved) = self.reserved_label() {
            write!(f, " ({})", reserved)?;
        }

        Ok(())
    }
}

/// Iterator over MPLS label stack
///
/// Iterates through the MPLS label stack until it finds a label with
/// the Bottom of Stack (S) bit set.
pub struct MplsLabelStackIter<'a> {
    data: &'a [u8],
    finished: bool,
}

impl<'a> MplsLabelStackIter<'a> {
    /// Create a new label stack iterator
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            finished: false,
        }
    }

    /// Returns the remaining unparsed data
    ///
    /// This is useful for getting the payload after the label stack.
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }

    /// Parse the entire label stack and return the payload
    ///
    /// Consumes all labels until bottom of stack is found and returns
    /// the remaining data as payload.
    pub fn skip_to_payload(mut self) -> &'a [u8] {
        while self.next().is_some() {}
        self.data
    }

    /// Collect all labels into a Vec
    pub fn collect_labels(self) -> Vec<MplsLabel> {
        self.copied().collect()
    }
}

impl<'a> Iterator for MplsLabelStackIter<'a> {
    type Item = &'a MplsLabel;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.data.len() < 4 {
            return None;
        }

        // Parse the label using zerocopy
        let (label_ref, rest) = zerocopy::Ref::<_, MplsLabel>::from_prefix(self.data).ok()?;

        let label = zerocopy::Ref::into_ref(label_ref);

        // Check if this is the bottom of stack
        if label.is_bottom_of_stack() {
            self.finished = true;
        }

        self.data = rest;

        Some(label)
    }
}

/// MPLS Label Stack wrapper for full stack parsing
#[derive(Debug, Clone)]
pub struct MplsLabelStack<'a> {
    /// The raw label stack data
    pub data: &'a [u8],
    /// Number of labels in the stack
    pub count: usize,
    /// Total size of the label stack in bytes
    pub total_size: usize,
}

impl<'a> MplsLabelStack<'a> {
    /// Parse an MPLS label stack from a buffer
    ///
    /// Returns the label stack and the remaining payload.
    pub fn parse(data: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let mut offset = 0;
        let mut count = 0;

        loop {
            if data.len() < offset + 4 {
                return None; // Not enough data
            }

            let label_data = &data[offset..offset + 4];
            let raw =
                u32::from_be_bytes([label_data[0], label_data[1], label_data[2], label_data[3]]);

            count += 1;
            offset += 4;

            // Check bottom of stack
            if raw & MplsLabel::BOS_MASK != 0 {
                break;
            }

            // Safety limit to prevent infinite loops
            if count > 16 {
                return None;
            }
        }

        Some((
            MplsLabelStack {
                data: &data[..offset],
                count,
                total_size: offset,
            },
            &data[offset..],
        ))
    }

    /// Get an iterator over the labels in the stack
    pub fn iter(&self) -> MplsLabelStackIter<'a> {
        MplsLabelStackIter::new(self.data)
    }

    /// Get the first (outermost) label
    pub fn first(&self) -> Option<&'a MplsLabel> {
        self.iter().next()
    }

    /// Get the last (innermost) label
    pub fn last(&self) -> Option<&'a MplsLabel> {
        self.iter().last()
    }
}

impl<'a> IntoIterator for &'a MplsLabelStack<'a> {
    type Item = &'a MplsLabel;
    type IntoIter = MplsLabelStackIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Display for MplsLabelStack<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "MPLS[")?;
        let mut first = true;
        for label in self.iter() {
            if !first {
                write!(f, " -> ")?;
            }
            write!(f, "{}", label.label())?;
            first = false;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_label_size() {
        assert_eq!(std::mem::size_of::<MplsLabel>(), 4);
        assert_eq!(MplsLabel::FIXED_LEN, 4);
    }

    #[test]
    fn test_mpls_single_label() {
        // Label=16, TC=0, S=1, TTL=64
        let packet = vec![0x00, 0x01, 0x01, 0x40, 0x45, 0x00, 0x00, 0x00];

        let (label, payload) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.label(), 16);
        assert_eq!(label.traffic_class(), 0);
        assert!(label.is_bottom_of_stack());
        assert_eq!(label.ttl(), 64);
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_mpls_label_max_value() {
        // Label=0xFFFFF (max), TC=7, S=1, TTL=255
        let packet = vec![0xFF, 0xFF, 0xFF, 0xFF];

        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.label(), 0xFFFFF);
        assert_eq!(label.traffic_class(), 7);
        assert!(label.is_bottom_of_stack());
        assert_eq!(label.ttl(), 255);
    }

    #[test]
    fn test_mpls_label_zero() {
        // Label=0 (IPv4 Explicit NULL), TC=0, S=1, TTL=1
        let packet = vec![0x00, 0x00, 0x01, 0x01];

        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.label(), 0);
        assert!(label.is_ipv4_explicit_null());
        assert!(label.is_reserved());
        assert_eq!(
            label.reserved_label(),
            Some(MplsReservedLabel::Ipv4ExplicitNull)
        );
    }

    #[test]
    fn test_mpls_label_ipv6_explicit_null() {
        // Label=2 (IPv6 Explicit NULL), TC=0, S=1, TTL=64
        let packet = vec![0x00, 0x00, 0x21, 0x40];

        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.label(), 2);
        assert!(label.is_ipv6_explicit_null());
        assert!(label.is_reserved());
    }

    #[test]
    fn test_mpls_label_router_alert() {
        // Label=1 (Router Alert), TC=0, S=1, TTL=64
        let packet = vec![0x00, 0x00, 0x11, 0x40];

        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.label(), 1);
        assert!(label.is_router_alert());
    }

    #[test]
    fn test_mpls_label_implicit_null() {
        // Label=3 (Implicit NULL), TC=0, S=1, TTL=64
        let packet = vec![0x00, 0x00, 0x31, 0x40];

        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.label(), 3);
        assert!(label.is_implicit_null());
    }

    #[test]
    fn test_mpls_label_not_bos() {
        // Label=100, TC=3, S=0, TTL=128
        let packet = vec![0x00, 0x06, 0x46, 0x80];

        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.label(), 100);
        assert_eq!(label.traffic_class(), 3);
        assert!(!label.is_bottom_of_stack());
        assert_eq!(label.ttl(), 128);
    }

    #[test]
    fn test_mpls_label_stack_iterator() {
        // Two MPLS labels
        let packet = vec![
            0x00, 0x01, 0x00, 0x40, // Label=16, S=0
            0x00, 0x02, 0x01, 0x3F, // Label=32, S=1
            0x45, 0x00, 0x00, 0x00, // Payload
        ];

        let mut iter = MplsLabelStackIter::new(&packet);

        let first = iter.next().unwrap();
        assert_eq!(first.label(), 16);
        assert!(!first.is_bottom_of_stack());

        let second = iter.next().unwrap();
        assert_eq!(second.label(), 32);
        assert!(second.is_bottom_of_stack());

        assert!(iter.next().is_none());
        assert_eq!(iter.remaining().len(), 4);
    }

    #[test]
    fn test_mpls_label_stack_three_labels() {
        // Three MPLS labels
        let packet = vec![
            0x00, 0x00, 0xC0, 0x40, // Label=12, S=0
            0x00, 0x01, 0x80, 0x3F, // Label=24, S=0
            0x00, 0x02, 0x41, 0x3E, // Label=36, S=1
            0x45, 0x00, // Payload
        ];

        let mut iter = MplsLabelStackIter::new(&packet);

        let first = iter.next().unwrap();
        assert_eq!(first.label(), 12);
        assert!(!first.is_bottom_of_stack());

        let second = iter.next().unwrap();
        assert_eq!(second.label(), 24);
        assert!(!second.is_bottom_of_stack());

        let third = iter.next().unwrap();
        assert_eq!(third.label(), 36);
        assert!(third.is_bottom_of_stack());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_mpls_label_stack_skip_to_payload() {
        let packet = vec![
            0x00, 0x01, 0x00, 0x40, // Label=16, S=0
            0x00, 0x02, 0x01, 0x3F, // Label=32, S=1
            0x45, 0x00, 0x00, 0x14, // IPv4 header start
        ];

        let iter = MplsLabelStackIter::new(&packet);
        let payload = iter.skip_to_payload();
        assert_eq!(payload.len(), 4);
        assert_eq!(payload[0], 0x45); // IPv4 version
    }

    #[test]
    fn test_mpls_label_stack_collect() {
        let packet = vec![
            0x00, 0x01, 0x00, 0x40, // Label=16, S=0
            0x00, 0x02, 0x01, 0x3F, // Label=32, S=1
        ];

        let iter = MplsLabelStackIter::new(&packet);
        let labels: Vec<MplsLabel> = iter.collect_labels();

        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].label(), 16);
        assert_eq!(labels[1].label(), 32);
    }

    #[test]
    fn test_mpls_label_stack_parse() {
        let packet = vec![
            0x00, 0x01, 0x00, 0x40, // Label=16, S=0
            0x00, 0x02, 0x01, 0x3F, // Label=32, S=1
            0x45, 0x00, 0x00, 0x14,
        ];

        let (stack, payload) = MplsLabelStack::parse(&packet).unwrap();
        assert_eq!(stack.count, 2);
        assert_eq!(stack.total_size, 8);
        assert_eq!(payload.len(), 4);

        let first = stack.first().unwrap();
        assert_eq!(first.label(), 16);

        let last = stack.last().unwrap();
        assert_eq!(last.label(), 32);
    }

    #[test]
    fn test_mpls_label_stack_single() {
        let packet = vec![
            0x00, 0x01, 0x01, 0x40, // Label=16, S=1
            0x45, 0x00,
        ];

        let (stack, payload) = MplsLabelStack::parse(&packet).unwrap();
        assert_eq!(stack.count, 1);
        assert_eq!(stack.total_size, 4);
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn test_mpls_label_too_small() {
        let packet = vec![0x00, 0x01, 0x01]; // Only 3 bytes
        let result = MplsLabel::from_bytes(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_mpls_label_stack_empty() {
        let packet: Vec<u8> = vec![];
        let result = MplsLabelStack::parse(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_mpls_display() {
        let packet = vec![0x00, 0x01, 0x01, 0x40];
        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        let display = format!("{}", label);
        assert!(display.contains("label=16"));
        assert!(display.contains("ttl=64"));
    }

    #[test]
    fn test_mpls_display_reserved() {
        let packet = vec![0x00, 0x00, 0x01, 0x40]; // Label=0
        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        let display = format!("{}", label);
        assert!(display.contains("IPv4 Explicit NULL"));
    }

    #[test]
    fn test_mpls_label_stack_display() {
        let packet = vec![
            0x00, 0x01, 0x00, 0x40, // Label=16
            0x00, 0x02, 0x01, 0x3F, // Label=32
        ];

        let (stack, _) = MplsLabelStack::parse(&packet).unwrap();
        let display = format!("{}", stack);
        assert!(display.contains("MPLS["));
        assert!(display.contains("16"));
        assert!(display.contains("32"));
    }

    #[test]
    fn test_mpls_reserved_labels() {
        assert!(MplsReservedLabel::is_reserved(0));
        assert!(MplsReservedLabel::is_reserved(15));
        assert!(!MplsReservedLabel::is_reserved(16));

        assert_eq!(
            MplsReservedLabel::from_label(0),
            Some(MplsReservedLabel::Ipv4ExplicitNull)
        );
        assert_eq!(
            MplsReservedLabel::from_label(1),
            Some(MplsReservedLabel::RouterAlert)
        );
        assert_eq!(
            MplsReservedLabel::from_label(13),
            Some(MplsReservedLabel::Gal)
        );
        assert_eq!(MplsReservedLabel::from_label(16), None);
    }

    #[test]
    fn test_mpls_exp_alias() {
        let packet = vec![0x00, 0x06, 0x47, 0x40]; // TC=3
        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.exp(), label.traffic_class());
        assert_eq!(label.exp(), 3);
    }

    #[test]
    fn test_mpls_ethertype() {
        assert!(is_mpls_ethertype(0x8847));
        assert!(is_mpls_ethertype(0x8848));
        assert!(!is_mpls_ethertype(0x0800));
    }

    #[test]
    fn test_mpls_inner_type() {
        let packet = vec![0x00, 0x10, 0x01, 0x40]; // Label=256
        let (label, _) = MplsLabel::from_bytes(&packet).unwrap();
        assert_eq!(label.inner_type(), 256);
    }

    #[test]
    fn test_mpls_label_into_iter() {
        let packet = vec![0x00, 0x01, 0x00, 0x40, 0x00, 0x02, 0x01, 0x3F];

        let (stack, _) = MplsLabelStack::parse(&packet).unwrap();
        let labels: Vec<u32> = (&stack).into_iter().map(|l| l.label()).collect();
        assert_eq!(labels, vec![16, 32]);
    }
}
