//! Bidirectional flow state, metrics, and TCP/IP tracking
//!
//! This module defines [`Flow<T, D>`] and its constituent sub-structures:
//! - [`FlowBase<T>`]: Core protocol-agnostic and L3/L4 flow metadata:
//!   - [`FlowId<T>`]: Canonical flow tuple (`T`, oriented from client to server), Ethernet protocol, and MAC addresses.
//!   - [`FlowTiming`]: First-seen (`start`) and last-seen (`last`) [`Timestamp`]s.
//!   - [`IpState`]: IPv4 IP-ID sequence tracking and estimated packet loss (`u_lost`, `d_lost`).
//!   - [`TcpState`]: TCP connection state machine ([`TcpStatus`]), sequence numbers (`u_seq`, `d_seq`), and 3-way handshake RTT decomposition (`rtt`, `rtt_net`, `rtt_user`).
//!   - [`Confidence`]: Two-level confidence (`Low` or `High`) in the flow's current client-server orientation.
//!   - [`FlowMetrics`]: Bidirectional packet, byte, payload, and IPv4 fragmentation counters (`u_*` for uplink, `d_*` for downlink).
//! - `data: D`: Custom user-defined per-flow state implementing [`Process`].
//!
//! # Examples
//!
//! ## Creating, Updating, and Flipping a Flow
//!
//! ```
//! use packet_strata::metadata::PacketMetadata;
//! use packet_strata::packet::iter::LinkType;
//! use packet_strata::packet::{Packet, ParseMode};
//! use packet_strata::timestamp::Timestamp;
//! use packet_strata::tracker::direction::{Confidence, PacketDirection};
//! use packet_strata::tracker::flow::{Flow, FlowIpV4};
//! use packet_strata::tracker::tuple::TupleV4;
//! use packet_strata::tracker::vni::VniMapper;
//!
//! struct Meta<'a> {
//!     ts: Timestamp,
//!     raw: &'a [u8],
//! }
//! impl PacketMetadata for Meta<'_> {
//!     fn timestamp(&self) -> Timestamp { self.ts }
//!     fn caplen(&self) -> u32 { self.raw.len() as u32 }
//!     fn origlen(&self) -> u32 { self.raw.len() as u32 }
//!     fn data(&self) -> &[u8] { self.raw }
//! }
//!
//! // Ethernet + IPv4 + TCP SYN packet (10.0.0.1:50000 -> 10.0.0.2:443)
//! let raw_syn = [
//!     0x00, 0x00, 0x0c, 0x33, 0x44, 0x55,
//!     0x00, 0x00, 0x00, 0x99, 0xaa, 0xbb,
//!     0x08, 0x00,
//!     0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
//!     10, 0, 0, 1,
//!     10, 0, 0, 2,
//!     0xc3, 0x50, 0x01, 0xbb,             // 50000 -> 443
//!     0x00, 0x00, 0x03, 0xe8,             // Seq: 1000
//!     0x00, 0x00, 0x00, 0x00,             // Ack: 0
//!     0x50, 0x02, 0xff, 0xff,             // Flags: SYN (0x02)
//!     0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let mut vni = VniMapper::new();
//! let pkt = Packet::from_bytes(&raw_syn, LinkType::Ethernet, ParseMode::Innermost).unwrap();
//! let tuple = TupleV4::new(&pkt, &mut vni).unwrap();
//!
//! // Phase 1: Create and update flow
//! let mut flow: FlowIpV4<()> = Flow::new(Timestamp::from_nanos(1_000_000_000), tuple, &pkt);
//! let dir = flow.update(&Meta { ts: Timestamp::from_nanos(1_000_000_000), raw: &raw_syn }, &pkt);
//!
//! assert_eq!(dir, PacketDirection::Upwards);
//! assert_eq!(flow.base.confidence, Confidence::High);
//! assert_eq!(flow.base.metrics.u_pkts, 1);
//! assert_eq!(flow.base.tcp.u_seq, 1000);
//! ```

use serde::{Deserialize, Serialize};

use crate::{
    metadata::PacketMetadata,
    packet::{
        ether::EthAddr,
        header::{NetworkLayer, TransportLayer},
        protocol::EtherProto,
        Packet,
    },
    timestamp::{Interval, Timestamp},
    tracker::{
        direction::{Confidence, PacketDirection},
        process::Process,
        tuple::Tuple,
        Trackable,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpStatus {
    #[default]
    /// Initial state, or when tracking metadata is evicted/expired.
    Closed,

    /// Client sent SYN, waiting for SYN-ACK.
    SynSent,

    /// Server sent SYN-ACK.
    SynReceived,

    /// Handshake completed (ACK received).
    Established,

    /// One side sent a FIN.
    FinWait,

    /// The other side acknowledged the FIN.
    CloseWait,

    /// Simultaneous close or final stages of termination.
    Closing,

    /// Connection reset via RST flag.
    Reset,
}

impl TcpStatus {
    #[inline(always)]
    #[must_use]
    pub fn is_established(self) -> bool {
        matches!(self, TcpStatus::Established)
    }

    #[inline(always)]
    #[must_use]
    pub fn is_close_in_progress(self) -> bool {
        matches!(self, TcpStatus::FinWait)
            || matches!(self, TcpStatus::CloseWait)
            || matches!(self, TcpStatus::Closing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlowId<T> {
    /// Generic address tuple (e.g. TupleV4, TupleV6 or TupleEth)
    pub tuple: T,
    /// Ethernet protocol.
    pub eth_proto: EtherProto,
    /// Source MAC address.
    pub src_mac: EthAddr,
    /// Destination MAC address.
    pub dst_mac: EthAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlowTiming {
    /// Timestamp of the first packet in the flow.
    pub start: Timestamp,
    /// Timestamp of the last packet in the flow.
    pub last: Timestamp,
}

/// ICMP/ICMPv6 error message correlated to a flow via the inner IP/L4 header in the ICMP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpError {
    /// ICMPv4 error message (`icmp_type`, `code`).
    V4 { icmp_type: u8, code: u8 },
    /// ICMPv6 error message (`icmp_type`, `code`).
    V6 { icmp_type: u8, code: u8 },
}

impl IcmpError {
    /// Returns the `(icmp_type, code)` pair regardless of IP version.
    #[inline(always)]
    pub const fn into_parts(self) -> (u8, u8) {
        match self {
            Self::V4 { icmp_type, code } | Self::V6 { icmp_type, code } => (icmp_type, code),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IpState {
    /// Uplink IP identification.
    pub u_id: Option<u16>,
    /// Downlink IP identification.
    pub d_id: Option<u16>,
    /// Uplink packets lost.
    pub u_lost: u32,
    /// Downlink packets lost.
    pub d_lost: u32,
    /// Last ICMP/ICMPv6 error message correlated to this flow (if any).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub icmp_error: Option<IcmpError>,
}

impl IpState {
    #[inline(always)]
    pub fn update(&mut self, pkt: &Packet<'_>, dir: PacketDirection) {
        if let Some(NetworkLayer::Ipv4(h)) = pkt.network() {
            if !h.has_dont_fragment() {
                let id = h.header.id();
                let (last_id, lost) = match dir {
                    PacketDirection::Upwards => (&mut self.u_id, &mut self.u_lost),
                    PacketDirection::Downwards => (&mut self.d_id, &mut self.d_lost),
                };

                if let Some(prev) = *last_id {
                    let delta = id.wrapping_sub(prev);
                    if delta > 0 && delta < 128 {
                        *lost += (delta - 1) as u32;
                    }
                }
                *last_id = Some(id);
            }
        }
    }

    /// Swaps uplink and downlink IP state counters.
    #[inline]
    pub fn swap_directions(&mut self) {
        std::mem::swap(&mut self.u_id, &mut self.d_id);
        std::mem::swap(&mut self.u_lost, &mut self.d_lost);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpState {
    /// Timestamp of the initial SYN packet.
    pub ts_syn: Timestamp,
    /// Timestamp of the SYN-ACK packet.
    pub ts_syn_ack: Timestamp,
    /// Timestamp of the ACK packet completing the handshake.
    pub ts_ack: Timestamp,
    /// Round-trip time.
    pub rtt: Interval,
    /// Network component of the RTT.
    pub rtt_net: Interval,
    /// User/Application component of the RTT.
    pub rtt_user: Interval,
    /// Uplink sequence number.
    pub u_seq: u32,
    /// Downlink sequence number.
    pub d_seq: u32,
    /// Current TCP status.
    pub status: TcpStatus,
}

impl TcpState {
    #[inline(always)]
    pub fn update<Meta: PacketMetadata>(
        &mut self,
        pkt: &Packet<'_>,
        dir: PacketDirection,
        meta: &Meta,
        metrics: &FlowMetrics,
    ) {
        self.update_with_ts(pkt, dir, meta.timestamp(), metrics);
    }

    #[inline(always)]
    fn update_with_ts(
        &mut self,
        pkt: &Packet<'_>,
        dir: PacketDirection,
        ts: Timestamp,
        metrics: &FlowMetrics,
    ) {
        if let Some(TransportLayer::Tcp(hdr)) = pkt.transport() {
            match dir {
                PacketDirection::Upwards => self.u_seq = hdr.sequence_number(),
                PacketDirection::Downwards => self.d_seq = hdr.sequence_number(),
            }

            if hdr.has_rst() {
                // R
                self.status = TcpStatus::Reset;
            } else if hdr.has_fin() {
                // F
                if self.status < TcpStatus::FinWait {
                    self.status = TcpStatus::FinWait;
                } else if self.status == TcpStatus::FinWait || self.status == TcpStatus::CloseWait {
                    self.status = TcpStatus::Closing;
                }
            } else if hdr.has_ack() {
                if hdr.has_syn() {
                    // S|A
                    self.status = TcpStatus::SynReceived;
                    self.ts_syn_ack = ts;
                    if self.ts_syn.0 > 0 {
                        self.rtt_net = ts - self.ts_syn;
                    }
                } else {
                    // A only
                    if matches!(self.status, TcpStatus::SynReceived) {
                        self.status = TcpStatus::Established;
                        self.ts_ack = ts;
                        if self.ts_syn.0 > 0 {
                            self.rtt = self.ts_ack - self.ts_syn;
                        }

                        if self.ts_syn_ack.0 > 0 {
                            self.rtt_user = self.ts_ack - self.ts_syn_ack;
                        }
                    } else if matches!(self.status, TcpStatus::FinWait) {
                        self.status = TcpStatus::CloseWait;
                    } else if self.status < TcpStatus::Established
                        && metrics.d_pkts > 0
                        && metrics.u_pkts > 0
                    {
                        self.status = TcpStatus::Established;
                    }
                }
            } else if hdr.has_syn() {
                self.status = TcpStatus::SynSent;
                self.ts_syn = ts;
            }
        }
    }

    /// Swaps uplink and downlink TCP sequence numbers.
    #[inline]
    pub fn swap_directions(&mut self) {
        std::mem::swap(&mut self.u_seq, &mut self.d_seq);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlowMetrics {
    /// Total uplink bytes.
    pub u_bytes: u64,
    /// Total downlink bytes.
    pub d_bytes: u64,
    /// Total uplink payload bytes.
    pub u_payload_bytes: u64,
    /// Total downlink payload bytes.
    pub d_payload_bytes: u64,
    /// Total uplink packets.
    pub u_pkts: u32,
    /// Total downlink packets.
    pub d_pkts: u32,
    /// Uplink packets with payload.
    pub u_payload_pkts: u32,
    /// Downlink packets with payload.
    pub d_payload_pkts: u32,
    /// Total uplink fragments count.
    pub u_fragments: u32,
    /// Total uplink fragmented packets.
    pub u_fragmented_pkts: u32,
    /// Total downlink fragments count.
    pub d_fragments: u32,
    /// Total downlink fragmented packets.
    pub d_fragmented_pkts: u32,
}

impl FlowMetrics {
    #[inline(always)]
    pub fn update<Meta: PacketMetadata>(
        &mut self,
        pkt: &Packet<'_>,
        dir: PacketDirection,
        meta: &Meta,
    ) {
        let payload_len = pkt.data().len() as u64;
        let caplen = meta.caplen() as u64;
        let is_payload = payload_len > 0;
        match dir {
            PacketDirection::Upwards => {
                self.u_bytes += caplen;
                self.u_pkts += 1;
                self.u_payload_bytes += payload_len;
                self.u_payload_pkts += is_payload as u32;
                if let Some(NetworkLayer::Ipv4(hdr)) = pkt.network() {
                    self.u_fragments += hdr.is_fragmenting() as u32;
                    self.u_fragmented_pkts += hdr.is_first_fragment() as u32;
                };
            }
            PacketDirection::Downwards => {
                self.d_bytes += caplen;
                self.d_pkts += 1;
                self.d_payload_bytes += payload_len;
                self.d_payload_pkts += is_payload as u32;
                if let Some(NetworkLayer::Ipv4(hdr)) = pkt.network() {
                    self.d_fragments += hdr.is_fragmenting() as u32;
                    self.d_fragmented_pkts += hdr.is_first_fragment() as u32;
                };
            }
        }
    }

    /// Swaps all uplink and downlink packet/byte counters.
    #[inline]
    pub fn swap_directions(&mut self) {
        std::mem::swap(&mut self.u_bytes, &mut self.d_bytes);
        std::mem::swap(&mut self.u_payload_bytes, &mut self.d_payload_bytes);
        std::mem::swap(&mut self.u_pkts, &mut self.d_pkts);
        std::mem::swap(&mut self.u_payload_pkts, &mut self.d_payload_pkts);
        std::mem::swap(&mut self.u_fragments, &mut self.d_fragments);
        std::mem::swap(&mut self.u_fragmented_pkts, &mut self.d_fragmented_pkts);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlowBase<T> {
    /// Identity information (Tuple, MACs, Proto).
    pub id: FlowId<T>,
    /// Timing information (Start, Last).
    pub timing: FlowTiming,
    /// IP layer state and loss tracking.
    pub ip: IpState,
    /// TCP layer state and info.
    pub tcp: TcpState,
    /// Two-level confidence (`Low` or `High`) in the inferred flow direction.
    pub confidence: Confidence,
    /// Flow statistics and counters.
    pub metrics: FlowMetrics,
}

impl<T: Tuple> FlowBase<T> {
    /// Flips the canonical orientation of the flow in-place, swaps all uplink/downlink
    /// statistics (including bytes and packets already counted), and upgrades `confidence`
    /// to `Confidence::High`.
    ///
    /// Can be called during Phase 2 by an external DPI engine whenever it determines
    /// that the initial flow direction was inverted.
    #[cold]
    #[inline(never)]
    pub fn flip_direction(&mut self) {
        self.id.tuple = self.id.tuple.flip();
        std::mem::swap(&mut self.id.src_mac, &mut self.id.dst_mac);
        self.ip.swap_directions();
        self.tcp.swap_directions();
        self.metrics.swap_directions();
        self.confidence = Confidence::High;
    }

    #[cold]
    #[inline(never)]
    fn resolve_l4_direction(
        &mut self,
        pkt: &Packet<'_>,
        tuple_dir: PacketDirection,
    ) -> PacketDirection {
        let total_pkts = self.metrics.u_pkts + self.metrics.d_pkts;
        if total_pkts == 0 {
            return tuple_dir;
        }

        if let Some(l4_dir) = PacketDirection::infer_l4_handshake(pkt) {
            if !self.id.tuple.is_symmetric() && l4_dir != tuple_dir {
                self.flip_direction();
            } else {
                self.confidence = Confidence::High;
            }
            return l4_dir;
        }

        if total_pkts >= 7 || (self.metrics.u_payload_pkts > 0 && self.metrics.d_payload_pkts > 0) {
            self.confidence = Confidence::High;
        }
        tuple_dir
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Flow<T, D> {
    /// Basic flow data organized in logical blocks.
    pub base: FlowBase<T>,
    /// Custom data associated with the flow.
    pub data: D,
}

impl<T, D> Flow<T, D>
where
    T: Default + Clone + Tuple + Sized,
    D: Default,
{
    /// Creates a new `Flow` instance (Phase 1 initialization).
    ///
    /// Automatically infers the initial flow orientation (`Upwards` or `Downwards`)
    /// and its `Confidence` (`High` or `Low`) from L4 headers and OS-aware port ranking.
    #[inline(always)]
    pub fn new(timestamp: Timestamp, tuple: T, pkt: &Packet<'_>) -> Self {
        Self::new_with_dir(timestamp, tuple, pkt).0
    }

    /// Creates a new `Flow` instance and also returns the inferred direction of the initial packet.
    #[inline(always)]
    pub(crate) fn new_with_dir(
        timestamp: Timestamp,
        tuple: T,
        pkt: &Packet<'_>,
    ) -> (Self, PacketDirection) {
        let (dir, confidence) = if tuple.is_symmetric() {
            (PacketDirection::infer_symmetric(pkt), Confidence::High)
        } else {
            PacketDirection::infer_with_confidence(pkt)
        };
        let upwards = matches!(dir, PacketDirection::Upwards);
        let flow = Self {
            base: FlowBase {
                id: FlowId {
                    tuple: if upwards { tuple } else { tuple.flip() },
                    eth_proto: pkt.link().protocol(),
                    src_mac: if upwards {
                        pkt.link().source()
                    } else {
                        pkt.link().dest()
                    },
                    dst_mac: if upwards {
                        pkt.link().dest()
                    } else {
                        pkt.link().source()
                    },
                },
                timing: FlowTiming {
                    start: timestamp,
                    last: timestamp,
                },
                confidence,
                ..Default::default()
            },
            data: Default::default(),
        };
        // Note: relative to the newly oriented `flow.base.id.tuple` (which was flipped if `dir` was Downwards),
        // the initial packet itself travels from `id.tuple.source -> id.tuple.dest` (`Upwards`) when `upwards` is true,
        // and from `id.tuple.dest -> id.tuple.source` (`Downwards`) when `upwards` is false — which is `dir`!
        (flow, dir)
    }
}

impl<T: Tuple, D> Flow<T, D> {
    /// Determines the direction of a packet relative to the flow's current tuple orientation.
    #[inline(always)]
    pub fn packet_dir(&self, pkt: &Packet<'_>) -> PacketDirection {
        if self.base.id.tuple.is_symmetric() {
            return PacketDirection::infer_symmetric(pkt);
        }

        if self.base.id.tuple.is_same_dir(pkt) {
            PacketDirection::Upwards
        } else {
            PacketDirection::Downwards
        }
    }

    /// Flips the canonical orientation of the flow in-place, swaps all uplink/downlink
    /// statistics (including bytes and packets already counted), and upgrades `confidence`
    /// to `Confidence::High`.
    ///
    /// Call this in Phase 2 if your DPI engine determines that the flow orientation should be swapped.
    #[inline]
    pub fn flip_direction(&mut self) {
        self.base.flip_direction();
    }
}

impl<T, D> Flow<T, D>
where
    T: Tuple,
    D: Process,
{
    /// Updates the flow with a new packet (Phase 1) and invokes `self.data.process` (Phase 2).
    ///
    /// Returns the `PacketDirection` assigned to `pkt` during Phase 1.
    /// If external DPI logic running after `flow.update(meta, pkt)` determines that the flow
    /// direction should be swapped, it can simply call `flow.flip_direction()`.
    #[inline(always)]
    pub fn update<Meta: PacketMetadata>(
        &mut self,
        meta: &Meta,
        pkt: &Packet<'_>,
    ) -> PacketDirection {
        let tuple_dir = self.packet_dir(pkt);
        let dir = if self.base.confidence == Confidence::Low {
            self.base.resolve_l4_direction(pkt, tuple_dir)
        } else {
            tuple_dir
        };
        self.update_with_dir(meta, pkt, dir)
    }

    /// Updates the flow using an already-known packet direction (used on the 1st packet in `track_packet`
    /// to avoid re-evaluating `packet_dir` and `resolve_l4_direction`).
    #[inline(always)]
    pub(crate) fn update_with_dir<Meta: PacketMetadata>(
        &mut self,
        meta: &Meta,
        pkt: &Packet<'_>,
        dir: PacketDirection,
    ) -> PacketDirection {
        let ts = meta.timestamp();
        self.base.timing.last = ts;
        self.base.metrics.update(pkt, dir, meta);
        self.base.ip.update(pkt, dir);
        self.base
            .tcp
            .update_with_ts(pkt, dir, ts, &self.base.metrics);
        self.data.process(meta, pkt, dir, &mut self.base);
        dir
    }
}

impl<T, D> Trackable for Flow<T, D> {
    type Timestamp = Timestamp;

    #[inline(always)]
    fn first_seen(&self) -> Timestamp {
        self.base.timing.start
    }

    #[inline(always)]
    fn last_seen(&self) -> Timestamp {
        self.base.timing.last
    }

    #[inline(always)]
    fn set_last_seen(&mut self, ts: Self::Timestamp) {
        self.base.timing.last = ts;
    }
}

pub type FlowIpV4<D> = Flow<crate::tracker::tuple::TupleV4, D>;
pub type FlowIpV6<D> = Flow<crate::tracker::tuple::TupleV6, D>;
pub type FlowEth<D> = Flow<crate::tracker::tuple::TupleEth, D>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{iter::LinkType, Packet, ParseMode};
    use crate::tracker::tuple::TupleV4;
    use crate::tracker::vni::VniMapper;

    struct DummyMeta<'a> {
        ts: Timestamp,
        raw: &'a [u8],
    }

    impl PacketMetadata for DummyMeta<'_> {
        fn timestamp(&self) -> Timestamp {
            self.ts
        }
        fn caplen(&self) -> u32 {
            self.raw.len() as u32
        }
        fn origlen(&self) -> u32 {
            self.raw.len() as u32
        }
        fn data(&self) -> &[u8] {
            self.raw
        }
    }

    fn build_tcp_ipv4(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        build_tcp_ipv4_with_seq(src_ip, dst_ip, src_port, dst_port, 100, 200, flags, payload)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_tcp_ipv4_with_seq(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = (20 + 20 + payload.len()) as u16;
        let mut buf = Vec::with_capacity(14 + total_len as usize);
        buf.extend_from_slice(&[0x00, 0x00, 0x0C, 0x33, 0x44, 0x55]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x99, 0xaa, 0xbb]);
        buf.extend_from_slice(&[0x08, 0x00]);
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]);
        buf.push(64);
        buf.push(6); // TCP
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&src_ip);
        buf.extend_from_slice(&dst_ip);
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&ack.to_be_bytes());
        buf.push(0x50);
        buf.push(flags);
        buf.extend_from_slice(&65535u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_two_phase_update_and_dpi_flip_direction() {
        let mut vni = VniMapper::default();
        let clt_ip = [10, 0, 0, 1];
        let srv_ip = [10, 0, 0, 2];
        // Both ports in Dynamic range (49152..=65535 -> Rank 4), so initial ACK has Confidence::Low
        let clt_port = 50000u16;
        let srv_port = 55000u16;

        // Packet 1: Mid-stream empty ACK from Server (55000) -> Client (50000).
        // Phase 1 (`Flow::new` + `flow.update`) guesses Upwards (55000 > 50000) with Confidence::Low.
        let raw1 =
            build_tcp_ipv4_with_seq(srv_ip, clt_ip, srv_port, clt_port, 2000, 1000, 0x10, &[]);
        let pkt1 = Packet::from_bytes(&raw1, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        let tuple1 = TupleV4::new(&pkt1, &mut vni).unwrap();

        let mut flow: FlowIpV4<()> = Flow::new(Timestamp(100), tuple1, &pkt1);
        assert_eq!(flow.base.confidence, Confidence::Low);

        let d1 = flow.update(
            &DummyMeta {
                ts: Timestamp(100),
                raw: &raw1,
            },
            &pkt1,
        );
        assert_eq!(d1, PacketDirection::Upwards);
        assert_eq!(flow.base.metrics.u_pkts, 1);
        assert_eq!(flow.base.metrics.d_pkts, 0);
        assert_eq!(flow.base.tcp.u_seq, 2000);
        assert_eq!(flow.base.tcp.d_seq, 0);

        // Packet 2: Empty ACK from Client (50000) -> Server (55000).
        let raw2 =
            build_tcp_ipv4_with_seq(clt_ip, srv_ip, clt_port, srv_port, 1000, 2000, 0x10, &[]);
        let pkt2 = Packet::from_bytes(&raw2, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        let d2 = flow.update(
            &DummyMeta {
                ts: Timestamp(101),
                raw: &raw2,
            },
            &pkt2,
        );
        assert_eq!(d2, PacketDirection::Downwards);
        assert_eq!(flow.base.confidence, Confidence::Low);
        assert_eq!(flow.base.metrics.u_pkts, 1);
        assert_eq!(flow.base.metrics.d_pkts, 1);
        assert_eq!(flow.base.tcp.u_seq, 2000);
        assert_eq!(flow.base.tcp.d_seq, 1000);

        // Packet 3: Client (50000) -> Server (55000) sends HTTP GET request!
        // Phase 1 (`flow.update`) provisionally counts it as `Downwards` (`d_pkts` becomes 2, `d_payload_pkts` becomes 1).
        let raw3 = build_tcp_ipv4_with_seq(
            clt_ip,
            srv_ip,
            clt_port,
            srv_port,
            1005,
            2000,
            0x18,
            b"GET /index.html HTTP/1.1\r\n",
        );
        let pkt3 = Packet::from_bytes(&raw3, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        let d3 = flow.update(
            &DummyMeta {
                ts: Timestamp(102),
                raw: &raw3,
            },
            &pkt3,
        );
        assert_eq!(d3, PacketDirection::Downwards);

        // Phase 2: User's DPI inspects `pkt3`, sees it's an HTTP GET request (which must be `Upwards`),
        // notices `d3 != PacketDirection::Upwards`, and calls `flow.flip_direction()`!
        if d3 != PacketDirection::Upwards {
            flow.flip_direction();
        }

        // Now the flow tuple, MACs, TCP seqs, and ALL accumulated counters (including Packet 3!) are flipped and High confidence!
        assert_eq!(flow.base.confidence, Confidence::High);
        assert_eq!(flow.base.id.tuple.source_port(), clt_port);
        assert_eq!(flow.base.id.tuple.dest_port(), srv_port);
        assert_eq!(flow.base.metrics.u_pkts, 2);
        assert_eq!(flow.base.metrics.d_pkts, 1);
        assert_eq!(flow.base.metrics.u_payload_pkts, 1);
        assert_eq!(flow.base.metrics.d_payload_pkts, 0);
        assert_eq!(flow.base.metrics.u_payload_bytes, 26u64);
        assert_eq!(flow.base.metrics.d_payload_bytes, 0u64);
        assert_eq!(flow.base.tcp.u_seq, 1005);
        assert_eq!(flow.base.tcp.d_seq, 2000);
    }

    #[test]
    fn test_flow_l4_handshake_refinement() {
        let mut vni = VniMapper::default();
        let clt_ip = [10, 0, 0, 1];
        let srv_ip = [10, 0, 0, 2];
        let clt_port = 50000u16;
        let srv_port = 55000u16;

        // Packet 1: Stray/out-of-order ACK from Server (55000) -> Client (50000) creates flow with Confidence::Low
        let raw1 = build_tcp_ipv4(srv_ip, clt_ip, srv_port, clt_port, 0x10, &[]);
        let pkt1 = Packet::from_bytes(&raw1, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        let tuple1 = TupleV4::new(&pkt1, &mut vni).unwrap();
        let mut flow: FlowIpV4<()> = Flow::new(Timestamp(100), tuple1, &pkt1);
        flow.update(
            &DummyMeta {
                ts: Timestamp(100),
                raw: &raw1,
            },
            &pkt1,
        );
        assert_eq!(flow.base.confidence, Confidence::Low);

        // Packet 2: Retransmitted SYN-ACK (0x12) from Server (55000) -> Client (50000).
        // Phase 1 pure L4 handshake detection recognizes SYN-ACK as `Downwards`, flips the flow, and sets `Confidence::High`!
        let raw2 = build_tcp_ipv4(srv_ip, clt_ip, srv_port, clt_port, 0x12, &[]);
        let pkt2 = Packet::from_bytes(&raw2, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        let d2 = flow.update(
            &DummyMeta {
                ts: Timestamp(101),
                raw: &raw2,
            },
            &pkt2,
        );
        assert_eq!(d2, PacketDirection::Downwards);
        assert_eq!(flow.base.confidence, Confidence::High);
        assert_eq!(flow.base.id.tuple.source_port(), clt_port);
        assert_eq!(flow.base.id.tuple.dest_port(), srv_port);
        assert_eq!(flow.base.metrics.u_pkts, 0);
        assert_eq!(flow.base.metrics.d_pkts, 2);
    }
}
