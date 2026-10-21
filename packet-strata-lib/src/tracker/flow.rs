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
        _dir: PacketDirection,
        ts: Timestamp,
        metrics: &FlowMetrics,
    ) {
        if let Some(TransportLayer::Tcp(hdr)) = pkt.transport() {
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
                    self.d_seq = hdr.sequence_number();
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
    pub u_bytes: usize,
    /// Total downlink bytes.
    pub d_bytes: usize,
    /// Total uplink payload bytes.
    pub u_payload_bytes: usize,
    /// Total downlink payload bytes.
    pub d_payload_bytes: usize,
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
        let payload_len = pkt.data().len();
        let caplen = meta.caplen() as usize;
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
    /// Flips the canonical orientation of the flow in-place and swaps uplink/downlink statistics.
    #[cold]
    #[inline(never)]
    pub fn flip_direction(&mut self) {
        self.id.tuple = self.id.tuple.flip();
        std::mem::swap(&mut self.id.src_mac, &mut self.id.dst_mac);
        self.ip.swap_directions();
        self.tcp.swap_directions();
        self.metrics.swap_directions();
    }

    /// Confirms or corrects the flow orientation based on an authoritative packet direction
    /// (e.g. from an external DPI engine or a subsequent L4 handshake packet).
    ///
    /// If `actual_pkt_dir != tuple_dir` (and the tuple is not symmetric), flips the flow
    /// and all accumulated counters in-place, then sets `self.confidence = Confidence::High`.
    #[inline]
    pub fn confirm_direction(
        &mut self,
        tuple_dir: PacketDirection,
        actual_pkt_dir: PacketDirection,
    ) -> PacketDirection {
        if !self.id.tuple.is_symmetric() && actual_pkt_dir != tuple_dir {
            self.flip_direction();
        }
        self.confidence = Confidence::High;
        actual_pkt_dir
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
            return self.confirm_direction(tuple_dir, l4_dir);
        }

        if total_pkts >= 7 || (self.metrics.u_payload_pkts > 0 && self.metrics.d_payload_pkts > 0)
        {
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
    /// Creates a new `Flow` instance.
    ///
    /// If `dir` is `Some(d)` (provided by an external DPI engine), the flow is oriented
    /// according to `d` with `Confidence::High`.
    /// If `dir` is `None`, the initial orientation and `Confidence` (`High` or `Low`) are
    /// inferred automatically from L4 headers and OS-aware port ranking.
    #[inline(always)]
    pub fn new(
        timestamp: Timestamp,
        tuple: T,
        pkt: &Packet<'_>,
        dir: Option<PacketDirection>,
    ) -> Self {
        let (resolved_dir, confidence) = match dir {
            Some(d) => (d, Confidence::High),
            None => {
                if tuple.is_symmetric() {
                    (PacketDirection::infer_symmetric(pkt), Confidence::High)
                } else {
                    PacketDirection::infer_with_confidence(pkt)
                }
            }
        };
        let upwards = matches!(resolved_dir, PacketDirection::Upwards);
        Self {
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
        }
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
}

impl<T, D> Flow<T, D>
where
    T: Tuple,
    D: Process,
{
    /// Processes a packet and updates flow statistics.
    ///
    /// `dir` is the optional packet direction provided by an external DPI engine:
    /// - When `dir` is `Some(dpi_dir)`, if the flow's orientation conflicts with `dpi_dir`,
    ///   the flow is automatically flipped in-place (swapping tuple, MACs, and accumulated
    ///   uplink/downlink counters) and `confidence` is set to `Confidence::High`.
    /// - When `dir` is `None`, the direction is computed from the flow's tuple (and if
    ///   `confidence == Confidence::Low`, checked against definitive L4 handshake signals).
    #[inline(always)]
    pub fn process<Meta: PacketMetadata>(
        &mut self,
        meta: &Meta,
        pkt: &Packet<'_>,
        dir: Option<PacketDirection>,
    ) {
        let tuple_dir = self.packet_dir(pkt);
        let resolved_dir = match dir {
            Some(dpi_dir) => self.base.confirm_direction(tuple_dir, dpi_dir),
            None => {
                if self.base.confidence == Confidence::Low {
                    self.base.resolve_l4_direction(pkt, tuple_dir)
                } else {
                    tuple_dir
                }
            }
        };

        let ts = meta.timestamp();
        self.base.timing.last = ts;
        self.base.metrics.update(pkt, resolved_dir, meta);
        self.base.ip.update(pkt, resolved_dir);
        self.base
            .tcp
            .update_with_ts(pkt, resolved_dir, ts, &self.base.metrics);
        self.data
            .process(meta, pkt, Some(resolved_dir), &mut self.base);
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
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(&200u32.to_be_bytes());
        buf.push(0x50);
        buf.push(flags);
        buf.extend_from_slice(&65535u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_flow_multi_packet_direction_refinement_via_optional_dpi_dir() {
        let mut vni = VniMapper::default();
        let clt_ip = [10, 0, 0, 1];
        let srv_ip = [10, 0, 0, 2];
        // Both ports in Dynamic range (49152..=65535 -> Rank 4), so initial ACK has Confidence::Low
        let clt_port = 50000u16;
        let srv_port = 55000u16;

        // Packet 1: Mid-stream empty ACK from Server (55000) -> Client (50000).
        // DPI passes `None` (no payload yet). Stateless L4 guesses Upwards (55000 > 50000) with Confidence::Low.
        let raw1 = build_tcp_ipv4(srv_ip, clt_ip, srv_port, clt_port, 0x10, &[]);
        let pkt1 = Packet::from_bytes(&raw1, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        let tuple1 = TupleV4::new(&pkt1, &mut vni).unwrap();

        let mut flow: FlowIpV4<()> = Flow::new(Timestamp(100), tuple1, &pkt1, None);
        assert_eq!(flow.base.confidence, Confidence::Low);

        flow.process(
            &DummyMeta {
                ts: Timestamp(100),
                raw: &raw1,
            },
            &pkt1,
            None,
        );
        assert_eq!(flow.base.metrics.u_pkts, 1);
        assert_eq!(flow.base.metrics.d_pkts, 0);

        // Packet 2: Empty ACK from Client (50000) -> Server (55000). DPI still passes `None`.
        let raw2 = build_tcp_ipv4(clt_ip, srv_ip, clt_port, srv_port, 0x10, &[]);
        let pkt2 = Packet::from_bytes(&raw2, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        flow.process(
            &DummyMeta {
                ts: Timestamp(101),
                raw: &raw2,
            },
            &pkt2,
            None,
        );
        assert_eq!(flow.base.confidence, Confidence::Low);
        assert_eq!(flow.base.metrics.u_pkts, 1);
        assert_eq!(flow.base.metrics.d_pkts, 1);

        // Packet 3: Client (50000) -> Server (55000) sends L7 request!
        // The external DPI engine identifies the packet as `Some(PacketDirection::Upwards)` and passes it to `flow.process`.
        // `Flow` sees that `Upwards` conflicts with the provisional tuple orientation (`Downwards`),
        // automatically flips the flow in-place, swaps the accumulated counters, and upgrades to `Confidence::High`!
        let raw3 = build_tcp_ipv4(
            clt_ip,
            srv_ip,
            clt_port,
            srv_port,
            0x18,
            b"GET /index.html HTTP/1.1\r\n",
        );
        let pkt3 = Packet::from_bytes(&raw3, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        flow.process(
            &DummyMeta {
                ts: Timestamp(102),
                raw: &raw3,
            },
            &pkt3,
            Some(PacketDirection::Upwards),
        );

        assert_eq!(flow.base.confidence, Confidence::High);
        assert_eq!(flow.base.id.tuple.source_port(), clt_port);
        assert_eq!(flow.base.id.tuple.dest_port(), srv_port);
        assert_eq!(flow.base.metrics.u_pkts, 2);
        assert_eq!(flow.base.metrics.d_pkts, 1);
        assert_eq!(flow.base.metrics.u_payload_pkts, 1);
        assert_eq!(flow.base.metrics.d_payload_pkts, 0);
    }

    #[test]
    fn test_flow_l4_handshake_refinement_when_dpi_is_none() {
        let mut vni = VniMapper::default();
        let clt_ip = [10, 0, 0, 1];
        let srv_ip = [10, 0, 0, 2];
        let clt_port = 50000u16;
        let srv_port = 55000u16;

        // Packet 1: Stray/out-of-order ACK from Server (55000) -> Client (50000) creates flow with Confidence::Low
        let raw1 = build_tcp_ipv4(srv_ip, clt_ip, srv_port, clt_port, 0x10, &[]);
        let pkt1 = Packet::from_bytes(&raw1, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        let tuple1 = TupleV4::new(&pkt1, &mut vni).unwrap();
        let mut flow: FlowIpV4<()> = Flow::new(Timestamp(100), tuple1, &pkt1, None);
        flow.process(
            &DummyMeta {
                ts: Timestamp(100),
                raw: &raw1,
            },
            &pkt1,
            None,
        );
        assert_eq!(flow.base.confidence, Confidence::Low);

        // Packet 2: Retransmitted SYN-ACK (0x12) from Server (55000) -> Client (50000) with `dir = None`.
        // Pure L4 handshake detection recognizes SYN-ACK as `Downwards`, flips the flow, and sets `Confidence::High`!
        let raw2 = build_tcp_ipv4(srv_ip, clt_ip, srv_port, clt_port, 0x12, &[]);
        let pkt2 = Packet::from_bytes(&raw2, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        flow.process(
            &DummyMeta {
                ts: Timestamp(101),
                raw: &raw2,
            },
            &pkt2,
            None,
        );
        assert_eq!(flow.base.confidence, Confidence::High);
        assert_eq!(flow.base.id.tuple.source_port(), clt_port);
        assert_eq!(flow.base.id.tuple.dest_port(), srv_port);
        assert_eq!(flow.base.metrics.u_pkts, 0);
        assert_eq!(flow.base.metrics.d_pkts, 2);
    }
}
