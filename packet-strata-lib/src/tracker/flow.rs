use serde::{Deserialize, Serialize};

use crate::{
    metadata::PacketMetadata,
    packet::{
        ether::EthAddr,
        header::{NetworkLayer, SourceDestLayer, TransportLayer},
        protocol::EtherProto,
        Packet,
    },
    timestamp::{Interval, Timestamp},
    tracker::{direction::PacketDirection, process::Process, tuple::Tuple, Trackable},
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
    #[inline]
    #[must_use]
    pub fn is_established(self) -> bool {
        matches!(self, TcpStatus::Established)
    }

    #[inline]
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
    pub fn update<Meta: PacketMetadata>(
        &mut self,
        pkt: &Packet<'_>,
        _dir: PacketDirection,
        meta: &Meta,
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
                    self.ts_syn_ack = meta.timestamp();
                    self.d_seq = hdr.sequence_number();
                    if self.ts_syn.0 > 0 {
                        self.rtt_net = meta.timestamp() - self.ts_syn;
                    }
                } else {
                    // A only
                    if matches!(self.status, TcpStatus::SynReceived) {
                        self.status = TcpStatus::Established;
                        self.ts_ack = meta.timestamp();
                        if self.ts_syn.0 > 0 {
                            self.rtt = self.ts_ack - self.ts_syn;
                        }

                        if self.ts_syn_ack.0 > 0 {
                            self.rtt_user = self.ts_ack - self.ts_syn_ack;
                        }
                    } else if matches!(self.status, TcpStatus::FinWait) {
                        self.status = TcpStatus::CloseWait;
                    } else {
                        if self.status < TcpStatus::Established {
                            if metrics.d_pkts > 0 && metrics.u_pkts > 0 {
                                self.status = TcpStatus::Established;
                            }
                        }
                    }
                }
            } else if hdr.has_syn() {
                self.status = TcpStatus::SynSent;
                self.ts_syn = meta.timestamp();
            }
        }
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
    /// Flow statistics and counters.
    pub metrics: FlowMetrics,
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
    for<'a> NetworkLayer<'a>: SourceDestLayer<T::Addr>,
    T::Addr: Eq,
    D: Default,
{
    /// Creates a new `Flow` instance.
    pub fn new(timestamp: Timestamp, tuple: T, pkt: &Packet<'_>, dir: PacketDirection) -> Self {
        let upwards = matches!(dir, PacketDirection::Upwards);
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
                ..Default::default()
            },
            data: Default::default(),
        }
    }

    /// Determines the direction of a packet relative to the flow.
    #[inline]
    pub fn packet_dir(&self, pkt: &Packet<'_>) -> PacketDirection {
        if self.base.id.tuple.is_symmetric() {
            return PacketDirection::infer(pkt);
        }

        let is_upwards_addr = pkt
            .network()
            .and_then(|net| SourceDestLayer::<T::Addr>::source(net))
            .is_some_and(|src| src == self.base.id.tuple.source());

        let is_upwards_port = pkt
            .transport()
            .and_then(|tr| SourceDestLayer::<u16>::source(tr))
            .is_some_and(|src| src == self.base.id.tuple.source_port());

        if is_upwards_addr && is_upwards_port {
            PacketDirection::Upwards
        } else {
            PacketDirection::Downwards
        }
    }
}

impl<T, D> Flow<T, D>
where
    D: Process,
{
    /// Process a packet and update flow statistics.
    pub fn process<Meta: PacketMetadata>(
        &mut self,
        meta: &Meta,
        pkt: &Packet<'_>,
        dir: PacketDirection,
    ) {
        self.base.timing.last = meta.timestamp();
        self.base.metrics.update(pkt, dir, meta);
        self.base.ip.update(pkt, dir);
        self.base.tcp.update(pkt, dir, meta, &self.base.metrics);
        self.data.process(meta, pkt, dir, &mut self.base);
    }
}

impl<T, D> Trackable for Flow<T, D> {
    type Timestamp = Timestamp;

    fn timestamp(&self) -> Timestamp {
        self.base.timing.start
    }

    fn set_timestamp(&mut self, ts: Self::Timestamp) {
        self.base.timing.last = ts;
    }
}

pub type FlowIpV4<D> = Flow<crate::tracker::tuple::TupleV4, D>;
pub type FlowIpV6<D> = Flow<crate::tracker::tuple::TupleV6, D>;
