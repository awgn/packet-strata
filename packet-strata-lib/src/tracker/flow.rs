use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use chrono::TimeDelta;
use serde::{Deserialize, Serialize};

use crate::{
    metadata::PacketMetadata, packet::{
        Packet, ether::EthAddr, icmp::IcmpType, protocol::EtherProto
    }, timestamp::Timestamp, tracker::{Trackable, direction::PacketDirection, tuple::Tuple, process::Process}
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TcpState {
    #[default]
    /// Initial state, or when tracking metadata is evicted/expired.
    Closed,

    /// Client sent SYN, waiting for SYN-ACK.
    /// Crucial for detecting SYN floods or failed connections.
    SynSent,

    /// Server sent SYN-ACK. The handshake is partially complete.
    SynReceived,

    /// Handshake completed (ACK received). Data transfer phase.
    Established,

    /// One side sent a FIN. Passive monitor infers this when seeing the first FIN.
    FinWait,

    /// The other side acknowledged the FIN.
    CloseWait,

    /// Simultaneous close or final stages of termination.
    Closing,

    /// Connection reset via RST flag.
    Reset,

    /// State cannot be inferred from the observed packet sequence.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Termination {
    /// Normal TCP shutdown (FIN exchange observed).
    #[default]
    Close,

    /// Connection reset (RST flag observed).
    Reset,

    /// Session expired due to inactivity (Idle Timeout).
    Timeout,

    /// Specific timeout for flows that never reached 'Established' state.
    /// Crucial for passive monitors to detect/discard SYN floods without noise.
    HandshakeTimeout,

    /// Received ICMP Destination Unreachable or similar error (IPv4).
    /// Note: ICMP code is technically u8, changed from u16 to match standard header.
    Icmp4 { type_: u8, code: u8 },

    /// Received ICMPv6 error.
    Icmp6 { type_: u8, code: u8 },

    /// The flow was forced out of the tracking table to free up memory.
    /// Passive monitors have finite state maps; this distinguishes a "lost" flow from a "finished" one.
    Eviction,

    /// The monitoring application is shutting down or flushing state.
    MonitorShutdown,
}

impl Termination {
    #[inline]
    #[must_use]
    pub fn is_close(&self) -> bool {
        matches!(self, Termination::Close)
    }

    #[inline]
    #[must_use]
    pub fn is_reset(&self) -> bool {
        matches!(self, Termination::Reset)
    }

    #[inline]
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Termination::Timeout)
    }

    #[inline]
    #[must_use]
    pub fn is_icmp(&self) -> bool {
        matches!(self, Termination::Icmp4 { .. }) || matches!(self, Termination::Icmp6 { .. })
    }

    #[inline]
    #[must_use]
    pub fn is_icmp4(&self) -> bool {
        matches!(self, Termination::Icmp4 { .. })
    }

    #[inline]
    #[must_use]
    pub fn is_icmp6(&self) -> bool {
        matches!(self, Termination::Icmp6 { .. })
    }

    #[inline]
    #[must_use]
    pub fn is_icmp4_type(&self, t: IcmpType) -> bool {
        matches!(self, Termination::Icmp4 { type_, .. } if *type_ == t.0)
    }

    #[inline]
    #[must_use]
    pub fn is_icmp6_type(&self, t: IcmpType) -> bool {
        matches!(self, Termination::Icmp6 { type_, .. } if *type_ == t.0)
    }
}

impl Display for Termination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Termination::Close => write!(f, "close"),
            Termination::Reset => write!(f, "reset"),
            Termination::Timeout => write!(f, "timeout"),
            Termination::Icmp4 { type_, code } => write!(f, "ICMP4({},{})", type_, code),
            Termination::Icmp6 { type_, code } => write!(f, "ICMP6({},{})", type_, code),
            Termination::Eviction => write!(f, "eviction"),
            Termination::HandshakeTimeout => write!(f, "handshake-timeout"),
            Termination::MonitorShutdown => write!(f, "monitor-shutdown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FlowType {
    #[default]
    /// Unspecified or unknown flow type.
    Unspec,
    /// Uplink traffic (e.g., from subscriber to network).
    Uplink,
    /// Downlink traffic (e.g., from network to subscriber).
    Downlink,
    /// Internal LAN traffic.
    Inner,
    /// External LAN traffic.
    Outer,
    /// Link-local traffic.
    Linklocal,
    /// Broadcast traffic.
    Broadcast,
    /// Multicast traffic.
    Multicast,
    /// Loopback traffic.
    Loopback,
}

impl Display for FlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowType::Unspec => write!(f, "unspecified"),
            FlowType::Uplink => write!(f, "uplink"),
            FlowType::Downlink => write!(f, "downlink"),
            FlowType::Inner => write!(f, "inner"),
            FlowType::Outer => write!(f, "outer"),
            FlowType::Linklocal => write!(f, "link-local"),
            FlowType::Broadcast => write!(f, "broadcast"),
            FlowType::Multicast => write!(f, "multicast"),
            FlowType::Loopback => write!(f, "loopback"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IpInfo {
    /// Uplink IP identification.
    u_id: Option<u16>,
    /// Downlink IP identification.
    d_id: Option<u16>,
    /// Uplink packets lost.
    u_lost: u32,
    /// Downlink packets lost.
    d_lost: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpInfo {
    /// Timestamp of the initial SYN packet.
    ts_syn: Timestamp,

    /// Timestamp of the SYN-ACK packet.
    ts_syn_ack: Timestamp,

    /// Timestamp of the ACK packet completing the handshake.
    ts_ack: Timestamp,

    /// Round-trip time. Usually `rtt = rtt_net + rtt_usr`.
    /// If a packet is missing (e.g. SYN-ACK), only total RTT might be computable.
    rtt: TimeDelta,

    /// Network component of the round-trip time.
    rtt_net: TimeDelta,

    /// User/Application component of the round-trip time.
    rtt_user: TimeDelta,

    /// Uplink sequence number.
    u_seq: u32,

    /// Downlink sequence number.
    d_seq: u32,

    /// Current TCP state.
    state: TcpState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Flow<T, D> {
    /// Timestamp of the first packet in the flow.
    pub start_ts: Timestamp,

    /// Timestamp of the last packet in the flow.
    pub last_ts: Timestamp,

    /// Source MAC address.
    pub src_mac: EthAddr,

    /// Destination MAC address.
    pub dst_mac: EthAddr,

    /// Ethernet protocol.
    pub eth_proto: EtherProto,

    /// Generic address tuple (e.g. TupleV4, TupleV6 or TupleL2)
    pub tuple: T,

    /// Flow classification (Uplink, Downlink, etc.).
    pub r#type: FlowType,

    /// Reason for flow termination.
    pub termination: Termination,

    /// IP layer statistics and info.
    pub ip_info: IpInfo,

    /// TCP layer statistics and info (optional).
    pub tcp_info: TcpInfo,

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

    /// Uplink fragments count.
    pub u_frags: u32,

    /// Downlink fragments count.
    pub d_frags: u32,

    /// Custom data associated with the flow.
    pub data: D,
}

impl<T, D> Flow<T, D>
where
    T: Default + Clone + Tuple + Sized,
    D: Default,
{
    pub fn new(timestamp: Timestamp, tuple: T, pkt: &Packet<'_>, dir: PacketDirection) -> Self {
        let upwards = matches!(dir, PacketDirection::Upwards);
        Self {
            start_ts: timestamp,
            last_ts: timestamp,
            src_mac: if upwards { pkt.link().source() } else { pkt.link().dest() },
            dst_mac: if upwards { pkt.link().dest() } else { pkt.link().source() },
            eth_proto: pkt.link().protocol(),
            tuple: if upwards { tuple } else { tuple.flip() },
            ..Default::default()
        }
    }
}

impl<A, T> Process for Flow<A, T>
    where T: Process,
{
    fn process<Meta: PacketMetadata>(&mut self, meta: &Meta, pkt: &Packet<'_>) {
        self.last_ts = meta.timestamp();
        let uplink = true;
        if uplink {
            self.u_bytes += meta.caplen() as usize;
            self.u_pkts += 1;
            self.u_payload_bytes += pkt.data().len();
            self.u_payload_pkts += (!pkt.data().is_empty()) as u32;
        } else {
            self.d_bytes += meta.caplen() as usize;
            self.d_pkts += 1;
            self.d_payload_bytes += pkt.data().len();
            self.d_payload_pkts += (!pkt.data().is_empty()) as u32;
        }

        self.data.process(meta, pkt);
    }
}

impl<A, T> Trackable for Flow<A, T> {
    type Timestamp = Timestamp;

    fn timestamp(&self) -> Timestamp {
        self.start_ts
    }

    fn set_timestamp(&mut self, ts: Self::Timestamp) {
        self.last_ts = ts;
    }
}

pub type FlowIpV4<T> = Flow<Ipv4Addr, T>;
pub type FlowIpV6<T> = Flow<Ipv6Addr, T>;
