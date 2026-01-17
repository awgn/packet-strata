use std::fmt::Display;

use chrono::TimeDelta;

use crate::{
    packet::{
        ether::EthAddr,
        icmp::IcmpType,
        protocol::{EtherProto, IpProto},
    },
    timestamp::Timestamp,
    tracker::vni::VniId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// Normal TCP shutdown (FIN exchange observed).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowIp<IP, T> {
    /// Flow classification (Uplink, Downlink, etc.).
    r#type: FlowType,

    /// Reason for flow termination.
    termination: Termination,

    /// IP layer statistics and info.
    ip_info: IpInfo,

    /// TCP layer statistics and info (optional).
    tcp_info: Option<TcpInfo>,

    /// Timestamp of the first packet in the flow.
    ts_start: Timestamp,

    /// Timestamp of the last packet in the flow.
    ts_last: Timestamp,

    /// Source MAC address.
    src_mac: EthAddr,

    /// Destination MAC address.
    dst_mac: EthAddr,

    /// Ethernet protocol.
    eth_proto: EtherProto,

    /// Source IP address.
    src_addr: IP,

    /// Destination IP address.
    dst_addr: IP,

    /// IP protocol (TCP, UDP, etc.).
    ip_proto: IpProto,

    /// Source port (if applicable).
    src_port: u16,

    /// Destination port (if applicable).
    dst_port: u16,

    /// Virtual Network Identifier (if applicable).
    vni: VniId,

    /// Total uplink bytes.
    u_bytes: usize,

    /// Total downlink bytes.
    d_bytes: usize,

    /// Total uplink payload bytes.
    u_payload_bytes: usize,

    /// Total downlink payload bytes.
    d_payload_bytes: usize,

    /// Total uplink packets.
    u_pkts: u32,

    /// Total downlink packets.
    d_pkts: u32,

    /// Uplink packets with payload.
    u_payload_pkts: u32,

    /// Downlink packets with payload.
    d_payload_pkts: u32,

    /// Uplink fragments count.
    u_frags: u32,

    /// Downlink fragments count.
    d_frags: u32,

    /// Custom data associated with the flow.
    data: T,
}
