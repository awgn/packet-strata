//! Pure L4 packet direction and confidence inference
//!
//! This module implements a zero-DPI, purely Layer-4 direction inference engine that
//! classifies packets into [`PacketDirection::Upwards`] (Client $\rightarrow$ Server) or
//! [`PacketDirection::Downwards`] (Server $\rightarrow$ Client) along with a two-level
//! [`Confidence`] (`High` or `Low`).
//!
//! # Inference Hierarchy
//!
//! 1. **Authoritative L4 Protocol Signals ([`Confidence::High`])**:
//!    - **TCP**: `SYN` (without `ACK`) is always `Upwards`; `SYN-ACK` is always `Downwards`.
//!    - **SCTP (RFC 4960)**: `Verification Tag == 0` or control chunks `INIT`, `COOKIE-ECHO`,
//!      `SHUTDOWN` are `Upwards`; `INIT-ACK`, `COOKIE-ACK`, `SHUTDOWN-ACK`, `SHUTDOWN-COMPLETE`
//!      are `Downwards`.
//!    - **UDP**: Fixed DHCPv4 (`68 -> 67`) and DHCPv6 (`546 -> 547`) client/server port pairs.
//!    - **ICMPv4 / ICMPv6**: Echo/Timestamp/Address/Neighbor/Router requests & solicitations are
//!      `Upwards`; replies & advertisements are `Downwards`.
//!
//! 2. **5-Tier OS-Aware Port Ranking ([`Confidence::High`] across distinct tiers)**:
//!    When no L4 handshake flag is present (e.g. mid-stream TCP/SCTP or general UDP), ports are
//!    mapped into 5 priority tiers (`0` = highest server likelihood, `4` = highest ephemeral client likelihood):
//!
//!    | Rank | Port Range / Category | Rationale |
//!    |------|-----------------------|-----------|
//!    | `0`  | `0..=1024` (System / Well-Known) | Privileged IANA system ports (HTTP `80`, HTTPS `443`, DNS `53`, SSH `22`, etc.) |
//!    | `1`  | Core Registered Service Ports (`> 1024`) | O(1) compile-time bitmap of major server ports (MySQL `3306`, PostgreSQL `5432`, Redis `6379`, Telco S1AP `36412` / NGAP `38412`, WireGuard `51820`, etc.) |
//!    | `2`  | `1025..=32767` (Lower Registered) | Below the Linux ephemeral boundary (`32768`); never allocated as ephemeral client ports by modern OSes |
//!    | `3`  | `32768..=49151` (Linux / Android Ephemeral) | Default Linux kernel `ip_local_port_range` (`32768..=60999`) |
//!    | `4`  | `49152..=65535` (IANA / Windows / macOS / BSD Ephemeral) | RFC 6335 dynamic/private client port range |
//!
//! 3. **Same-Tier Tie-Breaker ([`Confidence::Low`])**:
//!    If both ports fall into the exact same tier (e.g. two ephemeral ports `50000` and `55000`),
//!    the higher port is provisionally treated as the client (`source > dest => Upwards`) with
//!    [`Confidence::Low`], signaling that stateful L4 tracking or an external Phase 2 DPI engine
//!    may flip the flow on subsequent packets.
//!
//! # Example
//!
//! ```
//! use packet_strata::packet::iter::LinkType;
//! use packet_strata::packet::{Packet, ParseMode};
//! use packet_strata::tracker::direction::{Confidence, PacketDirection};
//!
//! // Ethernet + IPv4 + UDP response from DNS Server (1.1.1.1:53 -> 10.0.0.1:50000)
//! let raw = [
//!     0x00, 0x00, 0x00, 0x44, 0x55, 0x66,
//!     0x00, 0x00, 0x0c, 0x11, 0x22, 0x33,
//!     0x08, 0x00,
//!     0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
//!     1, 1, 1, 1,                         // Src IP: 1.1.1.1
//!     10, 0, 0, 1,                        // Dst IP: 10.0.0.1
//!     0x00, 0x35, 0xc3, 0x50,             // Src Port: 53 (Rank 0), Dst Port: 50000 (Rank 4)
//!     0x00, 0x08, 0x00, 0x00,
//! ];
//!
//! let pkt = Packet::from_bytes(&raw, LinkType::Ethernet, ParseMode::Innermost).unwrap();
//! let (dir, confidence) = PacketDirection::infer_with_confidence(&pkt);
//!
//! assert_eq!(dir, PacketDirection::Downwards);
//! assert_eq!(confidence, Confidence::High);
//! ```

use crate::packet::{
    header::TransportLayer,
    icmp::{IcmpHeader, IcmpType},
    icmp6::{Icmp6Header, Icmp6Type},
    sctp::SctpHeader,
    tcp::TcpHeaderOpt,
    Packet,
};
use serde::{Deserialize, Serialize};
use std::fmt;

// DHCP / DHCPv6 L4 fixed port pairs
const PORT_DHCP_SERVER: u16 = 67;
const PORT_DHCP_CLIENT: u16 = 68;
const PORT_DHCPV6_CLIENT: u16 = 546;
const PORT_DHCPV6_SERVER: u16 = 547;

// SCTP control chunk types (RFC 4960)
const SCTP_CHUNK_INIT: u8 = 1;
const SCTP_CHUNK_INIT_ACK: u8 = 2;
const SCTP_CHUNK_SHUTDOWN: u8 = 7;
const SCTP_CHUNK_SHUTDOWN_ACK: u8 = 8;
const SCTP_CHUNK_COOKIE_ECHO: u8 = 10;
const SCTP_CHUNK_COOKIE_ACK: u8 = 11;
const SCTP_CHUNK_SHUTDOWN_COMPLETE: u8 = 14;

/// Boundary where the Linux kernel (`net.ipv4.ip_local_port_range`) starts allocating
/// ephemeral client ports by default (`32768..=60999`).
const LINUX_EPHEMERAL_START: u16 = 32768;

/// Boundary where IANA (RFC 6335), Windows, macOS, and BSD start allocating
/// dynamic/ephemeral client ports (`49152..=65535`).
const IANA_EPHEMERAL_START: u16 = 49152;

/// Represents the confidence level of a packet/flow direction inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    #[default]
    /// Direction is uncertain (e.g. same port rank tie-breaker `source > dest`, or symmetric ports).
    /// Stateful flow tracking or an external DPI engine can confirm or flip the flow direction on subsequent packets.
    Low,
    /// Direction is certain (L4 handshake flags, SCTP control chunks, ICMP, DHCP, or distinct port ranks).
    High,
}

/// Represents the direction of a packet in a flow.
///
/// Direction is determined from the perspective of the client-server model:
/// - `Upwards`: From client to server (request/query/initiator)
/// - `Downwards`: From server to client (response/reply)
///
/// For stateless analysis (mid-connection packets), the first packet seen
/// is assumed to be from the initiator and therefore `Upwards`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketDirection {
    #[default]
    Upwards,
    Downwards,
}

impl fmt::Display for PacketDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketDirection::Upwards => write!(f, "Upwards"),
            PacketDirection::Downwards => write!(f, "Downwards"),
        }
    }
}

const REGISTERED_SERVICE_PORTS: &[u16] = &[
    1080,  // SOCKS
    1194,  // OpenVPN
    1433,  // MSSQL
    1521,  // Oracle DB
    1645,  // Old RADIUS
    1646,  // Old RADIUS Acct
    1701,  // L2TP
    1723,  // PPTP
    1812,  // RADIUS
    1813,  // RADIUS Acct
    1883,  // MQTT
    1900,  // SSDP / UPnP
    2049,  // NFS
    2083,  // cPanel SSL
    2123,  // GTP-C
    2152,  // GTP-U
    2181,  // ZooKeeper
    2375,  // Docker
    2376,  // Docker TLS
    2379,  // etcd client
    2380,  // etcd peer
    2427,  // MGCP
    2525,  // SMTP Alt
    2727,  // MGCP Call Agent
    2905,  // M3UA (SS7 over SCTP)
    2944,  // MEGACO / H.248 text
    2945,  // MEGACO / H.248 binary
    3000,  // Grafana / HTTP dev
    3128,  // Squid HTTP Proxy
    3260,  // iSCSI
    3268,  // Active Directory Global Catalog
    3269,  // Active Directory Global Catalog SSL
    3306,  // MySQL / MariaDB
    3389,  // RDP
    3478,  // STUN / TURN
    3799,  // RADIUS CoA
    3868,  // Diameter
    4222,  // NATS
    4317,  // OpenTelemetry OTLP gRPC
    4318,  // OpenTelemetry OTLP HTTP
    4500,  // IPsec NAT-T
    4789,  // VXLAN
    5000,  // UPnP / Docker Registry
    5044,  // Logstash Beats
    5060,  // SIP
    5061,  // SIPS (TLS)
    5222,  // XMPP Client
    5223,  // Apple Push Notification Service (APNS)
    5228,  // Google Cloud Messaging / FCM
    5269,  // XMPP Server
    5349,  // STUN / TURN TLS
    5353,  // mDNS
    5355,  // LLMNR
    5432,  // PostgreSQL
    5601,  // Kibana
    5671,  // AMQPS
    5672,  // AMQP (RabbitMQ)
    5868,  // Diameter TLS
    5900,  // VNC
    5984,  // CouchDB
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    6081,  // Geneve
    6379,  // Redis
    6443,  // Kubernetes API Server
    6650,  // Apache Pulsar
    8000,  // HTTP Alt
    8008,  // HTTP Alt
    8080,  // HTTP Proxy / Alt
    8081,  // HTTP Alt
    8086,  // InfluxDB
    8200,  // HashiCorp Vault
    8443,  // HTTPS Alt
    8500,  // HashiCorp Consul
    8554,  // RTSP Alt
    8805,  // PFCP (5G N4)
    8883,  // Secure MQTT
    8888,  // HTTP Alt
    9000,  // MinIO / PHP-FPM / SonarQube
    9042,  // Cassandra CQL
    9090,  // Prometheus
    9092,  // Apache Kafka
    9100,  // Prometheus Node Exporter / JetDirect
    9200,  // Elasticsearch HTTP
    9300,  // Elasticsearch Transport
    9418,  // Git protocol
    9443,  // HTTPS Alt
    10050, // Zabbix Agent
    10051, // Zabbix Server
    10250, // Kubelet API
    11211, // Memcached
    15672, // RabbitMQ Management
    26257, // CockroachDB
    27017, // MongoDB
    29118, // 3GPP SGsAP
    36412, // 3GPP S1AP (4G LTE)
    36422, // 3GPP X2AP
    38412, // 3GPP NGAP (5G NR)
    38422, // 3GPP XnAP
    51820, // WireGuard
];

/// Compile-time 8 KB bitmap (`[u64; 1024]`) of registered service ports for branchless O(1) lookup.
const SERVICE_PORT_BITMAP: [u64; 1024] = {
    let mut bm = [0u64; 1024];
    let mut i = 0;
    while i < REGISTERED_SERVICE_PORTS.len() {
        let p = REGISTERED_SERVICE_PORTS[i] as usize;
        bm[p >> 6] |= 1u64 << (p & 63);
        i += 1;
    }
    bm
};

impl PacketDirection {
    /// Infers the direction of a packet based purely on L4 transport headers and OS-aware port ranking.
    ///
    /// If the direction cannot be definitively determined, it defaults to `Upwards`.
    #[inline]
    pub fn infer(pkt: &Packet<'_>) -> PacketDirection {
        Self::infer_with_confidence(pkt).0
    }

    /// Infers both the direction of a packet and the two-level `Confidence` (`High` or `Low`)
    /// using purely L4 transport headers (TCP SYN/SYN-ACK, SCTP control chunks, ICMP/ICMPv6 types,
    /// DHCP port pairs) and the 5-tier OS-aware port rank hierarchy.
    #[inline]
    pub fn infer_with_confidence(pkt: &Packet<'_>) -> (PacketDirection, Confidence) {
        match pkt.transport() {
            Some(TransportLayer::Tcp(tcp)) => {
                if let Some(dir) = Self::infer_tcp_l4(tcp) {
                    (dir, Confidence::High)
                } else {
                    Self::infer_direction_from_ports(tcp.src_port(), tcp.dst_port())
                        .unwrap_or((PacketDirection::Upwards, Confidence::Low))
                }
            }
            Some(TransportLayer::Udp(udp)) => {
                let src = udp.src_port();
                let dst = udp.dst_port();
                if let Some(dir) = Self::infer_udp_l4(src, dst) {
                    (dir, Confidence::High)
                } else {
                    Self::infer_direction_from_ports(src, dst)
                        .unwrap_or((PacketDirection::Upwards, Confidence::Low))
                }
            }
            Some(TransportLayer::Sctp(sctp)) => {
                if let Some(dir) = Self::infer_sctp_l4(sctp, pkt.data()) {
                    (dir, Confidence::High)
                } else {
                    Self::infer_direction_from_ports(sctp.src_port(), sctp.dst_port())
                        .unwrap_or((PacketDirection::Upwards, Confidence::Low))
                }
            }
            Some(TransportLayer::Icmp(icmp)) => (Self::infer_icmp(icmp), Confidence::High),
            Some(TransportLayer::Icmp6(icmp6)) => (Self::infer_icmp6(icmp6), Confidence::High),
            None => (PacketDirection::Upwards, Confidence::Low),
        }
    }

    /// Infers the direction of a packet when the flow tuple is symmetric (`src == dst` and `src_port == dst_port`).
    ///
    /// Evaluates L4 handshake/control flags and ICMP types, defaulting to `Upwards` when L4 is symmetric.
    #[cold]
    #[inline]
    pub fn infer_symmetric(pkt: &Packet<'_>) -> PacketDirection {
        Self::infer_l4_handshake(pkt).unwrap_or(PacketDirection::Upwards)
    }

    /// Evaluates only definitive (`Confidence::High`) L4 protocol handshake/control signals
    /// without falling back to port-number comparisons.
    ///
    /// Used by stateful flow tracking when `flow.base.confidence == Confidence::Low` and no external
    /// DPI direction was provided.
    #[inline]
    pub fn infer_l4_handshake(pkt: &Packet<'_>) -> Option<PacketDirection> {
        match pkt.transport() {
            Some(TransportLayer::Tcp(tcp)) => Self::infer_tcp_l4(tcp),
            Some(TransportLayer::Udp(udp)) => Self::infer_udp_l4(udp.src_port(), udp.dst_port()),
            Some(TransportLayer::Sctp(sctp)) => Self::infer_sctp_l4(sctp, pkt.data()),
            Some(TransportLayer::Icmp(icmp)) => Some(Self::infer_icmp(icmp)),
            Some(TransportLayer::Icmp6(icmp6)) => Some(Self::infer_icmp6(icmp6)),
            None => None,
        }
    }

    /// Pure L4 TCP connection establishment inspection (`SYN` vs `SYN-ACK`).
    #[inline(always)]
    fn infer_tcp_l4(tcp: &TcpHeaderOpt<'_>) -> Option<PacketDirection> {
        if tcp.header.has_syn() {
            Some(if tcp.header.has_ack() {
                PacketDirection::Downwards // SYN-ACK (Server -> Client)
            } else {
                PacketDirection::Upwards // SYN (Client -> Server)
            })
        } else {
            None
        }
    }

    /// Pure L4 UDP fixed client/server port-pair inspection (DHCPv4 and DHCPv6).
    #[inline(always)]
    fn infer_udp_l4(source: u16, dest: u16) -> Option<PacketDirection> {
        match (source, dest) {
            (PORT_DHCP_CLIENT, PORT_DHCP_SERVER) | (PORT_DHCPV6_CLIENT, PORT_DHCPV6_SERVER) => {
                Some(PacketDirection::Upwards)
            }
            (PORT_DHCP_SERVER, PORT_DHCP_CLIENT) | (PORT_DHCPV6_SERVER, PORT_DHCPV6_CLIENT) => {
                Some(PacketDirection::Downwards)
            }
            _ => None,
        }
    }

    /// Pure L4 SCTP direction inference based on verification tag and control chunk type (RFC 4960).
    #[inline(always)]
    fn infer_sctp_l4(sctp: &SctpHeader, data: &[u8]) -> Option<PacketDirection> {
        // RFC 4960 Section 3.1: Verification Tag == 0 is only permitted on INIT packets
        if sctp.verification_tag() == 0 {
            return Some(PacketDirection::Upwards);
        }

        if data.len() >= 4 {
            match data[0] {
                SCTP_CHUNK_INIT | SCTP_CHUNK_COOKIE_ECHO | SCTP_CHUNK_SHUTDOWN => {
                    return Some(PacketDirection::Upwards);
                }
                SCTP_CHUNK_INIT_ACK
                | SCTP_CHUNK_COOKIE_ACK
                | SCTP_CHUNK_SHUTDOWN_ACK
                | SCTP_CHUNK_SHUTDOWN_COMPLETE => {
                    return Some(PacketDirection::Downwards);
                }
                _ => {}
            }
        }

        None
    }

    #[inline]
    fn infer_icmp(icmp: &IcmpHeader) -> PacketDirection {
        match icmp.icmp_type() {
            IcmpType::ECHO => PacketDirection::Upwards,
            IcmpType::ECHO_REPLY => PacketDirection::Downwards,
            IcmpType::TIMESTAMP => PacketDirection::Upwards,
            IcmpType::TIMESTAMP_REPLY => PacketDirection::Downwards,
            IcmpType::INFO_REQUEST => PacketDirection::Upwards,
            IcmpType::INFO_REPLY => PacketDirection::Downwards,
            IcmpType::ADDRESS => PacketDirection::Upwards,
            IcmpType::ADDRESS_REPLY => PacketDirection::Downwards,
            IcmpType::EX_ECHO => PacketDirection::Upwards,
            IcmpType::EX_ECHO_REPLY => PacketDirection::Downwards,
            IcmpType::DEST_UNREACH => PacketDirection::Upwards,
            IcmpType::SOURCE_QUENCH => PacketDirection::Upwards,
            IcmpType::REDIRECT => PacketDirection::Upwards,
            IcmpType::ROUTER_ADV => PacketDirection::Downwards,
            IcmpType::ROUTER_SOLICIT => PacketDirection::Upwards,
            IcmpType::TIME_EXCEEDED => PacketDirection::Upwards,
            IcmpType::PARAMETER_PROBLEM => PacketDirection::Upwards,
            _ => PacketDirection::Upwards,
        }
    }

    #[inline]
    fn infer_icmp6(icmp6: &Icmp6Header) -> PacketDirection {
        match icmp6.icmp6_type() {
            Icmp6Type::DST_UNREACH => PacketDirection::Upwards,
            Icmp6Type::PACKET_TOO_BIG => PacketDirection::Upwards,
            Icmp6Type::TIME_EXCEEDED => PacketDirection::Upwards,
            Icmp6Type::PARAM_PROB => PacketDirection::Upwards,
            Icmp6Type::ECHO_REQUEST => PacketDirection::Upwards,
            Icmp6Type::ECHO_REPLY => PacketDirection::Downwards,
            Icmp6Type::MLD_LISTENER_QUERY => PacketDirection::Downwards,
            Icmp6Type::MLD_LISTENER_REPORT => PacketDirection::Upwards,
            Icmp6Type::MLD_LISTENER_REDUCTION => PacketDirection::Upwards,
            Icmp6Type::ROUTER_SOLICITATION => PacketDirection::Upwards,
            Icmp6Type::ROUTER_ADVERTISEMENT => PacketDirection::Downwards,
            Icmp6Type::NEIGHBOR_SOLICITATION => PacketDirection::Upwards,
            Icmp6Type::NEIGHBOR_ADVERTISEMENT => PacketDirection::Downwards,
            Icmp6Type::REDIRECT_MESSAGE => PacketDirection::Upwards,
            Icmp6Type::ROUTER_RENUMBERING => PacketDirection::Downwards,
            Icmp6Type::NODE_INFORMATION_QUERY => PacketDirection::Upwards,
            Icmp6Type::NODE_INFORMATION_RESPONSE => PacketDirection::Downwards,
            Icmp6Type::INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION => PacketDirection::Upwards,
            Icmp6Type::INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT => PacketDirection::Downwards,
            Icmp6Type::MULTICAST_LISTENER_DISCOVERY_REPORTS => PacketDirection::Upwards,
            Icmp6Type::HOME_AGENT_ADDRESS_DISCOVERY_REQUEST => PacketDirection::Upwards,
            Icmp6Type::HOME_AGENT_ADDRESS_DISCOVERY_REPLY => PacketDirection::Downwards,
            Icmp6Type::MOBILE_PREFIX_SOLICITATION => PacketDirection::Upwards,
            Icmp6Type::MOBILE_PREFIX_ADVERTISEMENT => PacketDirection::Downwards,
            Icmp6Type::MULTICAST_ROUTER_SOLICITATION => PacketDirection::Upwards,
            Icmp6Type::MULTICAST_ROUTER_TERMINATION => PacketDirection::Upwards,
            Icmp6Type::FMIPV6 => PacketDirection::Upwards,
            Icmp6Type::RPL_CONTROL_MESSAGE => PacketDirection::Upwards,
            Icmp6Type::ILNPV6_LOCATOR_UPDATE => PacketDirection::Upwards,
            Icmp6Type::DUPLICATE_ADDRESS_REQUEST => PacketDirection::Upwards,
            Icmp6Type::DUPLICATE_ADDRESS_CONFIRM => PacketDirection::Downwards,
            Icmp6Type::MPL_CONTROL_MESSAGE => PacketDirection::Upwards,
            Icmp6Type::EXTENDED_ECHO_REQUEST => PacketDirection::Upwards,
            Icmp6Type::EXTENDED_ECHO_REPLY => PacketDirection::Downwards,
            _ => PacketDirection::Upwards,
        }
    }

    /// Returns `true` if `p` (> 1024) is a standard IANA-registered core server port
    /// (Databases, Telco/3GPP, Tunneling, Cloud, Messaging, Security, Media).
    #[inline(always)]
    pub(crate) const fn is_registered_service_port(p: u16) -> bool {
        (SERVICE_PORT_BITMAP[(p >> 6) as usize] & (1u64 << (p & 63))) != 0
    }

    /// Classifies a port into a 5-tier OS-aware server priority rank (`0` = highest server priority, `4` = lowest):
    /// - Rank `0`: System / Well-Known Ports (`0..=1024`)
    /// - Rank `1`: Core IANA Registered Service Ports (`> 1024`, including Telco S1AP/NGAP and WireGuard `51820`)
    /// - Rank `2`: Lower Registered Ports (`1025..=32767`) — never allocated as ephemeral client ports by modern OSes
    /// - Rank `3`: Linux / Android Ephemeral Range (`32768..=49151`)
    /// - Rank `4`: IANA / Windows / macOS / BSD Ephemeral Range (`49152..=65535`)
    #[inline(always)]
    pub(crate) fn port_rank(p: u16) -> u8 {
        if p <= 1024 {
            0
        } else if Self::is_registered_service_port(p) {
            1
        } else if p < LINUX_EPHEMERAL_START {
            2
        } else if p < IANA_EPHEMERAL_START {
            3
        } else {
            4
        }
    }

    /// Infers direction based on the 5-tier OS-aware port classification.
    ///
    /// Returns `Confidence::High` when port ranks differ, and `Confidence::Low` when both ports
    /// fall into the same rank (tie-breaker `source > dest`).
    #[inline(always)]
    fn infer_direction_from_ports(source: u16, dest: u16) -> Option<(PacketDirection, Confidence)> {
        if source == dest {
            return None;
        }

        let src_rank = Self::port_rank(source);
        let dst_rank = Self::port_rank(dest);

        match src_rank.cmp(&dst_rank) {
            std::cmp::Ordering::Greater => Some((PacketDirection::Upwards, Confidence::High)),
            std::cmp::Ordering::Less => Some((PacketDirection::Downwards, Confidence::High)),
            std::cmp::Ordering::Equal => {
                if source > dest {
                    Some((PacketDirection::Upwards, Confidence::Low))
                } else {
                    Some((PacketDirection::Downwards, Confidence::Low))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{iter::LinkType, Packet, ParseMode};

    fn build_ipv4_packet(proto: u8, l4_and_payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + l4_and_payload.len()) as u16;
        let mut buf = Vec::with_capacity(14 + total_len as usize);
        buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        buf.extend_from_slice(&[0x08, 0x00]);
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]);
        buf.push(64);
        buf.push(proto);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&[10, 0, 0, 2]);
        buf.extend_from_slice(l4_and_payload);
        buf
    }

    fn build_ipv6_packet(next_hdr: u8, l4_and_payload: &[u8]) -> Vec<u8> {
        let payload_len = l4_and_payload.len() as u16;
        let mut buf = Vec::with_capacity(14 + 40 + l4_and_payload.len());
        buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        buf.extend_from_slice(&[0x86, 0xdd]);
        buf.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.push(next_hdr);
        buf.push(64);
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        buf.extend_from_slice(l4_and_payload);
        buf
    }

    fn build_tcp_packet(src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::with_capacity(20 + payload.len());
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.push(0x50);
        tcp.push(flags);
        tcp.extend_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&[0x00, 0x00]);
        tcp.extend_from_slice(&[0x00, 0x00]);
        tcp.extend_from_slice(payload);
        build_ipv4_packet(6, &tcp)
    }

    fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let len = (8 + payload.len()) as u16;
        let mut udp = Vec::with_capacity(len as usize);
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&len.to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]);
        udp.extend_from_slice(payload);
        build_ipv4_packet(17, &udp)
    }

    fn build_sctp_packet(src_port: u16, dst_port: u16, vtag: u32, payload: &[u8]) -> Vec<u8> {
        let mut sctp = Vec::with_capacity(12 + payload.len());
        sctp.extend_from_slice(&src_port.to_be_bytes());
        sctp.extend_from_slice(&dst_port.to_be_bytes());
        sctp.extend_from_slice(&vtag.to_be_bytes());
        sctp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        sctp.extend_from_slice(payload);
        build_ipv4_packet(132, &sctp)
    }

    fn build_icmp_packet(icmp_type: u8) -> Vec<u8> {
        let icmp = [icmp_type, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        build_ipv4_packet(1, &icmp)
    }

    fn build_icmp6_packet(icmp6_type: u8) -> Vec<u8> {
        let icmp6 = [icmp6_type, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        build_ipv6_packet(58, &icmp6)
    }

    fn infer_bytes(raw: &[u8]) -> PacketDirection {
        let pkt = Packet::from_bytes(raw, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        PacketDirection::infer(&pkt)
    }

    fn infer_with_conf_bytes(raw: &[u8]) -> (PacketDirection, Confidence) {
        let pkt = Packet::from_bytes(raw, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        PacketDirection::infer_with_confidence(&pkt)
    }

    fn infer_symmetric_bytes(raw: &[u8]) -> PacketDirection {
        let pkt = Packet::from_bytes(raw, LinkType::Ethernet, ParseMode::Outermost).unwrap();
        PacketDirection::infer_symmetric(&pkt)
    }

    #[test]
    fn test_display_and_default() {
        assert_eq!(PacketDirection::default(), PacketDirection::Upwards);
        assert_eq!(Confidence::default(), Confidence::Low);
        assert_eq!(format!("{}", PacketDirection::Upwards), "Upwards");
        assert_eq!(format!("{}", PacketDirection::Downwards), "Downwards");
    }

    #[test]
    fn test_tcp_syn_and_syn_ack() {
        // SYN (0x02) -> Upwards with High confidence even when src_port < dst_port
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(80, 50000, 0x02, &[])),
            (PacketDirection::Upwards, Confidence::High)
        );
        // SYN-ACK (0x12) -> Downwards with High confidence even when src_port > dst_port
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(50000, 80, 0x12, &[])),
            (PacketDirection::Downwards, Confidence::High)
        );
        // Symmetric ports with SYN / SYN-ACK
        assert_eq!(
            infer_symmetric_bytes(&build_tcp_packet(80, 80, 0x02, &[])),
            PacketDirection::Upwards
        );
        assert_eq!(
            infer_symmetric_bytes(&build_tcp_packet(80, 80, 0x12, &[])),
            PacketDirection::Downwards
        );
    }

    #[test]
    fn test_five_tier_port_ranks_and_linux_ephemeral_split() {
        // Rank 0 (0..=1024) vs Rank 1 (known service > 1024, e.g. 8080) -> Confidence::High
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(8080, 443, 0x10, &[])),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(443, 8080, 0x10, &[])),
            (PacketDirection::Downwards, Confidence::High)
        );

        // Rank 1 (known service > 1024, e.g. 3306 MySQL, 51820 WireGuard, 38412 NGAP) vs Rank 2/3/4 -> Confidence::High
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(15000, 3306, 0x10, &[])),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(3306, 15000, 0x10, &[])),
            (PacketDirection::Downwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_udp_packet(40000, 51820, &[0u8; 32])),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_udp_packet(51820, 40000, &[0u8; 32])),
            (PacketDirection::Downwards, Confidence::High)
        );

        // Rank 2 (Lower Registered 1025..=32767, e.g. custom server port 12000)
        // vs Rank 3 (Linux Ephemeral 32768..=49151, e.g. client port 38000) -> Confidence::High!
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(38000, 12000, 0x10, &[])),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(12000, 38000, 0x10, &[])),
            (PacketDirection::Downwards, Confidence::High)
        );

        // Rank 3 (32768..=49151) vs Rank 4 (49152..=65535) -> Confidence::High
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(52000, 35000, 0x10, &[])),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(35000, 52000, 0x10, &[])),
            (PacketDirection::Downwards, Confidence::High)
        );

        // Same rank: tie-breaker source > dest with Confidence::Low
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(55001, 55000, 0x10, &[])),
            (PacketDirection::Upwards, Confidence::Low)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(55000, 55001, 0x10, &[])),
            (PacketDirection::Downwards, Confidence::Low)
        );

        // Symmetric ports -> Upwards fallback with Confidence::Low
        assert_eq!(
            infer_with_conf_bytes(&build_tcp_packet(55000, 55000, 0x10, &[])),
            (PacketDirection::Upwards, Confidence::Low)
        );
        assert_eq!(
            infer_symmetric_bytes(&build_tcp_packet(55000, 55000, 0x10, &[])),
            PacketDirection::Upwards
        );
    }

    #[test]
    fn test_udp_dhcp_port_pairs() {
        assert_eq!(
            infer_with_conf_bytes(&build_udp_packet(PORT_DHCP_CLIENT, PORT_DHCP_SERVER, &[])),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_udp_packet(PORT_DHCP_SERVER, PORT_DHCP_CLIENT, &[])),
            (PacketDirection::Downwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_udp_packet(
                PORT_DHCPV6_CLIENT,
                PORT_DHCPV6_SERVER,
                &[]
            )),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_udp_packet(
                PORT_DHCPV6_SERVER,
                PORT_DHCPV6_CLIENT,
                &[]
            )),
            (PacketDirection::Downwards, Confidence::High)
        );
    }

    #[test]
    fn test_sctp_chunks_and_ports() {
        // 1. vtag == 0 -> Upwards (INIT) even if src_port < dst_port
        assert_eq!(
            infer_with_conf_bytes(&build_sctp_packet(80, 50000, 0, &[])),
            (PacketDirection::Upwards, Confidence::High)
        );

        // 2. INIT (1), COOKIE_ECHO (10), SHUTDOWN (7) -> Upwards
        for chunk_type in [SCTP_CHUNK_INIT, SCTP_CHUNK_COOKIE_ECHO, SCTP_CHUNK_SHUTDOWN] {
            let chunk = [chunk_type, 0x00, 0x00, 0x04];
            assert_eq!(
                infer_with_conf_bytes(&build_sctp_packet(80, 50000, 0x12345678, &chunk)),
                (PacketDirection::Upwards, Confidence::High)
            );
            assert_eq!(
                infer_symmetric_bytes(&build_sctp_packet(2905, 2905, 0x12345678, &chunk)),
                PacketDirection::Upwards
            );
        }

        // 3. INIT_ACK (2), COOKIE_ACK (11), SHUTDOWN_ACK (8), SHUTDOWN_COMPLETE (14) -> Downwards
        for chunk_type in [
            SCTP_CHUNK_INIT_ACK,
            SCTP_CHUNK_COOKIE_ACK,
            SCTP_CHUNK_SHUTDOWN_ACK,
            SCTP_CHUNK_SHUTDOWN_COMPLETE,
        ] {
            let chunk = [chunk_type, 0x00, 0x00, 0x04];
            assert_eq!(
                infer_with_conf_bytes(&build_sctp_packet(50000, 80, 0x12345678, &chunk)),
                (PacketDirection::Downwards, Confidence::High)
            );
            assert_eq!(
                infer_symmetric_bytes(&build_sctp_packet(2905, 2905, 0x12345678, &chunk)),
                PacketDirection::Downwards
            );
        }

        // 4. SCTP Port Rank fallback when no control chunk is present (e.g. DATA chunk type 0)
        let data_chunk = [0x00, 0x00, 0x00, 0x10];
        assert_eq!(
            infer_with_conf_bytes(&build_sctp_packet(50000, 38412, 0x12345678, &data_chunk)),
            (PacketDirection::Upwards, Confidence::High)
        );
        assert_eq!(
            infer_with_conf_bytes(&build_sctp_packet(38412, 50000, 0x12345678, &data_chunk)),
            (PacketDirection::Downwards, Confidence::High)
        );

        // 5. Unknown IP proto (e.g. OSPF = 89) -> transport is None -> Upwards with Confidence::Low
        assert_eq!(
            infer_with_conf_bytes(&build_ipv4_packet(89, &[0u8; 16])),
            (PacketDirection::Upwards, Confidence::Low)
        );
        assert_eq!(
            infer_symmetric_bytes(&build_ipv4_packet(89, &[0u8; 16])),
            PacketDirection::Upwards
        );
    }

    #[test]
    fn test_icmpv4_all_types() {
        let upwards_types = [
            IcmpType::ECHO,
            IcmpType::TIMESTAMP,
            IcmpType::INFO_REQUEST,
            IcmpType::ADDRESS,
            IcmpType::EX_ECHO,
            IcmpType::DEST_UNREACH,
            IcmpType::SOURCE_QUENCH,
            IcmpType::REDIRECT,
            IcmpType::ROUTER_SOLICIT,
            IcmpType::TIME_EXCEEDED,
            IcmpType::PARAMETER_PROBLEM,
            IcmpType(254),
        ];
        for t in upwards_types {
            assert_eq!(
                infer_bytes(&build_icmp_packet(t.0)),
                PacketDirection::Upwards,
                "ICMPv4 type {:?} should be Upwards",
                t
            );
        }

        let downwards_types = [
            IcmpType::ECHO_REPLY,
            IcmpType::TIMESTAMP_REPLY,
            IcmpType::INFO_REPLY,
            IcmpType::ADDRESS_REPLY,
            IcmpType::EX_ECHO_REPLY,
            IcmpType::ROUTER_ADV,
        ];
        for t in downwards_types {
            assert_eq!(
                infer_bytes(&build_icmp_packet(t.0)),
                PacketDirection::Downwards,
                "ICMPv4 type {:?} should be Downwards",
                t
            );
        }
    }

    #[test]
    fn test_icmpv6_all_types() {
        let upwards_types = [
            Icmp6Type::DST_UNREACH,
            Icmp6Type::PACKET_TOO_BIG,
            Icmp6Type::TIME_EXCEEDED,
            Icmp6Type::PARAM_PROB,
            Icmp6Type::ECHO_REQUEST,
            Icmp6Type::MLD_LISTENER_REPORT,
            Icmp6Type::MLD_LISTENER_REDUCTION,
            Icmp6Type::ROUTER_SOLICITATION,
            Icmp6Type::NEIGHBOR_SOLICITATION,
            Icmp6Type::REDIRECT_MESSAGE,
            Icmp6Type::NODE_INFORMATION_QUERY,
            Icmp6Type::INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION,
            Icmp6Type::MULTICAST_LISTENER_DISCOVERY_REPORTS,
            Icmp6Type::HOME_AGENT_ADDRESS_DISCOVERY_REQUEST,
            Icmp6Type::MOBILE_PREFIX_SOLICITATION,
            Icmp6Type::MULTICAST_ROUTER_SOLICITATION,
            Icmp6Type::MULTICAST_ROUTER_TERMINATION,
            Icmp6Type::FMIPV6,
            Icmp6Type::RPL_CONTROL_MESSAGE,
            Icmp6Type::ILNPV6_LOCATOR_UPDATE,
            Icmp6Type::DUPLICATE_ADDRESS_REQUEST,
            Icmp6Type::MPL_CONTROL_MESSAGE,
            Icmp6Type::EXTENDED_ECHO_REQUEST,
            Icmp6Type(254),
        ];
        for t in upwards_types {
            assert_eq!(
                infer_bytes(&build_icmp6_packet(t.0)),
                PacketDirection::Upwards,
                "ICMPv6 type {:?} should be Upwards",
                t
            );
        }

        let downwards_types = [
            Icmp6Type::ECHO_REPLY,
            Icmp6Type::MLD_LISTENER_QUERY,
            Icmp6Type::ROUTER_ADVERTISEMENT,
            Icmp6Type::NEIGHBOR_ADVERTISEMENT,
            Icmp6Type::ROUTER_RENUMBERING,
            Icmp6Type::NODE_INFORMATION_RESPONSE,
            Icmp6Type::INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT,
            Icmp6Type::HOME_AGENT_ADDRESS_DISCOVERY_REPLY,
            Icmp6Type::MOBILE_PREFIX_ADVERTISEMENT,
            Icmp6Type::DUPLICATE_ADDRESS_CONFIRM,
            Icmp6Type::EXTENDED_ECHO_REPLY,
        ];
        for t in downwards_types {
            assert_eq!(
                infer_bytes(&build_icmp6_packet(t.0)),
                PacketDirection::Downwards,
                "ICMPv6 type {:?} should be Downwards",
                t
            );
        }
    }
}
