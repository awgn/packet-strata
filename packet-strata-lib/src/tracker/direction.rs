use crate::packet::{header::TransportLayer, icmp::IcmpType, icmp6::Icmp6Type, Packet};
use std::{cmp::Ordering, fmt};

// Well-known ports
const PORT_DNS: u16 = 53;
const PORT_DHCP_SERVER: u16 = 67;
const PORT_DHCP_CLIENT: u16 = 68;
const PORT_NTP: u16 = 123;
const PORT_NETBIOS_NS: u16 = 137;
const PORT_NETBIOS_DGM: u16 = 138;
const PORT_SNMP: u16 = 161;
const PORT_SNMP_TRAP: u16 = 162;
const PORT_CLDAP: u16 = 389;
const PORT_HTTPS: u16 = 443;
const PORT_IKE: u16 = 500;
const PORT_SYSLOG: u16 = 514;
const PORT_RIP: u16 = 520;
const PORT_DHCPV6_CLIENT: u16 = 546;
const PORT_DHCPV6_SERVER: u16 = 547;
const PORT_OPENVPN: u16 = 1194;
const PORT_SSDP: u16 = 1900;
const PORT_IPSEC_NATT: u16 = 4500;
const PORT_MDNS: u16 = 5353;
const PORT_LLMNR: u16 = 5355;
const PORT_HTTPS_ALT: u16 = 8443;
const PORT_HTTP: u16 = 80;
const PORT_HTTP_ALT: u16 = 8080;
const PORT_STUN: u16 = 3478;
const PORT_STUN_TLS: u16 = 5349;

// Protocol constants
const DNS_QR_BIT_MASK: u8 = 0x80;
const NTP_MODE_MASK: u8 = 0x07;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;

/// Represents the direction of a packet in a flow.
///
/// Direction is determined from the perspective of the client-server model:
/// - `Upwards`: From client to server (request/query/initiator)
/// - `Downwards`: From server to client (response/reply)
///
/// For stateless analysis (mid-connection packets), the first packet seen
/// is assumed to be from the initiator and therefore `Upwards`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

impl PacketDirection {
    /// Infers the direction of a packet based on transport layer information.
    ///
    /// This method determines if a packet is `Upwards` (Client -> Server) or `Downwards` (Server -> Client) using:
    /// - **TCP**: Analysis of SYN/SYN-ACK flags and well-known ports.
    /// - **UDP**: Well-known ports (DNS, DHCP, NTP) and lightweight payload inspection (DPI Lite).
    /// - **ICMP**: Message types (e.g., Echo Request vs Echo Reply).
    ///
    /// If the direction cannot be definitively determined, it defaults to `Upwards`.
    pub fn infer(pkt: &Packet<'_>) -> PacketDirection {
        let transport = pkt.transport();
        match transport {
            Some(TransportLayer::Tcp(tcp)) => {
                // TCP: Use SYN/SYN-ACK for connection establishment
                if tcp.header.has_syn() {
                    if tcp.header.has_ack() {
                        return PacketDirection::Downwards; // SYN-ACK
                    } else {
                        return PacketDirection::Upwards; // SYN
                    }
                }

                return Self::infer_direction_tcp(tcp.src_port(), tcp.dst_port(), pkt.data());
            }
            Some(TransportLayer::Udp(udp)) => {
                Self::infer_direction_udp(udp.src_port(), udp.dst_port(), pkt.data())
            }

            Some(TransportLayer::Icmp(icmp)) => match icmp.icmp_type() {
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
            },
            Some(TransportLayer::Icmp6(icmp6)) => match icmp6.icmp6_type() {
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
            },
            Some(TransportLayer::Sctp(_)) | None => PacketDirection::Upwards,
        }
    }

    /// Simplified UDP direction inference: port-based + minimal DPI (max 2 bytes)
    ///
    /// DPI Lite checks:
    /// - DHCP: port pairs
    /// - DNS: QR bit (byte 2)
    /// - NTP: mode field (byte 0)
    /// - Payload length heuristic for symmetric traffic
    fn infer_direction_udp(source: u16, dest: u16, data: &[u8]) -> PacketDirection {
        // --- 1. Exact Port Pairs ---
        match (source, dest) {
            (PORT_DHCP_CLIENT, PORT_DHCP_SERVER) | (PORT_DHCPV6_CLIENT, PORT_DHCPV6_SERVER) => {
                return PacketDirection::Upwards;
            }
            (PORT_DHCP_SERVER, PORT_DHCP_CLIENT) | (PORT_DHCPV6_SERVER, PORT_DHCPV6_CLIENT) => {
                return PacketDirection::Downwards;
            }
            _ => {}
        }

        // --- 2. Minimal DPI ---

        // Extended DNS family (DNS, mDNS, LLMNR, NetBIOS NS)
        if (matches!(source, PORT_DNS | PORT_MDNS | PORT_LLMNR | PORT_NETBIOS_NS)
            || matches!(dest, PORT_DNS | PORT_MDNS | PORT_LLMNR | PORT_NETBIOS_NS))
            && source != dest
            && data.len() >= 3
        {
            let is_response = (data[2] & DNS_QR_BIT_MASK) != 0;
            return if is_response { PacketDirection::Downwards } else { PacketDirection::Upwards };
        }

        // SSDP (UDP 1900)
        if (source == PORT_SSDP || dest == PORT_SSDP) && data.len() >= 8 {
            if data.starts_with(b"HTTP/1.") {
                return PacketDirection::Downwards;
            }
            if data.starts_with(b"M-SE") {
                return PacketDirection::Upwards;
            }
        }

        // QUIC (UDP 443)
        if (source == PORT_HTTPS || dest == PORT_HTTPS) && data.len() >= 1200 {
            if (data[0] & 0xC0) == 0xC0 {
                return PacketDirection::Upwards;
            }
        }

        // STUN / WebRTC (UDP 3478, 5349)
        if (source == PORT_STUN || dest == PORT_STUN || source == PORT_STUN_TLS || dest == PORT_STUN_TLS) && data.len() >= 20 {
            if (data[0] & 0xC0) == 0x00 {
                let msg_type = ((data[0] as u16) << 8) | (data[1] as u16);
                let is_response = (msg_type & 0x0110) != 0;
                return if is_response { PacketDirection::Downwards } else { PacketDirection::Upwards };
            }
        }

        // NTP - Mode field in byte 0 (bits 0-2)
        if (source == PORT_NTP || dest == PORT_NTP) && !data.is_empty() {
            match data[0] & NTP_MODE_MASK {
                1 | 3 => return PacketDirection::Upwards,   // Symmetric Active, Client
                2 | 4 | 5 => return PacketDirection::Downwards, // Symmetric Passive, Server, Broadcast
                _ => {
                    if source != dest {
                        return if dest == PORT_NTP { PacketDirection::Upwards } else { PacketDirection::Downwards };
                    }
                }
            }
        }

        // --- 3. Payload Length Heuristic for Symmetric Traffic ---
        if source == dest {
            let threshold = match source {
                PORT_DNS => Some(64),          // DNS (queries typically < 64 bytes)
                PORT_NTP => Some(48),          // NTP (request = 48 bytes exactly in v3/v4)
                PORT_NETBIOS_NS => Some(60),   // NetBIOS Name Service
                PORT_NETBIOS_DGM => Some(100), // NetBIOS Datagram
                PORT_SNMP => Some(80),         // SNMP
                PORT_SNMP_TRAP => Some(80),    // SNMP Traps
                PORT_CLDAP => Some(150),       // CLDAP
                PORT_IKE => Some(200),         // IKE (initiator packets often smaller in phase 1)
                PORT_SYSLOG => Some(200), // Syslog (assume larger = more log data = server aggregating)
                PORT_RIP => Some(60),     // RIP (requests are smaller)
                PORT_OPENVPN => Some(100), // OpenVPN
                PORT_SSDP => Some(200),   // SSDP (M-SEARCH requests are small)
                PORT_IPSEC_NATT => Some(200), // IPsec NAT-T
                PORT_MDNS => Some(80),    // mDNS
                PORT_LLMNR => Some(64),   // LLMNR
                _ => None,
            };

            if let Some(t) = threshold {
                return if data.len() <= t {
                    PacketDirection::Upwards
                } else {
                    PacketDirection::Downwards
                };
            }
        }

        // --- 4. Port Rank Logic ---
        Self::infer_direction_from_ports(source, dest).unwrap_or(PacketDirection::Upwards)
    }

    /// Simplified TCP direction inference: port-based + minimal DPI (max 2 bytes)
    ///
    /// DPI Lite checks:
    /// - TLS: ContentType (byte 0) + Handshake type (byte 5)
    /// - DNS over TCP: QR bit (byte 4, after 2-byte length prefix)
    fn infer_direction_tcp(source: u16, dest: u16, data: &[u8]) -> PacketDirection {
        // --- 1. Minimal DPI (port + max 2 bytes) ---

        // HTTP (TCP 80, 8080)
        if (source == PORT_HTTP || dest == PORT_HTTP || source == PORT_HTTP_ALT || dest == PORT_HTTP_ALT) && data.len() >= 8 {
            if data.starts_with(b"HTTP/1.") {
                return PacketDirection::Downwards;
            }
            if data.starts_with(b"GET ") || data.starts_with(b"POST") || data.starts_with(b"PUT ") || data.starts_with(b"HEAD") {
                return PacketDirection::Upwards;
            }
        }

        // TLS - ContentType (byte 0) and Handshake type (byte 5)
        if (source == PORT_HTTPS
            || dest == PORT_HTTPS
            || source == PORT_HTTPS_ALT
            || dest == PORT_HTTPS_ALT)
            && data.len() >= 6
        {
            if data[0] == TLS_HANDSHAKE_CONTENT_TYPE {
                // ContentType 0x16 = Handshake
                let handshake_type = data[5];
                return match handshake_type {
                    TLS_CLIENT_HELLO => PacketDirection::Upwards, // ClientHello
                    TLS_SERVER_HELLO => PacketDirection::Downwards, // ServerHello
                    _ => {
                        if dest == PORT_HTTPS || dest == PORT_HTTPS_ALT {
                            PacketDirection::Upwards
                        } else {
                            PacketDirection::Downwards
                        }
                    }
                };
            }
        }

        // DNS over TCP - QR bit at byte 4 (after 2-byte length prefix, then byte 2 of DNS)
        if (source == PORT_DNS || dest == PORT_DNS) && data.len() >= 5 {
            let is_response = (data[4] & DNS_QR_BIT_MASK) != 0;
            return if is_response {
                PacketDirection::Downwards
            } else {
                PacketDirection::Upwards
            };
        }

        // --- 2. Port Rank Logic ---
        Self::infer_direction_from_ports(source, dest).unwrap_or(PacketDirection::Upwards)
    }

    /// Infers direction based on port hierarchy: System (≤1024) < User (1025-49151) < Dynamic (>49151)
    /// Falls back to absolute port number comparison if ranks are equal
    fn infer_direction_from_ports(source: u16, dest: u16) -> Option<PacketDirection> {
        if source == dest {
            return None; // Could not determine direction from identical ports.
        }

        let port_rank = |p: u16| -> u8 {
            match p {
                0..=1024 => 0,
                1025..=49151 => 1,
                49152..=u16::MAX => 2,
            }
        };

        match port_rank(source).cmp(&port_rank(dest)) {
            Ordering::Greater => Some(PacketDirection::Upwards), // Client (high rank) → Server (low rank)
            Ordering::Less => Some(PacketDirection::Downwards), // Server (low rank) → Client (high rank)
            Ordering::Equal => {
                if source > dest {
                    Some(PacketDirection::Upwards)
                } else {
                    Some(PacketDirection::Downwards)
                }
            }
        }
    }
}
