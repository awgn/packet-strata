use crate::packet::{header::TransportLayer, icmp::IcmpType, icmp6::Icmp6Type, Packet};
use std::fmt;

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

                return Self::infer_by_ports_and_payload_tcp(
                    tcp.src_port(),
                    tcp.dst_port(),
                    pkt.data(),
                );
            }
            Some(TransportLayer::Udp(udp)) => {
                Self::infer_by_ports_and_payload_udp(udp.src_port(), udp.dst_port(), pkt.data())
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
    fn infer_by_ports_and_payload_udp(source: u16, dest: u16, data: &[u8]) -> PacketDirection {
        // --- 1. Minimal DPI (port + max 2 bytes) ---

        // DHCP (Client 68 <-> Server 67)
        if source == 68 && dest == 67 {
            return PacketDirection::Upwards;
        }
        if source == 67 && dest == 68 {
            return PacketDirection::Downwards;
        }

        // DHCPv6 (Client 546 <-> Server 547)
        if source == 546 && dest == 547 {
            return PacketDirection::Upwards;
        }
        if source == 547 && dest == 546 {
            return PacketDirection::Downwards;
        }

        // DNS - QR bit in flags (byte 2, bit 7)
        if (source == 53 || dest == 53) && source != dest && data.len() >= 3 {
            let is_response = (data[2] & 0x80) != 0;
            return if is_response {
                PacketDirection::Downwards
            } else {
                PacketDirection::Upwards
            };
        }

        // NTP - Mode field in byte 0 (bits 0-2)
        if (source == 123 || dest == 123) && !data.is_empty() {
            let mode = data[0] & 0x07;
            return match mode {
                1 | 3 => PacketDirection::Upwards, // Symmetric Active, Client
                2 | 4 | 5 => PacketDirection::Downwards, // Symmetric Passive, Server, Broadcast
                _ => {
                    // Fall through to port-based logic
                    if dest == 123 {
                        PacketDirection::Upwards
                    } else {
                        PacketDirection::Downwards
                    }
                }
            };
        }

        // --- 2. Payload Length Heuristic for Symmetric Traffic ---
        if source == dest {
            let threshold = match source {
                53 => Some(64),    // DNS (queries typically < 64 bytes)
                123 => Some(48),   // NTP (request = 48 bytes exactly in v3/v4)
                137 => Some(60),   // NetBIOS Name Service
                138 => Some(100),  // NetBIOS Datagram
                161 => Some(80),   // SNMP
                162 => Some(80),   // SNMP Traps
                389 => Some(150),  // CLDAP
                500 => Some(200),  // IKE (initiator packets often smaller in phase 1)
                514 => Some(200),  // Syslog (assume larger = more log data = server aggregating)
                520 => Some(60),   // RIP (requests are smaller)
                1194 => Some(100), // OpenVPN
                1900 => Some(200), // SSDP (M-SEARCH requests are small)
                4500 => Some(200), // IPsec NAT-T
                5353 => Some(80),  // mDNS
                5355 => Some(64),  // LLMNR
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

        // --- 3. Port Rank Logic ---
        // System ports (≤1024) < User ports (1025-49151) < Dynamic ports (>49151)
        let get_port_rank = |p: u16| -> u8 {
            if p <= 1024 {
                0
            } else if p <= 49151 {
                1
            } else {
                2
            }
        };

        let src_rank = get_port_rank(source);
        let dst_rank = get_port_rank(dest);

        if src_rank > dst_rank {
            return PacketDirection::Upwards; // High port → Low port (Client → Server)
        } else if src_rank < dst_rank {
            return PacketDirection::Downwards; // Low port → High port (Server → Client)
        }

        // --- 4. Fallback ---
        PacketDirection::Upwards
    }

    /// Simplified TCP direction inference: port-based + minimal DPI (max 2 bytes)
    ///
    /// DPI Lite checks:
    /// - TLS: ContentType (byte 0) + Handshake type (byte 5)
    /// - DNS over TCP: QR bit (byte 4, after 2-byte length prefix)
    fn infer_by_ports_and_payload_tcp(source: u16, dest: u16, data: &[u8]) -> PacketDirection {
        // --- 1. Minimal DPI (port + max 2 bytes) ---

        // TLS - ContentType (byte 0) and Handshake type (byte 5)
        if (source == 443 || dest == 443 || source == 8443 || dest == 8443) && data.len() >= 6 {
            if data[0] == 0x16 {
                // ContentType 0x16 = Handshake
                let handshake_type = data[5];
                return match handshake_type {
                    0x01 => PacketDirection::Upwards,   // ClientHello
                    0x02 => PacketDirection::Downwards, // ServerHello
                    _ => {
                        if dest == 443 || dest == 8443 {
                            PacketDirection::Upwards
                        } else {
                            PacketDirection::Downwards
                        }
                    }
                };
            }
        }

        // DNS over TCP - QR bit at byte 4 (after 2-byte length prefix, then byte 2 of DNS)
        if (source == 53 || dest == 53) && data.len() >= 5 {
            let is_response = (data[4] & 0x80) != 0;
            return if is_response {
                PacketDirection::Downwards
            } else {
                PacketDirection::Upwards
            };
        }

        // --- 2. Port Rank Logic ---
        let get_port_rank = |p: u16| -> u8 {
            if p <= 1024 {
                0
            } else if p <= 49151 {
                1
            } else {
                2
            }
        };

        let src_rank = get_port_rank(source);
        let dst_rank = get_port_rank(dest);

        if src_rank > dst_rank {
            return PacketDirection::Upwards; // High port → Low port (Client → Server)
        } else if src_rank < dst_rank {
            return PacketDirection::Downwards; // Low port → High port (Server → Client)
        }

        // --- 3. Fallback ---
        PacketDirection::Upwards
    }
}
