use crate::packet::{Packet, header::TransportLayer, icmp::IcmpType, icmp6::Icmp6Type};
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
enum PacketDirection {
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
    pub fn infer_by_packet(pkt: &Packet<'_>) -> PacketDirection {
        let transport = pkt.transport();
        match transport {
            Some(TransportLayer::Tcp(tcp)) => {
                if tcp.header.has_syn() {
                    if tcp.header.has_ack() {
                        return PacketDirection::Downwards;
                    } else {
                        return PacketDirection::Upwards;
                    }
                }

                return Self::infer_by_ports_and_payload_tcp(tcp.src_port(), tcp.dst_port(), pkt.data())
            }
            Some(TransportLayer::Udp(udp)) => {
                Self::infer_by_ports_and_payload_udp(udp.src_port(), udp.dst_port(), pkt.data())
            }

            Some(TransportLayer::Icmp(icmp)) => {
                match icmp.icmp_type() {
                    IcmpType::ECHO => PacketDirection::Upwards, // Echo Request
                    IcmpType::ECHO_REPLY => PacketDirection::Downwards, // Echo Reply
                    IcmpType::TIMESTAMP => PacketDirection::Upwards, // Timestamp Request
                    IcmpType::TIMESTAMP_REPLY => PacketDirection::Downwards, // Timestamp Reply
                    IcmpType::INFO_REQUEST => PacketDirection::Upwards, // Information Request
                    IcmpType::INFO_REPLY => PacketDirection::Downwards, // Information Reply
                    IcmpType::ADDRESS => PacketDirection::Upwards, // Address Mask Request
                    IcmpType::ADDRESS_REPLY => PacketDirection::Downwards, // Address Mask Reply
                    IcmpType::EX_ECHO => PacketDirection::Upwards, // Extended Echo Request
                    IcmpType::EX_ECHO_REPLY => PacketDirection::Downwards, // Extended Echo Reply
                    IcmpType::DEST_UNREACH => PacketDirection::Upwards, // Destination Unreachable
                    IcmpType::SOURCE_QUENCH => PacketDirection::Upwards, // Source Quench
                    IcmpType::REDIRECT => PacketDirection::Upwards, // Redirect (change route)
                    IcmpType::ROUTER_ADV => PacketDirection::Downwards, // Router Advertisement
                    IcmpType::ROUTER_SOLICIT => PacketDirection::Upwards, // Router Solicitation
                    IcmpType::TIME_EXCEEDED => PacketDirection::Upwards, // Time Exceeded
                    IcmpType::PARAMETER_PROBLEM => PacketDirection::Upwards, // Parameter Problem
                    _ => PacketDirection::Upwards,
                }
            }
            Some(TransportLayer::Icmp6(icmp6)) => {
                match icmp6.icmp6_type() {
                    Icmp6Type::DST_UNREACH => PacketDirection::Upwards, // Destination Unreachable
                    Icmp6Type::PACKET_TOO_BIG => PacketDirection::Upwards, // Packet Too Big
                    Icmp6Type::TIME_EXCEEDED => PacketDirection::Upwards, // Time Exceeded
                    Icmp6Type::PARAM_PROB => PacketDirection::Upwards,  // Parameter Problem
                    Icmp6Type::ECHO_REQUEST => PacketDirection::Upwards, // Echo Request
                    Icmp6Type::ECHO_REPLY => PacketDirection::Downwards, // Echo Reply
                    Icmp6Type::MLD_LISTENER_QUERY => PacketDirection::Downwards, // Multicast Listener Query
                    Icmp6Type::MLD_LISTENER_REPORT => PacketDirection::Upwards, // Multicast Listener Report
                    Icmp6Type::MLD_LISTENER_REDUCTION => PacketDirection::Upwards, // Multicast Listener Reduction

                    Icmp6Type::ROUTER_SOLICITATION => PacketDirection::Upwards, // Router Solicitation
                    Icmp6Type::ROUTER_ADVERTISEMENT => PacketDirection::Downwards, // Router Advertisement
                    Icmp6Type::NEIGHBOR_SOLICITATION => PacketDirection::Upwards, // Neighbor Solicitation
                    Icmp6Type::NEIGHBOR_ADVERTISEMENT => PacketDirection::Downwards, // Neighbor Advertisement
                    Icmp6Type::REDIRECT_MESSAGE => PacketDirection::Upwards, // Redirect Message
                    Icmp6Type::ROUTER_RENUMBERING => PacketDirection::Downwards, // Router Renumbering
                    Icmp6Type::NODE_INFORMATION_QUERY => PacketDirection::Upwards, // Node Information Query
                    Icmp6Type::NODE_INFORMATION_RESPONSE => PacketDirection::Downwards, // Node Information Response

                    Icmp6Type::INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION => PacketDirection::Upwards, // Inverse Neighbor Discovery Solicitation
                    Icmp6Type::INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT => {
                        PacketDirection::Downwards
                    } // Inverse Neighbor Discovery Advertisement
                    Icmp6Type::MULTICAST_LISTENER_DISCOVERY_REPORTS => PacketDirection::Upwards, // Multicast Listener Discovery Reports
                    Icmp6Type::HOME_AGENT_ADDRESS_DISCOVERY_REQUEST => PacketDirection::Upwards, // Home Agent Address Discovery Request
                    Icmp6Type::HOME_AGENT_ADDRESS_DISCOVERY_REPLY => PacketDirection::Downwards, // Home Agent Address Discovery Reply
                    Icmp6Type::MOBILE_PREFIX_SOLICITATION => PacketDirection::Upwards, // Mobile Prefix Solicitation
                    Icmp6Type::MOBILE_PREFIX_ADVERTISEMENT => PacketDirection::Downwards, // Mobile Prefix Advertisement
                    Icmp6Type::MULTICAST_ROUTER_SOLICITATION => PacketDirection::Upwards, // Multicast Router Solicitation
                    Icmp6Type::MULTICAST_ROUTER_TERMINATION => PacketDirection::Upwards, // Multicast Router Termination
                    Icmp6Type::FMIPV6 => PacketDirection::Upwards,                       // FMIPv6
                    Icmp6Type::RPL_CONTROL_MESSAGE => PacketDirection::Upwards, // RPL Control Message
                    Icmp6Type::ILNPV6_LOCATOR_UPDATE => PacketDirection::Upwards, // ILNPv6 Locator Update
                    Icmp6Type::DUPLICATE_ADDRESS_REQUEST => PacketDirection::Upwards, // Duplicate Address Request
                    Icmp6Type::DUPLICATE_ADDRESS_CONFIRM => PacketDirection::Downwards, // Duplicate Address Confirm
                    Icmp6Type::MPL_CONTROL_MESSAGE => PacketDirection::Upwards, // MPL Control Message
                    Icmp6Type::EXTENDED_ECHO_REQUEST => PacketDirection::Upwards, // Extended Echo Request
                    Icmp6Type::EXTENDED_ECHO_REPLY => PacketDirection::Downwards, // Extended Echo Reply
                    _ => PacketDirection::Upwards,
                }
            },
            Some(TransportLayer::Sctp(_)) | None => PacketDirection::Upwards
        }
    }

    /// Infer packet direction for UDP traffic using port numbers and payload inspection.
    ///
    /// UDP is stateless, so this function relies on application-layer protocol patterns
    /// to determine the direction of communication.
    ///
    /// Strategy:
    /// 1. Protocol-specific detection (DPI Lite) - DHCP, STUN, SIP, DNS, NTP, QUIC, etc.
    /// 2. Symmetric traffic heuristics - payload length thresholds for same-port traffic
    /// 3. Port rank logic - well-known ports indicate server role
    /// 4. Fallback - first packet is assumed to be from client (Upwards)
    fn infer_by_ports_and_payload_udp(source: u16, dest: u16, data: &[u8]) -> PacketDirection {
        // --- 1. Protocol Specific Exceptions (DPI Lite) ---

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

        // Check payload availability for content inspection
        if !data.is_empty() {
            // PTP (Precision Time Protocol) - Ports 319 (Event), 320 (General)
            // Symmetric traffic. Byte 0 is messageType.
            if (source == 319 || source == 320) && (dest == 319 || dest == 320) {
                // 0x1 = Delay_Req (Client -> Master)
                // 0x3 = Pdelay_Req (Peer -> Peer, but initiator is "client")
                // Others (Sync 0x0, Follow_Up 0x8, Announce 0xB) are Server -> Client
                let msg_type = data[0] & 0x0F;
                return if msg_type == 1 || msg_type == 3 {
                    PacketDirection::Upwards
                } else {
                    PacketDirection::Downwards
                };
            }

            // RIP (Routing Information Protocol) - Port 520
            // Symmetric. Byte 0 is Command.
            if source == 520 && dest == 520 {
                // 1 = Request, 2 = Response
                return if data[0] == 1 {
                    PacketDirection::Upwards
                } else {
                    PacketDirection::Downwards
                };
            }

            // RADIUS - Ports 1812 (Auth), 1813 (Acct), 3799 (CoA/DM)
            // Symmetric if proxying. Byte 0 is Code.
            let is_radius_port = |p: u16| p == 1812 || p == 1813 || p == 3799;
            if is_radius_port(source) && is_radius_port(dest) {
                match data[0] {
                    1 | 4 | 40 | 43 => return PacketDirection::Upwards, // Access-Request, Accounting-Request, Disconnect-Request, CoA-Request
                    2 | 3 | 5 | 41 | 42 | 44 | 45 => return PacketDirection::Downwards, // Accept, Reject, Acct-Response, Disconnect-ACK/NAK, CoA-ACK/NAK
                    _ => {} // Unknown code, fall through to generic logic
                }
            }

            // TFTP - Port 69 (Initial connection only)
            // Note: Subsequent data transfer moves to random ports, hard to track statelessly.
            if dest == 69 && data.len() >= 2 {
                let opcode = u16::from_be_bytes([data[0], data[1]]);
                // 1 = RRQ, 2 = WRQ (client requests)
                // 3 = DATA, 4 = ACK, 5 = ERROR (responses or subsequent)
                if opcode == 1 || opcode == 2 {
                    return PacketDirection::Upwards;
                }
            }

            // STUN/TURN (RFC 5389) - Ports 3478, 3479, 5349
            // Byte 0-1 contain message type, bit patterns indicate request/response
            let is_stun_port = |p: u16| p == 3478 || p == 3479 || p == 5349;
            if data.len() >= 2 && (is_stun_port(source) || is_stun_port(dest)) {
                // Check magic cookie at bytes 4-7 (0x2112A442)
                if data.len() >= 8 {
                    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    if magic == 0x2112A442 {
                        // Bits 0-1 of message type: 00 = request, 01 = indication, 10 = success, 11 = error
                        let class_bits = ((data[0] & 0x01) << 1) | ((data[1] & 0x10) >> 4);
                        return if class_bits == 0 || class_bits == 1 {
                            PacketDirection::Upwards // Request or Indication
                        } else {
                            PacketDirection::Downwards // Success or Error Response
                        };
                    }
                }
            }

            // SIP (Session Initiation Protocol) - Ports 5060 (UDP), 5061 (TLS)
            // Check for SIP method or response in first line
            if (source == 5060 || dest == 5060 || source == 5061 || dest == 5061) && data.len() >= 7 {
                // SIP responses start with "SIP/2.0"
                if &data[..7] == b"SIP/2.0" {
                    return PacketDirection::Downwards;
                }
                // SIP requests start with method name (INVITE, REGISTER, etc.)
                let methods = [
                    b"INVITE " as &[u8], b"ACK ", b"BYE ", b"CANCEL ", b"REGISTER ",
                    b"OPTIONS ", b"PRACK ", b"SUBSCRIBE ", b"NOTIFY ", b"PUBLISH ",
                    b"INFO ", b"REFER ", b"MESSAGE ", b"UPDATE ",
                ];
                for method in methods {
                    if data.len() >= method.len() && &data[..method.len()] == method {
                        return PacketDirection::Upwards;
                    }
                }
            }

            // BGP - Port 179
            // BGP messages have a 16-byte marker (all 0xFF) followed by length and type
            if (source == 179 || dest == 179) && data.len() >= 19 {
                // Verify BGP marker (16 bytes of 0xFF)
                if data[..16].iter().all(|&b| b == 0xFF) {
                    let msg_type = data[18];
                    return match msg_type {
                        1 => PacketDirection::Upwards,   // OPEN (initiator)
                        2 => PacketDirection::Upwards,   // UPDATE (either direction, but assume request)
                        3 => PacketDirection::Downwards, // NOTIFICATION (usually response to error)
                        4 => PacketDirection::Upwards,   // KEEPALIVE (bidirectional, assume upward)
                        _ => PacketDirection::Upwards,
                    };
                }
            }

            // DNS (when not symmetric) - Port 53
            // Byte 2 contains flags: QR bit (0x80) distinguishes query (0) from response (1)
            if (source == 53 || dest == 53) && source != dest && data.len() >= 3 {
                let is_response = (data[2] & 0x80) != 0;
                return if is_response {
                    PacketDirection::Downwards
                } else {
                    PacketDirection::Upwards
                };
            }

            // NTP - Port 123
            // Byte 0 contains LI (2 bits), Version (3 bits), Mode (3 bits)
            // Mode 3 = Client, Mode 4 = Server, Mode 5 = Broadcast
            if (source == 123 || dest == 123) && data.len() >= 1 {
                let mode = data[0] & 0x07;
                return match mode {
                    1 | 3 => PacketDirection::Upwards,   // Symmetric Active, Client
                    2 | 4 | 5 => PacketDirection::Downwards, // Symmetric Passive, Server, Broadcast
                    _ => {
                        // Fall through to port-based logic for unknown modes
                        if dest == 123 { PacketDirection::Upwards } else { PacketDirection::Downwards }
                    }
                };
            }

            // SNMP - Ports 161 (agent), 162 (trap)
            // Can inspect BER-encoded PDU type, but complex. Use port heuristic.
            if dest == 161 {
                return PacketDirection::Upwards; // Request to agent
            }
            if source == 161 {
                return PacketDirection::Downwards; // Response from agent
            }
            if dest == 162 || source == 162 {
                // Traps are sent from agent to manager
                return if dest == 162 {
                    PacketDirection::Upwards // Trap notification
                } else {
                    PacketDirection::Downwards
                };
            }

            // Syslog - Port 514
            // Always client -> server (log messages)
            if dest == 514 {
                return PacketDirection::Upwards;
            }

            // LDAP - Port 389 (and 636 for LDAPS)
            // BER encoded, first byte is tag. 0x30 = SEQUENCE (request typically smaller)
            if (dest == 389 || dest == 636) && source != 389 && source != 636 {
                return PacketDirection::Upwards;
            }
            if (source == 389 || source == 636) && dest != 389 && dest != 636 {
                return PacketDirection::Downwards;
            }

            // Kerberos - Port 88
            if dest == 88 {
                return PacketDirection::Upwards;
            }
            if source == 88 {
                return PacketDirection::Downwards;
            }

            // MQTT - Port 1883 (and 8883 for TLS)
            // First byte high nibble is packet type
            if (source == 1883 || dest == 1883 || source == 8883 || dest == 8883) && data.len() >= 1 {
                let pkt_type = (data[0] & 0xF0) >> 4;
                return match pkt_type {
                    1 | 3 | 6 | 8 | 10 | 12 | 14 => PacketDirection::Upwards, // CONNECT, PUBLISH (C->S), PUBREL, SUBSCRIBE, UNSUBSCRIBE, PINGREQ, DISCONNECT
                    2 | 4 | 5 | 7 | 9 | 11 | 13 => PacketDirection::Downwards, // CONNACK, PUBACK, PUBREC, PUBCOMP, SUBACK, UNSUBACK, PINGRESP
                    _ => if dest == 1883 || dest == 8883 { PacketDirection::Upwards } else { PacketDirection::Downwards }
                };
            }

            // QUIC - Port 443 (UDP) - Initial packets
            // First byte: Header Form (1 bit), Fixed Bit (1 bit), then type-specific
            // Long header (0x80 set) initial packets are client -> server typically
            if (source == 443 || dest == 443) && data.len() >= 5 {
                let is_long_header = (data[0] & 0x80) != 0;
                if is_long_header {
                    let pkt_type = (data[0] & 0x30) >> 4;
                    // 0 = Initial, 1 = 0-RTT, 2 = Handshake, 3 = Retry
                    return match pkt_type {
                        0 | 1 => PacketDirection::Upwards,   // Initial, 0-RTT typically client
                        3 => PacketDirection::Downwards,     // Retry is server -> client
                        _ => if dest == 443 { PacketDirection::Upwards } else { PacketDirection::Downwards }
                    };
                }
            }
        }

        // --- 2. Symmetric Traffic Heuristics (Payload Length) ---
        // Applied only when ports are identical (Server-to-Server or P2P scenarios)
        if source == dest {
            let threshold = match source {
                53 => Some(64),     // DNS (queries typically < 64 bytes)
                123 => Some(48),    // NTP (request = 48 bytes exactly in v3/v4)
                137 => Some(60),    // NetBIOS Name Service
                138 => Some(100),   // NetBIOS Datagram
                161 => Some(80),    // SNMP
                162 => Some(80),    // SNMP Traps
                389 => Some(150),   // CLDAP
                500 => Some(200),   // IKE (initiator packets often smaller in phase 1)
                514 => Some(200),   // Syslog (assume larger = more log data = server aggregating)
                1194 => Some(100),  // OpenVPN
                1900 => Some(200),  // SSDP (M-SEARCH requests are small)
                4500 => Some(200),  // IPsec NAT-T
                5353 => Some(80),   // mDNS
                5355 => Some(64),   // LLMNR
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

        // --- 3. Generic Port Rank Logic ---
        // Rank 0: System Ports (<= 1024)      -> Strong "Server" indicator
        // Rank 1: User Ports (1025-49151)     -> Weak "Server" indicator
        // Rank 2: Dynamic Ports (> 49151)     -> "Client" indicator

        let get_port_rank = |p: u16| -> u8 {
            if p <= 1024 { 0 }
            else if p <= 49151 { 1 }
            else { 2 }
        };

        let src_rank = get_port_rank(source);
        let dst_rank = get_port_rank(dest);

        if src_rank > dst_rank {
            // High port talking to Low port -> Client to Server
            return PacketDirection::Upwards;
        } else if src_rank < dst_rank {
            // Low port talking to High port -> Server to Client
            return PacketDirection::Downwards;
        }

        // --- 4. Final Fallback ---
        // When ranks are equal (e.g., P2P or unhandled System-System),
        // assume the first packet seen is from the initiator (client).
        PacketDirection::Upwards
    }

    /// Infer packet direction for TCP traffic using port numbers and payload inspection.
    ///
    /// This function is designed for mid-connection packets where TCP flags are not
    /// sufficient to determine direction. It uses application-layer protocol patterns.
    ///
    /// Strategy:
    /// 1. Protocol-specific detection (DPI Lite) - HTTP, TLS, FTP, SMTP, databases, etc.
    /// 2. Port rank logic - well-known ports indicate server role
    /// 3. Fallback - first packet is assumed to be from client (Upwards)
    fn infer_by_ports_and_payload_tcp(source: u16, dest: u16, data: &[u8]) -> PacketDirection {
        // Check payload availability for content inspection
        if !data.is_empty() {
            // HTTP - Ports 80, 8080, 8000
            // Check for HTTP methods in the first bytes
            if (dest == 80 || dest == 8080 || dest == 8000) && data.len() >= 4 {
                let methods: &[&[u8]] = &[
                    b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD",
                    b"OPTI", b"PATC", b"TRAC", b"CONN",
                ];
                for method in methods {
                    if data.len() >= method.len() && &data[..method.len()] == *method {
                        return PacketDirection::Upwards;
                    }
                }
                // HTTP responses start with "HTTP/"
                if data.len() >= 5 && &data[..5] == b"HTTP/" {
                    return PacketDirection::Downwards;
                }
            }

            // HTTPS/TLS - Port 443, 8443 - TLS handshake inspection
            // TLS record: ContentType (1 byte), Version (2 bytes), Length (2 bytes)
            if (source == 443 || dest == 443 || source == 8443 || dest == 8443) && data.len() >= 6 {
                // ContentType 0x16 = Handshake
                if data[0] == 0x16 && data.len() >= 43 {
                    // TLS version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2, etc.)
                    let handshake_type = data[5];
                    return match handshake_type {
                        0x01 => PacketDirection::Upwards,   // ClientHello
                        0x02 => PacketDirection::Downwards, // ServerHello
                        0x0b => PacketDirection::Downwards, // Certificate (usually server)
                        0x0c => PacketDirection::Downwards, // ServerKeyExchange
                        0x0d => PacketDirection::Downwards, // CertificateRequest
                        0x0e => PacketDirection::Downwards, // ServerHelloDone
                        0x0f => PacketDirection::Upwards,   // CertificateVerify
                        0x10 => PacketDirection::Upwards,   // ClientKeyExchange
                        _ => if dest == 443 || dest == 8443 { PacketDirection::Upwards } else { PacketDirection::Downwards }
                    };
                }
            }

            // SSH - Port 22
            // SSH protocol exchange starts with "SSH-"
            if (source == 22 || dest == 22) && data.len() >= 4 {
                if &data[..4] == b"SSH-" {
                    // First SSH- is from server in protocol, but in capture could be either
                    // Use port direction as tie-breaker
                    return if dest == 22 {
                        PacketDirection::Upwards
                    } else {
                        PacketDirection::Downwards
                    };
                }
            }

            // FTP - Port 21 (control), 20 (data)
            // FTP commands are text-based (USER, PASS, etc.)
            if dest == 21 && data.len() >= 4 {
                let commands: &[&[u8]] = &[
                    b"USER", b"PASS", b"ACCT", b"CWD ", b"CDUP", b"SMNT",
                    b"QUIT", b"REIN", b"PORT", b"PASV", b"TYPE", b"STRU",
                    b"MODE", b"RETR", b"STOR", b"STOU", b"APPE", b"ALLO",
                    b"REST", b"RNFR", b"RNTO", b"ABOR", b"DELE", b"RMD ",
                    b"MKD ", b"PWD ", b"LIST", b"NLST", b"SITE", b"SYST",
                    b"STAT", b"HELP", b"NOOP",
                ];
                for cmd in commands {
                    if data.len() >= cmd.len() && &data[..cmd.len()] == *cmd {
                        return PacketDirection::Upwards;
                    }
                }
            }
            // FTP responses are numeric (e.g., "220 ", "331 ")
            if source == 21 && data.len() >= 4 {
                if data[0].is_ascii_digit() && data[1].is_ascii_digit() && data[2].is_ascii_digit() && data[3] == b' ' {
                    return PacketDirection::Downwards;
                }
            }

            // SMTP - Ports 25, 587, 465
            if (dest == 25 || dest == 587 || dest == 465) && data.len() >= 4 {
                let commands: &[&[u8]] = &[
                    b"HELO", b"EHLO", b"MAIL", b"RCPT", b"DATA",
                    b"RSET", b"VRFY", b"EXPN", b"HELP", b"NOOP",
                    b"QUIT", b"AUTH", b"STAR", // STARTTLS
                ];
                for cmd in commands {
                    if data.len() >= cmd.len() && &data[..cmd.len()] == *cmd {
                        return PacketDirection::Upwards;
                    }
                }
            }
            // SMTP responses are numeric
            if (source == 25 || source == 587 || source == 465) && data.len() >= 4 {
                if data[0].is_ascii_digit() && data[1].is_ascii_digit() && data[2].is_ascii_digit() && (data[3] == b' ' || data[3] == b'-') {
                    return PacketDirection::Downwards;
                }
            }

            // POP3 - Ports 110, 995
            if dest == 110 || dest == 995 {
                let commands: &[&[u8]] = &[b"USER", b"PASS", b"STAT", b"LIST", b"RETR", b"DELE", b"NOOP", b"RSET", b"QUIT", b"TOP ", b"UIDL", b"APOP"];
                for cmd in commands {
                    if data.len() >= cmd.len() && &data[..cmd.len()] == *cmd {
                        return PacketDirection::Upwards;
                    }
                }
            }
            // POP3 responses start with "+OK" or "-ERR"
            if (source == 110 || source == 995) && data.len() >= 3 {
                if &data[..3] == b"+OK" || &data[..4] == b"-ERR" {
                    return PacketDirection::Downwards;
                }
            }

            // IMAP - Ports 143, 993
            // IMAP commands have a tag prefix (e.g., "A001 LOGIN")
            // Simplified: look for common commands
            if (dest == 143 || dest == 993) && data.len() >= 4 {
                // IMAP commands typically have format: tag COMMAND
                let commands: &[&[u8]] = &[b"LOGIN", b"SELECT", b"EXAMINE", b"CREATE", b"DELETE", b"RENAME",
                               b"SUBSCRIBE", b"UNSUBSCRIBE", b"LIST", b"LSUB", b"STATUS",
                               b"APPEND", b"CHECK", b"CLOSE", b"EXPUNGE", b"SEARCH",
                               b"FETCH", b"STORE", b"COPY", b"UID", b"CAPABILITY", b"LOGOUT", b"NOOP"];
                for cmd in commands {
                    if data.len() >= cmd.len() {
                        // Simple check: see if command appears in first 20 bytes
                        let search_len = data.len().min(20);
                        if data[..search_len].windows(cmd.len()).any(|w| w == *cmd) {
                            return PacketDirection::Upwards;
                        }
                    }
                }
            }

            // BGP - Port 179 (TCP-based routing protocol)
            // BGP messages have a 16-byte marker (all 0xFF) followed by length and type
            if (source == 179 || dest == 179) && data.len() >= 19 {
                // Verify BGP marker (16 bytes of 0xFF)
                if data[..16].iter().all(|&b| b == 0xFF) {
                    let msg_type = data[18];
                    return match msg_type {
                        1 => PacketDirection::Upwards,   // OPEN (initiator)
                        2 => PacketDirection::Upwards,   // UPDATE (either direction, but assume request)
                        3 => PacketDirection::Downwards, // NOTIFICATION (usually response to error)
                        4 => PacketDirection::Upwards,   // KEEPALIVE (bidirectional, assume upward)
                        _ => PacketDirection::Upwards,
                    };
                }
            }

            // LDAP/LDAPS - Ports 389, 636 (primarily TCP)
            // BER encoded, complex to parse. Use simple port heuristic.
            if (dest == 389 || dest == 636) && source != 389 && source != 636 {
                return PacketDirection::Upwards;
            }
            if (source == 389 || source == 636) && dest != 389 && dest != 636 {
                return PacketDirection::Downwards;
            }

            // Kerberos - Port 88 (works on both TCP and UDP)
            if dest == 88 && source != 88 {
                return PacketDirection::Upwards;
            }
            if source == 88 && dest != 88 {
                return PacketDirection::Downwards;
            }

            // MySQL - Port 3306
            // Server greeting starts with protocol version (0x0a for v10)
            if source == 3306 && data.len() >= 5 && data[0] == 0x0a {
                return PacketDirection::Downwards; // Server greeting
            }
            if dest == 3306 {
                return PacketDirection::Upwards; // Client to server
            }

            // PostgreSQL - Port 5432
            // Startup message has specific format, but complex. Use port heuristic.
            if dest == 5432 {
                return PacketDirection::Upwards;
            }
            if source == 5432 {
                return PacketDirection::Downwards;
            }

            // Redis - Port 6379
            // Redis protocol uses RESP - commands start with '*' (array) or simple strings
            if dest == 6379 && data.len() >= 1 && (data[0] == b'*' || data[0] == b'+' || data[0] == b'-') {
                return PacketDirection::Upwards;
            }
            if source == 6379 {
                return PacketDirection::Downwards;
            }

            // MongoDB - Port 27017
            if dest == 27017 {
                return PacketDirection::Upwards;
            }
            if source == 27017 {
                return PacketDirection::Downwards;
            }

            // SMB/CIFS - Port 445
            // SMB header starts with 0xFF 'S' 'M' 'B' or 0xFE 'S' 'M' 'B' (SMB2/3)
            if (source == 445 || dest == 445) && data.len() >= 4 {
                if (data[0] == 0xFF || data[0] == 0xFE) && &data[1..4] == b"SMB" {
                    // Use port direction as heuristic
                    return if dest == 445 {
                        PacketDirection::Upwards
                    } else {
                        PacketDirection::Downwards
                    };
                }
            }

            // RDP - Port 3389
            // TPKT header: version (0x03), reserved (0x00), length (2 bytes)
            if (source == 3389 || dest == 3389) && data.len() >= 4 {
                if data[0] == 0x03 && data[1] == 0x00 {
                    return if dest == 3389 {
                        PacketDirection::Upwards
                    } else {
                        PacketDirection::Downwards
                    };
                }
            }

            // Telnet - Port 23
            // Telnet negotiation uses IAC (0xFF) commands, but regular text is common too
            if dest == 23 {
                return PacketDirection::Upwards;
            }
            if source == 23 {
                return PacketDirection::Downwards;
            }

            // SIP over TCP - Ports 5060, 5061
            if (source == 5060 || dest == 5060 || source == 5061 || dest == 5061) && data.len() >= 7 {
                // SIP responses start with "SIP/2.0"
                if &data[..7] == b"SIP/2.0" {
                    return PacketDirection::Downwards;
                }
                // SIP requests start with method name
                let methods: &[&[u8]] = &[
                    b"INVITE ", b"ACK ", b"BYE ", b"CANCEL ", b"REGISTER ",
                    b"OPTIONS ", b"PRACK ", b"SUBSCRIBE ", b"NOTIFY ", b"PUBLISH ",
                    b"INFO ", b"REFER ", b"MESSAGE ", b"UPDATE ",
                ];
                for method in methods {
                    if data.len() >= method.len() && &data[..method.len()] == *method {
                        return PacketDirection::Upwards;
                    }
                }
            }

            // MQTT over TCP - Ports 1883, 8883
            if (source == 1883 || dest == 1883 || source == 8883 || dest == 8883) && data.len() >= 1 {
                let pkt_type = (data[0] & 0xF0) >> 4;
                return match pkt_type {
                    1 | 3 | 6 | 8 | 10 | 12 | 14 => PacketDirection::Upwards,
                    2 | 4 | 5 | 7 | 9 | 11 | 13 => PacketDirection::Downwards,
                    _ => if dest == 1883 || dest == 8883 { PacketDirection::Upwards } else { PacketDirection::Downwards }
                };
            }

            // DNS over TCP - Port 53
            // DNS over TCP has 2-byte length prefix, then standard DNS message
            if (source == 53 || dest == 53) && data.len() >= 5 {
                // Skip 2-byte length, check QR bit at byte 2 (offset from length prefix)
                let is_response = (data[2] & 0x80) != 0;
                return if is_response {
                    PacketDirection::Downwards
                } else {
                    PacketDirection::Upwards
                };
            }
        }

        // --- 2. Generic Port Rank Logic (same as UDP) ---
        let get_port_rank = |p: u16| -> u8 {
            if p <= 1024 { 0 }
            else if p <= 49151 { 1 }
            else { 2 }
        };

        let src_rank = get_port_rank(source);
        let dst_rank = get_port_rank(dest);

        if src_rank > dst_rank {
            // High port talking to Low port -> Client to Server
            return PacketDirection::Upwards;
        } else if src_rank < dst_rank {
            // Low port talking to High port -> Server to Client
            return PacketDirection::Downwards;
        }

        // --- 3. Final Fallback ---
        // When ranks are equal (e.g., P2P or unhandled System-System),
        // assume the first packet seen is from the initiator (client).
        PacketDirection::Upwards
    }
}
