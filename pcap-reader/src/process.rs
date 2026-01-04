use packet_strata::packet::header::{LinkLayer, NetworkLayer, TransportLayer, TunnelLayer};
use packet_strata::packet::iter::{Header, LinkType, PacketIter};
use packet_strata::packet::tunnel::ipip::IpipType;
use packet_strata::packet::{Packet, ParseMode};

use crate::packet_metadata::PacketMetadata;
use crate::stats::{LocalStats, Stats, FLUSH_INTERVAL};

/// Process a single packet using the PacketIter iterator
///
/// This function iterates through all headers in the packet and
/// updates the appropriate counters.
#[inline]
pub fn process_packet<'a, Pkt: PacketMetadata>(
    _pkt_count: u64,
    link_type: &mut Option<LinkType>,
    pkt: &'a Pkt,
    local_stats: &mut LocalStats,
    stats: &Stats,
    dump_packet: bool,
    full_packet: bool,
) {
    if full_packet {
        process_full_packet(_pkt_count, link_type, pkt, local_stats, stats, dump_packet);
    } else {
        process_iterate_headers(_pkt_count, link_type, pkt, local_stats, stats, dump_packet);
    }
}

pub fn process_iterate_headers<'a, Pkt: PacketMetadata>(
    _pkt_count: u64,
    link_type: &mut Option<LinkType>,
    pkt: &'a Pkt,
    local_stats: &mut LocalStats,
    stats: &Stats,
    dump_packet: bool,
) {
    local_stats.total_packets += 1;
    local_stats.total_bytes += pkt.caplen() as u64;

    if link_type.is_none() {
        *link_type = Some(PacketIter::guess_link_type(pkt.data()));
    }

    let iter = PacketIter::new(pkt.data(), link_type.unwrap());

    if dump_packet {
        println!(
            "{:>5}   {} ({} bytes)",
            local_stats.total_packets,
            pkt.timestamp_string(),
            pkt.data().len()
        );
    }

    for result in iter {
        match result {
            Ok(header) => {
                if dump_packet {
                    println!("        {header}");
                }
                match header {
                    // Link layer
                    Header::Ethernet(_) => local_stats.ethernet += 1,
                    Header::Sll(_) => local_stats.sll += 1,
                    Header::Sllv2(_) => local_stats.sllv2 += 1,
                    Header::Null(_) => local_stats.null += 1,

                    // Network layer
                    Header::Ipv4(_) => local_stats.ipv4 += 1,
                    Header::Ipv6(_) => local_stats.ipv6 += 1,
                    Header::Arp(_) => local_stats.arp += 1,

                    // Transport layer
                    Header::Tcp(_) => local_stats.tcp += 1,
                    Header::Udp(_) => local_stats.udp += 1,
                    Header::Sctp(_) => local_stats.sctp += 1,
                    Header::Icmp(_) => local_stats.icmp += 1,
                    Header::Icmp6(_) => local_stats.icmpv6 += 1,

                    // Tunnel protocols
                    Header::Vxlan(_) => local_stats.vxlan += 1,
                    Header::Geneve(_) => local_stats.geneve += 1,
                    Header::Gre(_) => local_stats.gre += 1,
                    Header::Nvgre(_) => local_stats.nvgre += 1,
                    Header::Mpls(_) => local_stats.mpls += 1,
                    Header::Teredo(_) => local_stats.teredo += 1,
                    Header::Gtpv1(_) => local_stats.gtpv1 += 1,
                    Header::Gtpv2(_) => local_stats.gtpv2 += 1,
                    Header::L2tpv2(_) => local_stats.l2tpv2 += 1,
                    Header::L2tpv3(_) => local_stats.l2tpv3 += 1,
                    Header::Pbb(_) => local_stats.pbb += 1,
                    Header::Stt(_) => local_stats.stt += 1,
                    Header::Pptp(_) => local_stats.pptp += 1,
                    Header::Ipip(tunnel) => {
                        use packet_strata::packet::tunnel::ipip::IpipType;
                        match tunnel.tunnel_type() {
                            IpipType::Ipip => local_stats.ipip += 1,
                            IpipType::Sit => local_stats.sit += 1,
                            IpipType::Ip4in6 => local_stats.ip4in6 += 1,
                            IpipType::Ip6Tnl => local_stats.ip6tnl += 1,
                        }
                    }

                    // Unknown protocols
                    Header::Unknown { proto, .. } => {
                        use packet_strata::packet::iter::UnknownProto;
                        match proto {
                            UnknownProto::Ether(_) => local_stats.unknown_ether_proto += 1,
                            UnknownProto::Ip(_) => local_stats.unknown_ip_proto += 1,
                            UnknownProto::Tunnel(_) => local_stats.unknown_other += 1,
                        }
                    }
                }
            }
            Err(e) => {
                use packet_strata::packet::PacketHeaderError;
                match e {
                    PacketHeaderError::TooShort(_) => local_stats.too_small += 1,
                    PacketHeaderError::Invalid(_) => local_stats.invalid += 1,
                    PacketHeaderError::InsufficientLength(_) => local_stats.insufficient_len += 1,
                    PacketHeaderError::Other(_) => local_stats.other_errors += 1,
                }
                break;
            }
        }
    }

    // Periodic flush to shared stats
    if local_stats.should_flush(FLUSH_INTERVAL) {
        local_stats.flush(stats);
    }
}

pub fn process_full_packet<'a, Pkt: PacketMetadata>(
    _pkt_count: u64,
    link_type: &mut Option<LinkType>,
    pkt: &'a Pkt,
    local_stats: &mut LocalStats,
    stats: &Stats,
    dump_packet: bool,
) {
    local_stats.total_packets += 1;
    local_stats.total_bytes += pkt.caplen() as u64;

    if link_type.is_none() {
        *link_type = Some(PacketIter::guess_link_type(pkt.data()));
    }

    match Packet::from_bytes(pkt.data(), link_type.unwrap(), ParseMode::Innermost) {
        Ok(packet) => {
            if dump_packet {
                println!(
                    "{:>5}   {} ({} bytes)",
                    local_stats.total_packets,
                    pkt.timestamp_string(),
                    pkt.data().len()
                );
                print!("{}", packet);
            }

            // Update stats for link layer
            match packet.link() {
                LinkLayer::Ethernet(_) => local_stats.ethernet += 1,
                LinkLayer::Sll(_) => local_stats.sll += 1,
                LinkLayer::Sllv2(_) => local_stats.sllv2 += 1,
                LinkLayer::Null(_) => local_stats.null += 1,
            }

            // Update stats for ARP
            if packet.arp().is_some() {
                local_stats.arp += 1;
            }

            // Update stats for network layer
            if let Some(network) = packet.network() {
                match network {
                    NetworkLayer::Ipv4(_) => local_stats.ipv4 += 1,
                    NetworkLayer::Ipv6(_) => local_stats.ipv6 += 1,
                    NetworkLayer::Mpls(_) => local_stats.mpls += 1,
                }
            }

            // Update stats for transport layer
            if let Some(transport) = packet.transport() {
                match transport {
                    TransportLayer::Tcp(_) => local_stats.tcp += 1,
                    TransportLayer::Udp(_) => local_stats.udp += 1,
                    TransportLayer::Sctp(_) => local_stats.sctp += 1,
                    TransportLayer::Icmp(_) => local_stats.icmp += 1,
                    TransportLayer::Icmp6(_) => local_stats.icmpv6 += 1,
                }
            }

            // Update stats for tunnel layers
            for ip_tunnel in packet.tunnels() {
                match &ip_tunnel.tunnel {
                    TunnelLayer::Vxlan(_) => local_stats.vxlan += 1,
                    TunnelLayer::Geneve(_) => local_stats.geneve += 1,
                    TunnelLayer::Gre(_) => local_stats.gre += 1,
                    TunnelLayer::Nvgre(_) => local_stats.nvgre += 1,
                    TunnelLayer::Teredo(_) => local_stats.teredo += 1,
                    TunnelLayer::Gtpv1(_) => local_stats.gtpv1 += 1,
                    TunnelLayer::Gtpv2(_) => local_stats.gtpv2 += 1,
                    TunnelLayer::L2tpv2(_) => local_stats.l2tpv2 += 1,
                    TunnelLayer::L2tpv3(_) => local_stats.l2tpv3 += 1,
                    TunnelLayer::Pbb(_) => local_stats.pbb += 1,
                    TunnelLayer::Stt(_) => local_stats.stt += 1,
                    TunnelLayer::Pptp(_) => local_stats.pptp += 1,
                    TunnelLayer::Ipip(tunnel) => match tunnel.tunnel_type() {
                        IpipType::Ipip => local_stats.ipip += 1,
                        IpipType::Sit => local_stats.sit += 1,
                        IpipType::Ip4in6 => local_stats.ip4in6 += 1,
                        IpipType::Ip6Tnl => local_stats.ip6tnl += 1,
                    },
                }
            }
        }
        Err(e) => {
            use packet_strata::packet::PacketHeaderError;
            match e {
                PacketHeaderError::TooShort(_) => local_stats.too_small += 1,
                PacketHeaderError::Invalid(_) => local_stats.invalid += 1,
                PacketHeaderError::InsufficientLength(_) => local_stats.insufficient_len += 1,
                PacketHeaderError::Other(_) => local_stats.other_errors += 1,
            }
        }
    }

    // Periodic flush to shared stats
    if local_stats.should_flush(FLUSH_INTERVAL) {
        local_stats.flush(stats);
    }
}
