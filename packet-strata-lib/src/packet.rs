use smallvec::SmallVec;
use std::fmt;
use std::mem;
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, KnownLayout, Ref, Unaligned};

use crate::packet::{
    arp::{ArpHeader, ArpHeaderFull},
    detect::{
        detect_gre_variant, detect_mpls_inner_protocol, detect_udp_tunnel,
        find_ipv6_upper_protocol, is_stt_port, NextLayer, TunnelType,
    },
    ether::EtherHeader,
    header::{LinkLayer, NetworkLayer, NetworkTunnelLayer, TransportLayer, TunnelLayer},
    icmp::IcmpHeader,
    icmp6::Icmp6Header,
    ipv4::Ipv4Header,
    ipv6::Ipv6Header,
    iter::LinkType,
    null::NullHeader,
    protocol::{EtherProto, IpProto},
    sctp::SctpHeader,
    sll::{SllHeader, Sllv2Header},
    tcp::TcpHeader,
    tunnel::{
        geneve::GeneveHeader,
        gre::GreHeader,
        gtpv1::Gtpv1Header,
        gtpv2::Gtpv2Header,
        ipip::IpipTunnel,
        l2tp::{L2tpv2Header, L2tpv3SessionHeader},
        mpls::MplsLabelStack,
        nvgre::NvgreHeader,
        pbb::PbbHeader,
        pptp::PptpGreHeader,
        stt::SttPacket,
        teredo::TeredoPacket,
        vxlan::VxlanHeader,
    },
    udp::UdpHeader,
};

pub mod arp;
pub mod detect;
pub mod dhcp;
pub mod ether;
pub mod header;
pub mod icmp;
pub mod icmp6;
pub mod ipv4;
pub mod ipv6;
pub mod iter;
pub mod null;
pub mod protocol;
pub mod sctp;
pub mod sll;
pub mod tcp;
pub mod tunnel;
pub mod udp;

#[derive(Debug, Clone, Error)]
pub enum PacketHeaderError {
    #[error("buffer too short for {0}")]
    TooShort(&'static str),
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("insufficient buffer length for {0}")]
    InsufficientLength(&'static str),
    #[error("{0}")]
    Other(&'static str),
}

pub trait PacketHeader: Sized {
    const FIXED_LEN: usize = mem::size_of::<Self>();
    const NAME: &'static str;
    type InnerType;

    /// return the inner type of the header
    fn inner_type(&self) -> Self::InnerType;

    /// Returns the length of the network layer header
    /// For protocols with variable-length headers (like IPv6 with extensions),
    /// the buffer is needed to calculate the correct length
    fn total_len(&self, buf: &[u8]) -> usize {
        let _ = buf; // Suppress unused warning for implementations that don't need it
        Self::FIXED_LEN
    }

    /// check whether the network layer header is valid
    #[inline]
    fn is_valid(&self) -> bool {
        true
    }
}

pub trait HeaderParser: PacketHeader + FromBytes + KnownLayout + Immutable + Unaligned {
    /// The high-level view returned to the user.
    /// Can be `&'a Self` for fixed headers or a custom wrapper<'a> for variable ones.
    type Output<'a>
    where
        Self: 'a;

    /// Transform the raw struct and the options slice into the Output type.
    fn into_view<'a>(header: &'a Self, options: &'a [u8]) -> Self::Output<'a>;

    /// parse the network layer, ensuring validity and length
    #[inline]
    fn from_bytes<'a>(buf: &'a [u8]) -> Result<(Self::Output<'a>, &'a [u8]), PacketHeaderError> {
        // 1. Parse fixed part
        let (header_ref, rest_buf) = Ref::<_, Self>::from_prefix(buf)
            .map_err(|_| PacketHeaderError::TooShort(Self::NAME))?;

        if !header_ref.is_valid() {
            return Err(PacketHeaderError::Invalid(Self::NAME));
        }

        let header = Ref::into_ref(header_ref);

        // 3. Calculate dynamic length
        // We use the header itself to figure out how big it is
        let total_len = header.total_len(buf);

        let options_len = total_len - Self::FIXED_LEN;

        // 4. Check if we have enough bytes for the options
        if rest_buf.len() < options_len {
            return Err(PacketHeaderError::TooShort(Self::NAME));
        }

        // 5. Split options and payload
        let (options, payload) = rest_buf.split_at(options_len);

        // 6. Construct the specific view using the hook
        let view = Self::into_view(header, options);

        Ok((view, payload))
    }
}

/// Maximum number of tunnel layers stored inline (without heap allocation)
const MAX_INLINE_TUNNELS: usize = 4;

/// Parse mode for packet parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParseMode {
    /// Keep outermost headers only. Tunnels are ignored and treated as payload.
    /// The tunnel vector will be empty.
    #[default]
    Outermost,
    /// Parse through tunnels and keep innermost headers.
    /// Tunnel headers are accumulated in the tunnel vector.
    /// Network and transport layers are overwritten with inner packet headers.
    Innermost,
}

/// Result from network layer parsing
enum NetworkResult<'a> {
    Network(NetworkLayer<'a>, NextLayer, &'a [u8]),
    Arp(ArpHeaderFull<'a>, &'a [u8]),
    Tunnel(NextLayer, &'a [u8]),
    IpipTunnel(IpipTunnel<'a>, NextLayer, &'a [u8]),
    Mpls(MplsLabelStack<'a>, NextLayer, &'a [u8]),
    Done(&'a [u8]),
}

/// Result from transport layer parsing
enum TransportResult<'a> {
    Transport(TransportLayer<'a>, NextLayer, &'a [u8]),
    Icmp(&'a IcmpHeader, &'a [u8]),
    Icmp6(&'a Icmp6Header, &'a [u8]),
    Tunnel(NextLayer, &'a [u8]),
    Done(&'a [u8]),
}

#[derive(Debug, Clone)]
pub struct Packet<'a> {
    link: LinkLayer<'a>,
    arp: Option<ArpHeaderFull<'a>>,
    network: Option<NetworkLayer<'a>>,
    transport: Option<TransportLayer<'a>>,
    tunnel: SmallVec<[NetworkTunnelLayer<'a>; MAX_INLINE_TUNNELS]>,
    data: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Parse a packet from raw bytes using the specified link type and parse mode.
    ///
    /// This method directly parses all protocol layers without using an iterator,
    /// collecting them into a structured `Packet`.
    ///
    /// # Arguments
    ///
    /// * `buf` - The raw packet bytes
    /// * `link_type` - The link layer type of the packet
    /// * `mode` - Parse mode: `Outermost` ignores tunnels, `Innermost` parses through them
    #[inline]
    pub fn from_bytes(
        buf: &'a [u8],
        link_type: LinkType,
        mode: ParseMode,
    ) -> Result<Self, PacketHeaderError> {
        let mut remaining = buf;
        let mut next_layer = NextLayer::Link(link_type);

        let mut link: Option<LinkLayer<'a>> = None;
        let mut arp: Option<ArpHeaderFull<'a>> = None;
        let mut network: Option<NetworkLayer<'a>> = None;
        let mut transport: Option<TransportLayer<'a>> = None;
        let mut tunnel: SmallVec<[NetworkTunnelLayer<'a>; MAX_INLINE_TUNNELS]> = SmallVec::new();

        // Track outer IP for tunnel encapsulation
        let mut outer_ip_for_tunnel: Option<NetworkLayer<'a>> = None;

        loop {
            match next_layer {
                NextLayer::Link(lt) => {
                    let (link_layer, next, rest) = Self::parse_link(remaining, lt)?;
                    link = Some(link_layer);
                    next_layer = next;
                    remaining = rest;
                }
                NextLayer::Network(ether_proto) => {
                    match Self::parse_network(remaining, ether_proto)? {
                        NetworkResult::Network(net, next, rest) => {
                            network = Some(net.clone());
                            outer_ip_for_tunnel = Some(net);
                            next_layer = next;
                            remaining = rest;
                        }
                        NetworkResult::Arp(a, rest) => {
                            arp = Some(a);
                            next_layer = NextLayer::Done;
                            remaining = rest;
                        }
                        NetworkResult::Tunnel(next, rest) => {
                            // In Outermost mode, treat tunnel as end of parsing
                            if mode == ParseMode::Outermost {
                                next_layer = NextLayer::Done;
                                remaining = rest;
                            } else {
                                next_layer = next;
                                remaining = rest;
                            }
                        }
                        NetworkResult::IpipTunnel(tun, next, rest) => {
                            // In Outermost mode, don't enter the tunnel
                            if mode == ParseMode::Outermost {
                                // Store the outer IP header as network layer
                                // The tunnel's outer header is the network layer
                                next_layer = NextLayer::Done;
                                remaining = rest;
                            } else {
                                // IPIP tunnel already contains outer IP, wrap in IpTunnelLayer
                                tunnel.push(NetworkTunnelLayer::new_l2(TunnelLayer::Ipip(tun)));
                                // Reset outer IP since we consumed it
                                outer_ip_for_tunnel = None;
                                next_layer = next;
                                remaining = rest;
                            }
                        }
                        NetworkResult::Mpls(mpls, next, rest) => {
                            network = Some(NetworkLayer::Mpls(mpls));
                            // In Outermost mode, stop after MPLS
                            if mode == ParseMode::Outermost {
                                next_layer = NextLayer::Done;
                            } else {
                                next_layer = next;
                            }
                            remaining = rest;
                        }
                        NetworkResult::Done(rest) => {
                            next_layer = NextLayer::Done;
                            remaining = rest;
                        }
                    }
                }
                NextLayer::Transport(ip_proto) => {
                    match Self::parse_transport(remaining, ip_proto, mode)? {
                        TransportResult::Transport(t, next, rest) => {
                            transport = Some(t);
                            next_layer = next;
                            remaining = rest;
                        }
                        TransportResult::Icmp(icmp, rest) => {
                            transport = Some(TransportLayer::Icmp(icmp));
                            next_layer = NextLayer::Done;
                            remaining = rest;
                        }
                        TransportResult::Icmp6(icmp6, rest) => {
                            transport = Some(TransportLayer::Icmp6(icmp6));
                            next_layer = NextLayer::Done;
                            remaining = rest;
                        }
                        TransportResult::Tunnel(next, rest) => {
                            // Keep outer_ip_for_tunnel for the upcoming tunnel parsing
                            next_layer = next;
                            remaining = rest;
                        }
                        TransportResult::Done(rest) => {
                            next_layer = NextLayer::Done;
                            remaining = rest;
                        }
                    }
                }
                NextLayer::Tunnel(tunnel_type) => {
                    let (tun, next, rest) = Self::parse_tunnel(remaining, tunnel_type)?;

                    // Wrap tunnel with outer IP (if available)
                    let ip_tunnel = if let Some(outer) = outer_ip_for_tunnel.take() {
                        NetworkTunnelLayer::new(outer, tun)
                    } else {
                        // Layer 2 tunnel (e.g., PBB) without IP encapsulation
                        NetworkTunnelLayer::new_l2(tun)
                    };

                    tunnel.push(ip_tunnel);

                    // If we're continuing to parse inner packet, reset network tracking
                    network = None;
                    transport = None;

                    next_layer = next;
                    remaining = rest;
                }
                NextLayer::Done => break,
            }
        }

        let link = link.ok_or(PacketHeaderError::TooShort("link layer"))?;

        Ok(Packet {
            link,
            arp,
            network,
            transport,
            tunnel,
            data: remaining,
        })
    }

    /// Parse link layer
    #[inline]
    fn parse_link(
        buf: &'a [u8],
        link_type: LinkType,
    ) -> Result<(LinkLayer<'a>, NextLayer, &'a [u8]), PacketHeaderError> {
        match link_type {
            LinkType::Ethernet => {
                let (eth, rest) = EtherHeader::from_bytes(buf)?;
                let next_proto = eth.inner_type();
                Ok((
                    LinkLayer::Ethernet(eth),
                    NextLayer::Network(next_proto),
                    rest,
                ))
            }
            LinkType::Sll => {
                let (sll, rest) = SllHeader::from_bytes(buf)?;
                let next_proto = sll.protocol();
                Ok((LinkLayer::Sll(sll), NextLayer::Network(next_proto), rest))
            }
            LinkType::Sllv2 => {
                let (sll, rest) = Sllv2Header::from_bytes(buf)?;
                let next_proto = sll.protocol();
                Ok((LinkLayer::Sllv2(sll), NextLayer::Network(next_proto), rest))
            }
            LinkType::Null => {
                let (null, rest) = NullHeader::from_bytes(buf)?;
                let next_proto = null.protocol();
                Ok((LinkLayer::Null(null), NextLayer::Network(next_proto), rest))
            }
            LinkType::RawIpv4 => {
                // Create a dummy null header for raw IP
                // Actually we need to handle this differently - parse network directly
                // For RawIpv4/RawIpv6, we don't have a link layer header
                // We'll create a special case
                Err(PacketHeaderError::Other(
                    "RawIpv4 requires special handling",
                ))
            }
            LinkType::RawIpv6 => Err(PacketHeaderError::Other(
                "RawIpv6 requires special handling",
            )),
        }
    }

    /// Parse network layer
    #[inline]
    fn parse_network(
        buf: &'a [u8],
        ether_proto: EtherProto,
    ) -> Result<NetworkResult<'a>, PacketHeaderError> {
        match ether_proto {
            EtherProto::IPV4 => {
                let (ipv4, rest) = Ipv4Header::from_bytes(buf)?;
                let proto = ipv4.protocol();

                if proto == IpProto::IP_ENCAP {
                    // IPv4-in-IPv4 tunnel
                    Ok(NetworkResult::IpipTunnel(
                        IpipTunnel::ipip(ipv4),
                        NextLayer::Network(EtherProto::IPV4),
                        rest,
                    ))
                } else if proto == IpProto::IPV6 {
                    // IPv6-in-IPv4 (SIT) tunnel
                    Ok(NetworkResult::IpipTunnel(
                        IpipTunnel::sit(ipv4),
                        NextLayer::Network(EtherProto::IPV6),
                        rest,
                    ))
                } else {
                    Ok(NetworkResult::Network(
                        NetworkLayer::Ipv4(ipv4),
                        NextLayer::Transport(proto),
                        rest,
                    ))
                }
            }
            EtherProto::IPV6 => {
                let (ipv6, rest) = Ipv6Header::from_bytes(buf)?;
                let next_proto = find_ipv6_upper_protocol(&ipv6);

                if next_proto == IpProto::IP_ENCAP {
                    // IPv4-in-IPv6 (IP4in6) tunnel
                    Ok(NetworkResult::IpipTunnel(
                        IpipTunnel::ip4in6(ipv6),
                        NextLayer::Network(EtherProto::IPV4),
                        rest,
                    ))
                } else if next_proto == IpProto::IPV6 {
                    // IPv6-in-IPv6 (IP6Tnl) tunnel
                    Ok(NetworkResult::IpipTunnel(
                        IpipTunnel::ip6tnl(ipv6),
                        NextLayer::Network(EtherProto::IPV6),
                        rest,
                    ))
                } else {
                    Ok(NetworkResult::Network(
                        NetworkLayer::Ipv6(ipv6),
                        NextLayer::Transport(next_proto),
                        rest,
                    ))
                }
            }
            EtherProto::ARP => {
                let (arp, rest) = ArpHeader::from_bytes(buf)?;
                Ok(NetworkResult::Arp(arp, rest))
            }
            EtherProto::MPLS_UC | EtherProto::MPLS_MC => {
                // Parse MPLS directly here since it goes into NetworkLayer
                match MplsLabelStack::parse(buf) {
                    Some((mpls_stack, payload)) => {
                        let next = detect_mpls_inner_protocol(payload).unwrap_or(NextLayer::Done);
                        Ok(NetworkResult::Mpls(mpls_stack, next, payload))
                    }
                    None => Err(PacketHeaderError::TooShort("MPLS")),
                }
            }
            EtherProto::TEB => {
                // Transparent Ethernet Bridging - inner Ethernet frame
                Ok(NetworkResult::Tunnel(
                    NextLayer::Link(LinkType::Ethernet),
                    buf,
                ))
            }
            EtherProto::VLAN_8021AH | EtherProto::VLAN_8021AD => {
                // PBB (Provider Backbone Bridge / MAC-in-MAC)
                Ok(NetworkResult::Tunnel(
                    NextLayer::Tunnel(TunnelType::Pbb),
                    buf,
                ))
            }
            _ => {
                // Unknown network protocol - stop parsing
                Ok(NetworkResult::Done(buf))
            }
        }
    }

    /// Parse transport layer
    #[inline]
    fn parse_transport(
        buf: &'a [u8],
        ip_proto: IpProto,
        mode: ParseMode,
    ) -> Result<TransportResult<'a>, PacketHeaderError> {
        match ip_proto {
            IpProto::TCP => {
                let (tcp, rest) = TcpHeader::from_bytes(buf)?;

                // In Outermost mode, don't detect tunnels
                if mode == ParseMode::Outermost {
                    return Ok(TransportResult::Transport(
                        TransportLayer::Tcp(tcp),
                        NextLayer::Done,
                        rest,
                    ));
                }

                let src_port = tcp.src_port();
                let dst_port = tcp.dst_port();

                // Check for STT tunnel (TCP port 7471)
                if is_stt_port(dst_port) || is_stt_port(src_port) {
                    Ok(TransportResult::Transport(
                        TransportLayer::Tcp(tcp),
                        NextLayer::Tunnel(TunnelType::Stt),
                        rest,
                    ))
                } else {
                    Ok(TransportResult::Transport(
                        TransportLayer::Tcp(tcp),
                        NextLayer::Done,
                        rest,
                    ))
                }
            }
            IpProto::UDP => {
                let (udp, rest) = UdpHeader::from_bytes(buf)?;

                // In Outermost mode, don't detect tunnels
                if mode == ParseMode::Outermost {
                    return Ok(TransportResult::Transport(
                        TransportLayer::Udp(udp),
                        NextLayer::Done,
                        rest,
                    ));
                }

                let src_port = udp.src_port();
                let dst_port = udp.dst_port();

                // Check for tunnel protocols based on UDP ports
                if let Some(tunnel_type) = detect_udp_tunnel(src_port, dst_port, rest) {
                    Ok(TransportResult::Transport(
                        TransportLayer::Udp(udp),
                        NextLayer::Tunnel(tunnel_type),
                        rest,
                    ))
                } else {
                    Ok(TransportResult::Transport(
                        TransportLayer::Udp(udp),
                        NextLayer::Done,
                        rest,
                    ))
                }
            }
            IpProto::SCTP => {
                let (sctp, rest) = SctpHeader::from_bytes(buf)?;
                Ok(TransportResult::Transport(
                    TransportLayer::Sctp(sctp),
                    NextLayer::Done,
                    rest,
                ))
            }
            IpProto::ICMP => {
                let (icmp, rest) = IcmpHeader::from_bytes(buf)?;
                Ok(TransportResult::Icmp(icmp, rest))
            }
            IpProto::IPV6_ICMP => {
                let (icmp6, rest) = Icmp6Header::from_bytes(buf)?;
                Ok(TransportResult::Icmp6(icmp6, rest))
            }
            IpProto::GRE => {
                // In Outermost mode, treat GRE as end of parsing
                if mode == ParseMode::Outermost {
                    return Ok(TransportResult::Done(buf));
                }
                let tunnel_type = detect_gre_variant(buf);
                Ok(TransportResult::Tunnel(NextLayer::Tunnel(tunnel_type), buf))
            }
            IpProto::L2TP => {
                // In Outermost mode, treat L2TP as end of parsing
                if mode == ParseMode::Outermost {
                    return Ok(TransportResult::Done(buf));
                }
                // L2TPv3 over IP (protocol 115)
                Ok(TransportResult::Tunnel(
                    NextLayer::Tunnel(TunnelType::L2tpv3),
                    buf,
                ))
            }
            IpProto::IPV6_NONXT => {
                // No next header - we're done
                Ok(TransportResult::Done(buf))
            }
            _ => {
                // Unknown transport protocol - stop parsing
                Ok(TransportResult::Done(buf))
            }
        }
    }

    /// Parse tunnel layer
    #[inline]
    fn parse_tunnel(
        buf: &'a [u8],
        tunnel_type: TunnelType,
    ) -> Result<(TunnelLayer<'a>, NextLayer, &'a [u8]), PacketHeaderError> {
        match tunnel_type {
            TunnelType::Vxlan => {
                let (vxlan, rest) = VxlanHeader::from_bytes(buf)?;
                Ok((
                    TunnelLayer::Vxlan(vxlan),
                    NextLayer::Link(LinkType::Ethernet),
                    rest,
                ))
            }
            TunnelType::Geneve => {
                let (geneve, rest) = GeneveHeader::from_bytes(buf)?;
                let inner_proto = geneve.protocol_type();
                Ok((
                    TunnelLayer::Geneve(geneve),
                    NextLayer::Network(inner_proto),
                    rest,
                ))
            }
            TunnelType::Gre => {
                let (gre, rest) = GreHeader::from_bytes(buf)?;
                let inner_proto = gre.protocol_type();
                let next = if inner_proto == EtherProto::TEB {
                    NextLayer::Link(LinkType::Ethernet)
                } else {
                    NextLayer::Network(inner_proto)
                };
                Ok((TunnelLayer::Gre(gre), next, rest))
            }
            TunnelType::Mpls => {
                // MPLS is handled in parse_network via NetworkResult::Mpls
                // This should not be reached, but handle it gracefully
                Err(PacketHeaderError::Other(
                    "MPLS should be handled in network layer",
                ))
            }
            TunnelType::Teredo => {
                let teredo = TeredoPacket::parse(buf)?;
                let payload = teredo.ipv6_payload();
                Ok((
                    TunnelLayer::Teredo(Box::new(teredo)),
                    NextLayer::Network(EtherProto::IPV6),
                    payload,
                ))
            }
            TunnelType::Gtpv1 => {
                let (gtpv1, rest) = Gtpv1Header::from_bytes(buf)?;
                let next = if gtpv1.is_gpdu() && !rest.is_empty() {
                    let version = (rest[0] & 0xF0) >> 4;
                    match version {
                        4 => NextLayer::Network(EtherProto::IPV4),
                        6 => NextLayer::Network(EtherProto::IPV6),
                        _ => NextLayer::Done,
                    }
                } else {
                    NextLayer::Done
                };
                Ok((TunnelLayer::Gtpv1(gtpv1), next, rest))
            }
            TunnelType::Gtpv2 => {
                let (gtpv2, rest) = Gtpv2Header::from_bytes(buf)?;
                Ok((TunnelLayer::Gtpv2(gtpv2), NextLayer::Done, rest))
            }
            TunnelType::L2tpv2 => {
                let (l2tpv2, rest) = L2tpv2Header::from_bytes(buf)?;
                Ok((TunnelLayer::L2tpv2(l2tpv2), NextLayer::Done, rest))
            }
            TunnelType::L2tpv3 => {
                let (l2tpv3, rest) = L2tpv3SessionHeader::parse_with_cookie_len(buf, 0)?;
                let next = if !rest.is_empty() {
                    let first_byte = rest[0];
                    if first_byte == 0x00 || (first_byte & 0xF0) == 0x00 {
                        NextLayer::Link(LinkType::Ethernet)
                    } else {
                        NextLayer::Done
                    }
                } else {
                    NextLayer::Done
                };
                Ok((TunnelLayer::L2tpv3(l2tpv3), next, rest))
            }
            TunnelType::Nvgre => {
                let (nvgre, rest) = NvgreHeader::from_bytes(buf)?;
                Ok((
                    TunnelLayer::Nvgre(nvgre),
                    NextLayer::Link(LinkType::Ethernet),
                    rest,
                ))
            }
            TunnelType::Pbb => {
                let (pbb, rest) = PbbHeader::parse(buf)?;
                Ok((
                    TunnelLayer::Pbb(pbb),
                    NextLayer::Link(LinkType::Ethernet),
                    rest,
                ))
            }
            TunnelType::Stt => match SttPacket::parse(buf) {
                Some(stt) => {
                    let payload = stt.payload;
                    Ok((
                        TunnelLayer::Stt(stt),
                        NextLayer::Link(LinkType::Ethernet),
                        payload,
                    ))
                }
                None => Err(PacketHeaderError::TooShort("STT")),
            },
            TunnelType::Pptp => {
                let (pptp, rest) = PptpGreHeader::from_bytes(buf)?;
                Ok((TunnelLayer::Pptp(pptp), NextLayer::Done, rest))
            }
        }
    }

    /// Returns a reference to the link layer header.
    #[inline]
    pub fn link(&self) -> &LinkLayer<'a> {
        &self.link
    }

    /// Returns a reference to the ARP header, if present.
    #[inline]
    pub fn arp(&self) -> Option<&ArpHeaderFull<'a>> {
        self.arp.as_ref()
    }

    /// Returns a reference to the network layer header, if present.
    #[inline]
    pub fn network(&self) -> Option<&NetworkLayer<'a>> {
        self.network.as_ref()
    }

    /// Returns a reference to the transport layer header, if present.
    #[inline]
    pub fn transport(&self) -> Option<&TransportLayer<'a>> {
        self.transport.as_ref()
    }

    /// Returns a slice of IP tunnel layer headers.
    #[inline]
    pub fn tunnels(&self) -> &[NetworkTunnelLayer<'a>] {
        &self.tunnel
    }

    /// Returns the remaining payload data after all parsed headers.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> fmt::Display for Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Link layer
        writeln!(f, "        {}", self.link)?;

        // ARP (if present)
        if let Some(ref arp) = self.arp {
            writeln!(f, "        {}", arp)?;
        }

        // Tunnel layers
        for tunnel in &self.tunnel {
            writeln!(f, "        {}", tunnel)?;
        }

        // Network layer (if present)
        if let Some(ref network) = self.network {
            writeln!(f, "        {}", network)?;
        }

        // Transport layer (if present)
        if let Some(ref transport) = self.transport {
            writeln!(f, "        {}", transport)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::iter::LinkType;

    /// Create Ethernet + IPv4 + UDP + VXLAN + inner Ethernet + inner IPv4 packet
    fn create_vxlan_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Outer Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // Outer IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&72u16.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // Outer UDP header (8 bytes)
        packet.extend_from_slice(&12345u16.to_be_bytes()); // Src port
        packet.extend_from_slice(&4789u16.to_be_bytes()); // Dst port (VXLAN)
        packet.extend_from_slice(&52u16.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        // VXLAN header (8 bytes)
        packet.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // Flags (I=1)
        packet.extend_from_slice(&[0x00, 0x00, 0x64, 0x00]); // VNI = 100

        // Inner Ethernet header (14 bytes)
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // Dest MAC
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // Inner IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP, ECN
        packet.extend_from_slice(&28u16.to_be_bytes()); // Total length (20 + 8 ICMP)
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment offset
        packet.push(64); // TTL
        packet.push(1); // Protocol: ICMP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        // ICMP Echo Request (8 bytes)
        packet.push(8); // Type: Echo Request
        packet.push(0); // Code
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x01]); // Identifier
        packet.extend_from_slice(&[0x00, 0x01]); // Sequence number

        packet
    }

    #[test]
    fn test_vxlan_tunnel_parsing_innermost() {
        let packet_bytes = create_vxlan_packet();
        let packet = Packet::from_bytes(&packet_bytes, LinkType::Ethernet, ParseMode::Innermost)
            .expect("Should parse VXLAN packet");

        // Should have exactly one tunnel (VXLAN)
        assert_eq!(
            packet.tunnels().len(),
            1,
            "Expected 1 tunnel, got {}",
            packet.tunnels().len()
        );

        // The tunnel should be VXLAN
        assert!(
            matches!(packet.tunnels()[0].tunnel(), TunnelLayer::Vxlan(_)),
            "Expected VXLAN tunnel, got {:?}",
            packet.tunnels()[0].tunnel()
        );

        // The outer IP should be present
        assert!(
            packet.tunnels()[0].outer().is_some(),
            "Expected outer IP header"
        );
        assert!(
            matches!(packet.tunnels()[0].outer().unwrap(), NetworkLayer::Ipv4(_)),
            "Expected outer IPv4"
        );

        // Network should be the inner IPv4
        assert!(packet.network().is_some(), "Expected network layer");
        assert!(matches!(packet.network().unwrap(), NetworkLayer::Ipv4(_)));
    }

    #[test]
    fn test_vxlan_tunnel_parsing_outermost() {
        let packet_bytes = create_vxlan_packet();
        let packet = Packet::from_bytes(&packet_bytes, LinkType::Ethernet, ParseMode::Outermost)
            .expect("Should parse VXLAN packet");

        // Outermost mode should NOT parse tunnels
        assert_eq!(
            packet.tunnels().len(),
            0,
            "Outermost mode should have 0 tunnels"
        );

        // Network should be the outer IPv4
        assert!(packet.network().is_some(), "Expected network layer");
    }

    #[test]
    fn test_ip_tunnel_layer_structure() {
        let packet_bytes = create_vxlan_packet();
        let packet = Packet::from_bytes(&packet_bytes, LinkType::Ethernet, ParseMode::Innermost)
            .expect("Should parse VXLAN packet");

        // Verify IpTunnelLayer structure
        assert_eq!(packet.tunnels().len(), 1);
        let ip_tunnel = &packet.tunnels()[0];

        // Check outer IP header exists and is IPv4
        assert!(
            ip_tunnel.outer().is_some(),
            "Outer IP should be present for VXLAN"
        );
        match ip_tunnel.outer().unwrap() {
            NetworkLayer::Ipv4(ipv4) => {
                // Verify outer IPs match what we created
                assert_eq!(ipv4.src_ip().to_string(), "10.0.0.1");
                assert_eq!(ipv4.dst_ip().to_string(), "10.0.0.2");
            }
            _ => panic!("Expected IPv4 outer header"),
        }

        // Check tunnel layer is VXLAN
        match ip_tunnel.tunnel() {
            TunnelLayer::Vxlan(vxlan) => {
                assert_eq!(vxlan.vni(), 100, "Expected VNI 100");
            }
            _ => panic!("Expected VXLAN tunnel"),
        }

        // Verify Display format includes both outer and tunnel
        let display = format!("{}", ip_tunnel);
        assert!(display.contains("IPv4"), "Display should show outer IPv4");
        assert!(
            display.contains("VXLAN"),
            "Display should show VXLAN tunnel"
        );
    }
}
