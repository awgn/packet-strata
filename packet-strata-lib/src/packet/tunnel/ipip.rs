//! IP-in-IP Tunnel parsers
//!
//! This module provides structures to represent various IP-in-IP encapsulation tunnels:
//!
//! - **IPIP** (IPv4-in-IPv4) - RFC 2003, IP protocol 4
//! - **SIT/6in4** (IPv6-in-IPv4) - RFC 4213, IP protocol 41
//! - **IP4in6** (IPv4-in-IPv6) - RFC 2473, IPv6 next header 4
//! - **IP6Tnl** (IPv6-in-IPv6) - RFC 2473, IPv6 next header 41
//!
//! # Overview
//!
//! IP-in-IP tunneling is a simple encapsulation technique where an IP packet
//! is encapsulated directly within another IP packet. The outer IP header's
//! protocol field indicates the type of inner packet.
//!
//! # Protocol Numbers
//!
//! | Tunnel Type | Outer | Inner | Protocol/Next Header |
//! |-------------|-------|-------|---------------------|
//! | IPIP        | IPv4  | IPv4  | 4 (IP-ENCAP)        |
//! | SIT/6in4    | IPv4  | IPv6  | 41 (IPv6)           |
//! | IP4in6      | IPv6  | IPv4  | 4 (IP-ENCAP)        |
//! | IP6Tnl      | IPv6  | IPv6  | 41 (IPv6)           |

use std::fmt;

use crate::packet::ipv4::Ipv4HeaderOpt;
use crate::packet::ipv6::Ipv6HeaderExt;

/// Type of IP-in-IP tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpipType {
    /// IPv4-in-IPv4 (RFC 2003)
    Ipip,
    /// IPv6-in-IPv4 (RFC 4213) - also known as 6in4 or SIT
    Sit,
    /// IPv4-in-IPv6 (RFC 2473)
    Ip4in6,
    /// IPv6-in-IPv6 (RFC 2473)
    Ip6Tnl,
}

impl IpipType {
    /// Returns the tunnel type name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ipip => "IPIP",
            Self::Sit => "SIT",
            Self::Ip4in6 => "IP4in6",
            Self::Ip6Tnl => "IP6Tnl",
        }
    }

    /// Returns a description of the tunnel type
    pub fn description(&self) -> &'static str {
        match self {
            Self::Ipip => "IPv4-in-IPv4 (RFC 2003)",
            Self::Sit => "IPv6-in-IPv4 (RFC 4213)",
            Self::Ip4in6 => "IPv4-in-IPv6 (RFC 2473)",
            Self::Ip6Tnl => "IPv6-in-IPv6 (RFC 2473)",
        }
    }
}

impl fmt::Display for IpipType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// The outer IP header of an IP-in-IP tunnel
#[derive(Debug, Clone)]
pub enum OuterIpHeader<'a> {
    /// IPv4 outer header
    V4(Ipv4HeaderOpt<'a>),
    /// IPv6 outer header
    V6(Ipv6HeaderExt<'a>),
}

impl<'a> fmt::Display for OuterIpHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OuterIpHeader::V4(h) => write!(f, "{}", h),
            OuterIpHeader::V6(h) => write!(f, "{}", h),
        }
    }
}

/// IP-in-IP tunnel representation
///
/// This structure wraps the outer IP header along with the tunnel type.
/// The outer IP header addresses can be accessed via the `outer_header()` method.
#[derive(Debug, Clone)]
pub struct IpipTunnel<'a> {
    /// Type of tunnel
    tunnel_type: IpipType,
    /// The outer IP header
    outer_header: OuterIpHeader<'a>,
}

impl<'a> IpipTunnel<'a> {
    /// Create a new IP-in-IP tunnel with the given type and outer header
    #[inline]
    pub fn new(tunnel_type: IpipType, outer_header: OuterIpHeader<'a>) -> Self {
        Self {
            tunnel_type,
            outer_header,
        }
    }

    /// Create an IPIP tunnel (IPv4-in-IPv4) with the outer IPv4 header
    #[inline]
    pub fn ipip(outer: Ipv4HeaderOpt<'a>) -> Self {
        Self::new(IpipType::Ipip, OuterIpHeader::V4(outer))
    }

    /// Create a SIT tunnel (IPv6-in-IPv4) with the outer IPv4 header
    #[inline]
    pub fn sit(outer: Ipv4HeaderOpt<'a>) -> Self {
        Self::new(IpipType::Sit, OuterIpHeader::V4(outer))
    }

    /// Create an IP4in6 tunnel (IPv4-in-IPv6) with the outer IPv6 header
    #[inline]
    pub fn ip4in6(outer: Ipv6HeaderExt<'a>) -> Self {
        Self::new(IpipType::Ip4in6, OuterIpHeader::V6(outer))
    }

    /// Create an IP6Tnl tunnel (IPv6-in-IPv6) with the outer IPv6 header
    #[inline]
    pub fn ip6tnl(outer: Ipv6HeaderExt<'a>) -> Self {
        Self::new(IpipType::Ip6Tnl, OuterIpHeader::V6(outer))
    }

    /// Returns the tunnel type
    #[inline]
    pub fn tunnel_type(&self) -> IpipType {
        self.tunnel_type
    }

    /// Returns the tunnel name
    #[inline]
    pub fn name(&self) -> &'static str {
        self.tunnel_type.name()
    }

    /// Returns a reference to the outer IP header
    #[inline]
    pub fn outer_header(&self) -> &OuterIpHeader<'a> {
        &self.outer_header
    }

    /// Returns the outer IPv4 header if present
    #[inline]
    pub fn outer_ipv4(&self) -> Option<&Ipv4HeaderOpt<'a>> {
        match &self.outer_header {
            OuterIpHeader::V4(h) => Some(h),
            OuterIpHeader::V6(_) => None,
        }
    }

    /// Returns the outer IPv6 header if present
    #[inline]
    pub fn outer_ipv6(&self) -> Option<&Ipv6HeaderExt<'a>> {
        match &self.outer_header {
            OuterIpHeader::V4(_) => None,
            OuterIpHeader::V6(h) => Some(h),
        }
    }
}

impl fmt::Display for IpipTunnel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.tunnel_type.name(), self.outer_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require constructing Ipv4HeaderOpt/Ipv6HeaderExt from packet data,
    // which is tested in the iterator tests. Here we test the basic type functionality.

    #[test]
    fn test_tunnel_type_names() {
        assert_eq!(IpipType::Ipip.name(), "IPIP");
        assert_eq!(IpipType::Sit.name(), "SIT");
        assert_eq!(IpipType::Ip4in6.name(), "IP4in6");
        assert_eq!(IpipType::Ip6Tnl.name(), "IP6Tnl");
    }

    #[test]
    fn test_tunnel_type_descriptions() {
        assert_eq!(IpipType::Ipip.description(), "IPv4-in-IPv4 (RFC 2003)");
        assert_eq!(IpipType::Sit.description(), "IPv6-in-IPv4 (RFC 4213)");
        assert_eq!(IpipType::Ip4in6.description(), "IPv4-in-IPv6 (RFC 2473)");
        assert_eq!(IpipType::Ip6Tnl.description(), "IPv6-in-IPv6 (RFC 2473)");
    }

    #[test]
    fn test_tunnel_type_display() {
        assert_eq!(format!("{}", IpipType::Ipip), "IPIP");
        assert_eq!(format!("{}", IpipType::Sit), "SIT");
        assert_eq!(format!("{}", IpipType::Ip4in6), "IP4in6");
        assert_eq!(format!("{}", IpipType::Ip6Tnl), "IP6Tnl");
    }
}
