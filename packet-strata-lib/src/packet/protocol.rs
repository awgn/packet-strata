//! IP Protocol Numbers
//!
//! This module defines IP protocol numbers as specified in RFC 1700 and maintained
//! by IANA. These protocol numbers are used in IPv4 headers (Protocol field) and
//! IPv6 headers (Next Header field).
//!
//! # Examples
//!
//! ```
//! use packet_strata::packet::protocol::IpProto;
//!
//! // Common protocols
//! let tcp = IpProto::TCP;
//! let udp = IpProto::UDP;
//! let icmp = IpProto::ICMP;
//!
//! // IPv6 extension headers
//! let hop_by_hop = IpProto::IPV6_HOPOPT;
//! let routing = IpProto::IPV6_ROUTE;
//! let fragment = IpProto::IPV6_FRAG;
//!
//! // Display protocol names
//! assert_eq!(format!("{}", tcp), "tcp");
//! assert_eq!(format!("{}", udp), "udp");
//! assert_eq!(format!("{}", IpProto::IPV6_ICMP), "icmp6");
//!
//! // Convert from/to u8
//! let proto = IpProto::from(6);
//! assert_eq!(proto, IpProto::TCP);
//! let value: u8 = IpProto::UDP.into();
//! assert_eq!(value, 17);
//!
//! // Check if protocol is valid/known
//! assert!(IpProto::TCP.is_valid());
//! assert!(IpProto::UDP.is_valid());
//! assert!(!IpProto::from(200).is_valid());
//! ```

use core::fmt::{self, Display, Formatter};
use serde::{Deserialize, Serialize};
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout, Serialize, Deserialize)]
#[serde(into = "u16")]
#[serde(try_from = "u16")]
pub struct EtherProto(pub U16<BigEndian>);

impl Default for EtherProto {
    fn default() -> Self {
        EtherProto::IPV4
    }
}

impl EtherProto {
    // DIX Ethernet Protocol Types
    pub const LOOP: EtherProto = EtherProto(U16::new(0x0060)); /* Ethernet Loopback packet */
    pub const PUP: EtherProto = EtherProto(U16::new(0x0200)); /* Xerox PUP packet */
    pub const PUPAT: EtherProto = EtherProto(U16::new(0x0201)); /* Xerox PUP Addr Trans packet */
    pub const IPV4: EtherProto = EtherProto(U16::new(0x0800)); /* Internet Protocol packet (was IP) */
    pub const X25: EtherProto = EtherProto(U16::new(0x0805)); /* CCITT X.25 */
    pub const ARP: EtherProto = EtherProto(U16::new(0x0806)); /* Address Resolution packet */
    pub const BPQ: EtherProto = EtherProto(U16::new(0x08FF)); /* G8BPQ AX.25 Ethernet Packet [NOT AN OFFICIALLY REGISTERED ID] */
    pub const IEEEPUP: EtherProto = EtherProto(U16::new(0x0a00)); /* Xerox IEEE802.3 PUP packet */
    pub const IEEEPUPAT: EtherProto = EtherProto(U16::new(0x0a01)); /* Xerox IEEE802.3 PUP Addr Trans packet */
    pub const BATMAN: EtherProto = EtherProto(U16::new(0x4305)); /* B.A.T.M.A.N.-Advanced packet [NOT AN OFFICIALLY REGISTERED ID] */
    pub const DEC: EtherProto = EtherProto(U16::new(0x6000)); /* DEC Assigned proto */
    pub const DNA_DL: EtherProto = EtherProto(U16::new(0x6001)); /* DEC DNA Dump/Load */
    pub const DNA_RC: EtherProto = EtherProto(U16::new(0x6002)); /* DEC DNA Remote Console */
    pub const DNA_RT: EtherProto = EtherProto(U16::new(0x6003)); /* DEC DNA Routing */
    pub const LAT: EtherProto = EtherProto(U16::new(0x6004)); /* DEC LAT */
    pub const DIAG: EtherProto = EtherProto(U16::new(0x6005)); /* DEC Diagnostics */
    pub const CUST: EtherProto = EtherProto(U16::new(0x6006)); /* DEC Customer use */
    pub const SCA: EtherProto = EtherProto(U16::new(0x6007)); /* DEC Systems Comms Arch */
    pub const TEB: EtherProto = EtherProto(U16::new(0x6558)); /* Transp. Ether Bridging */
    pub const RARP: EtherProto = EtherProto(U16::new(0x8035)); /* Reverse Addr Res packet */
    pub const ATALK: EtherProto = EtherProto(U16::new(0x809B)); /* Appletalk DDP */
    pub const AARP: EtherProto = EtherProto(U16::new(0x80F3)); /* Appletalk AARP */
    pub const VLAN_8021Q: EtherProto = EtherProto(U16::new(0x8100)); /* 802.1Q VLAN Extended Header (was VLAN_8021Q) */
    pub const IPX: EtherProto = EtherProto(U16::new(0x8137)); /* IPX over DIX */
    pub const IPV6: EtherProto = EtherProto(U16::new(0x86DD)); /* IPv6 over bluebook */
    pub const PAUSE: EtherProto = EtherProto(U16::new(0x8808)); /* IEEE Pause frames. See 802.3 31B */
    pub const SLOW: EtherProto = EtherProto(U16::new(0x8809)); /* Slow Protocol. See 802.3ad 43B */
    pub const WCCP: EtherProto = EtherProto(U16::new(0x883E)); /* Web-cache coordination protocol */
    pub const MPLS_UC: EtherProto = EtherProto(U16::new(0x8847)); /* MPLS Unicast traffic */
    pub const MPLS_MC: EtherProto = EtherProto(U16::new(0x8848)); /* MPLS Multicast traffic */
    pub const ATMMPOA: EtherProto = EtherProto(U16::new(0x884c)); /* MultiProtocol Over ATM */
    pub const PPP_DISC: EtherProto = EtherProto(U16::new(0x8863)); /* PPPoE discovery messages */
    pub const PPP_SES: EtherProto = EtherProto(U16::new(0x8864)); /* PPPoE session messages */
    pub const LINK_CTL: EtherProto = EtherProto(U16::new(0x886c)); /* HPNA, wlan link local tunnel */
    pub const ATMFATE: EtherProto = EtherProto(U16::new(0x8884)); /* Frame-based ATM Transport over Ethernet */
    pub const PAE: EtherProto = EtherProto(U16::new(0x888E)); /* Port Access Entity (IEEE 802.1X) */
    pub const AOE: EtherProto = EtherProto(U16::new(0x88A2)); /* ATA over Ethernet */
    pub const VLAN_8021AD: EtherProto = EtherProto(U16::new(0x88A8)); /* 802.1ad Service VLAN */
    pub const IEEE_802_EX1: EtherProto = EtherProto(U16::new(0x88B5)); /* 802.1 Local Experimental 1. */
    pub const TIPC: EtherProto = EtherProto(U16::new(0x88CA)); /* TIPC */
    pub const VLAN_8021AH: EtherProto = EtherProto(U16::new(0x88E7)); /* 802.1ah Backbone Service Tag */
    pub const MVRP: EtherProto = EtherProto(U16::new(0x88F5)); /* 802.1Q MVRP */
    pub const IEEE_1588: EtherProto = EtherProto(U16::new(0x88F7)); /* IEEE 1588 Timesync */
    pub const PRP: EtherProto = EtherProto(U16::new(0x88FB)); /* IEC 62439-3 PRP/HSRv0 */
    pub const FCOE: EtherProto = EtherProto(U16::new(0x8906)); /* Fibre Channel over Ethernet */
    pub const TDLS: EtherProto = EtherProto(U16::new(0x890D)); /* TDLS */
    pub const FIP: EtherProto = EtherProto(U16::new(0x8914)); /* FCoE Initialization Protocol */
    pub const IEEE_80221: EtherProto = EtherProto(U16::new(0x8917)); /* IEEE 802.21 Media Independent Handover Protocol */
    pub const LOOPBACK: EtherProto = EtherProto(U16::new(0x9000)); /* Ethernet loopback packet, per IEEE 802.3 */
    pub const QINQ1: EtherProto = EtherProto(U16::new(0x9100)); /* deprecated QinQ VLAN [NOT AN OFFICIALLY REGISTERED ID] */
    pub const QINQ2: EtherProto = EtherProto(U16::new(0x9200)); /* deprecated QinQ VLAN [NOT AN OFFICIALLY REGISTERED ID] */
    pub const QINQ3: EtherProto = EtherProto(U16::new(0x9300)); /* deprecated QinQ VLAN [NOT AN OFFICIALLY REGISTERED ID] */
    pub const EDSA: EtherProto = EtherProto(U16::new(0xDADA)); /* Ethertype DSA [NOT AN OFFICIALLY REGISTERED ID] */
    pub const AF_IUCV: EtherProto = EtherProto(U16::new(0xFBFB)); /* IBM af_iucv [NOT AN OFFICIALLY REGISTERED ID] */
    pub const IEEE_802_3_MIN: EtherProto = EtherProto(U16::new(0x0600)); /* If the value in the ethernet type is less than this value then the frame is Ethernet II. Else it is 802.3 */

    // Non DIX types. Won't clash for 1500 types.
    pub const IEEE_802_3: EtherProto = EtherProto(U16::new(0x0001)); /* Dummy type for 802.3 frames */
    pub const AX25: EtherProto = EtherProto(U16::new(0x0002)); /* Dummy protocol id for AX.25 */
    pub const ALL: EtherProto = EtherProto(U16::new(0x0003)); /* Every packet (be careful!!!) */
    pub const IEEE_802_2: EtherProto = EtherProto(U16::new(0x0004)); /* 802.2 frames */
    pub const SNAP: EtherProto = EtherProto(U16::new(0x0005)); /* Internal only */
    pub const DDCMP: EtherProto = EtherProto(U16::new(0x0006)); /* DEC DDCMP: Internal only */
    pub const WAN_PPP: EtherProto = EtherProto(U16::new(0x0007)); /* Dummy type for WAN PPP frames */
    pub const PPP_MP: EtherProto = EtherProto(U16::new(0x0008)); /* Dummy type for PPP MP frames */
    pub const LOCALTALK: EtherProto = EtherProto(U16::new(0x0009)); /* Localtalk pseudo type */
    pub const CAN: EtherProto = EtherProto(U16::new(0x000C)); /* CAN: Controller Area Network */
    pub const CANFD: EtherProto = EtherProto(U16::new(0x000D)); /* CANFD: CAN flexible data rate */
    pub const PPPTALK: EtherProto = EtherProto(U16::new(0x0010)); /* Dummy type for Atalk over PPP */
    pub const TR_802_2: EtherProto = EtherProto(U16::new(0x0011)); /* 802.2 frames */
    pub const MOBITEX: EtherProto = EtherProto(U16::new(0x0015)); /* Mobitex (kaz@cafe.net) */
    pub const CONTROL: EtherProto = EtherProto(U16::new(0x0016)); /* Card specific control frames */
    pub const IRDA: EtherProto = EtherProto(U16::new(0x0017)); /* Linux-IrDA */
    pub const ECONET: EtherProto = EtherProto(U16::new(0x0018)); /* Acorn Econet */
    pub const HDLC: EtherProto = EtherProto(U16::new(0x0019)); /* HDLC frames */
    pub const ARCNET: EtherProto = EtherProto(U16::new(0x001A)); /* 1A for ArcNet :-) */
    pub const DSA: EtherProto = EtherProto(U16::new(0x001B)); /* Distributed Switch Arch. */
    pub const TRAILER: EtherProto = EtherProto(U16::new(0x001C)); /* Trailer switch tagging */
    pub const PHONET: EtherProto = EtherProto(U16::new(0x00F5)); /* Nokia Phonet frames */
    pub const IEEE802154: EtherProto = EtherProto(U16::new(0x00F6)); /* IEEE802.15.4 frame */
    pub const CAIF: EtherProto = EtherProto(U16::new(0x00F7)); /* ST-Ericsson CAIF protocol */
}

impl Display for EtherProto {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let name = match *self {
            // DIX Ethernet Protocol Types
            EtherProto::LOOP => "loop",
            EtherProto::PUP => "pup",
            EtherProto::PUPAT => "pupat",
            EtherProto::IPV4 => "ipv4",
            EtherProto::X25 => "x25",
            EtherProto::ARP => "arp",
            EtherProto::BPQ => "bpq",
            EtherProto::IEEEPUP => "ieeepup",
            EtherProto::IEEEPUPAT => "ieeepupat",
            EtherProto::BATMAN => "batman",
            EtherProto::DEC => "dec",
            EtherProto::DNA_DL => "dna_dl",
            EtherProto::DNA_RC => "dna_rc",
            EtherProto::DNA_RT => "dna_rt",
            EtherProto::LAT => "lat",
            EtherProto::DIAG => "diag",
            EtherProto::CUST => "cust",
            EtherProto::SCA => "sca",
            EtherProto::TEB => "teb",
            EtherProto::RARP => "rarp",
            EtherProto::ATALK => "atalk",
            EtherProto::AARP => "aarp",
            EtherProto::VLAN_8021Q => "vlan_8021q",
            EtherProto::IPX => "ipx",
            EtherProto::IPV6 => "ipv6",
            EtherProto::PAUSE => "pause",
            EtherProto::SLOW => "slow",
            EtherProto::WCCP => "wccp",
            EtherProto::MPLS_UC => "mpls_uc",
            EtherProto::MPLS_MC => "mpls_mc",
            EtherProto::ATMMPOA => "atmmpoa",
            EtherProto::PPP_DISC => "ppp_disc",
            EtherProto::PPP_SES => "ppp_ses",
            EtherProto::LINK_CTL => "link_ctl",
            EtherProto::ATMFATE => "atmfate",
            EtherProto::PAE => "pae",
            EtherProto::AOE => "aoe",
            EtherProto::VLAN_8021AD => "vlan_8021ad",
            EtherProto::IEEE_802_EX1 => "ieee_802_ex1",
            EtherProto::TIPC => "tipc",
            EtherProto::VLAN_8021AH => "vlan_8021ah",
            EtherProto::MVRP => "mvrp",
            EtherProto::IEEE_1588 => "ieee_1588",
            EtherProto::PRP => "prp",
            EtherProto::FCOE => "fcoe",
            EtherProto::TDLS => "tdls",
            EtherProto::FIP => "fip",
            EtherProto::IEEE_80221 => "ieee_80221",
            EtherProto::LOOPBACK => "loopback",
            EtherProto::QINQ1 => "qinq1",
            EtherProto::QINQ2 => "qinq2",
            EtherProto::QINQ3 => "qinq3",
            EtherProto::EDSA => "edsa",
            EtherProto::AF_IUCV => "af_iucv",
            EtherProto::IEEE_802_3_MIN => "ieee_802_3_min",
            // Non DIX types
            EtherProto::IEEE_802_3 => "ieee_802_3",
            EtherProto::AX25 => "ax25",
            EtherProto::ALL => "all",
            EtherProto::IEEE_802_2 => "ieee_802_2",
            EtherProto::SNAP => "snap",
            EtherProto::DDCMP => "ddcmp",
            EtherProto::WAN_PPP => "wan_ppp",
            EtherProto::PPP_MP => "ppp_mp",
            EtherProto::LOCALTALK => "localtalk",
            EtherProto::CAN => "can",
            EtherProto::CANFD => "canfd",
            EtherProto::PPPTALK => "ppptalk",
            EtherProto::TR_802_2 => "tr_802_2",
            EtherProto::MOBITEX => "mobitex",
            EtherProto::CONTROL => "control",
            EtherProto::IRDA => "irda",
            EtherProto::ECONET => "econet",
            EtherProto::HDLC => "hdlc",
            EtherProto::ARCNET => "arcnet",
            EtherProto::DSA => "dsa",
            EtherProto::TRAILER => "trailer",
            EtherProto::PHONET => "phonet",
            EtherProto::IEEE802154 => "ieee802154",
            EtherProto::CAIF => "caif",
            _ => return write!(f, "0x{:04x}", self.0.get()),
        };
        write!(f, "{}", name)
    }
}

impl From<u16> for EtherProto {
    fn from(value: u16) -> Self {
        EtherProto(U16::new(value))
    }
}

impl From<EtherProto> for u16 {
    fn from(proto: EtherProto) -> Self {
        proto.0.get()
    }
}

/// IP Protocol Number
///
/// A newtype wrapper around a `u8` representing an IP protocol number.
/// Used in IPv4 headers (Protocol field) and IPv6 headers (Next Header field).
///
/// This type provides named constants for well-known protocols and implements
/// `Display` to show human-readable protocol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout, Serialize, Deserialize)]
#[repr(transparent)]
pub struct IpProto(pub u8);

impl Default for IpProto {
    fn default() -> Self {
        IpProto::ANY
    }
}

impl IpProto {
    /// Check if this protocol number is a known/valid protocol
    ///
    /// Returns `true` if this protocol number corresponds to a known protocol,
    /// `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_strata::packet::protocol::IpProto;
    ///
    /// assert!(IpProto::TCP.is_valid());
    /// assert!(IpProto::UDP.is_valid());
    /// assert!(!IpProto::from(200).is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        to_string_literal(*self).is_some()
    }

    pub const IPV6_HOPOPT: IpProto = IpProto(0); // IPv6 Hop-by-hop options
    pub const ICMP: IpProto = IpProto(1); // Internet Control Message Protocol
    pub const IGMP: IpProto = IpProto(2); // Internet Group Management
    pub const GGP: IpProto = IpProto(3); // gateway-gateway protocol
    pub const IP_ENCAP: IpProto = IpProto(4); // IP encapsulated in IP (officially ``IP'')
    pub const ST: IpProto = IpProto(5); // ST datagram mode
    pub const TCP: IpProto = IpProto(6); // transmission control protocol
    pub const CBT: IpProto = IpProto(7); // core-based trees
    pub const EGP: IpProto = IpProto(8); // exterior gateway protocol
    pub const IGP: IpProto = IpProto(9); // any private interior gateway (Cisco)
    pub const BBN_RCC: IpProto = IpProto(10); // bbn-rcc-mon
    pub const NVP: IpProto = IpProto(11); // nvp
    pub const PUP: IpProto = IpProto(12); // PARC universal packet protocol
    pub const ARGUS: IpProto = IpProto(13); // argus
    pub const EMCON: IpProto = IpProto(14); // EMCON
    pub const XNET: IpProto = IpProto(15); // X-net debugger
    pub const CHAOS: IpProto = IpProto(16); // chaos
    pub const UDP: IpProto = IpProto(17); // user datagram protocol
    pub const MUX: IpProto = IpProto(18); // multiplexing
    pub const DCN_MEAS: IpProto = IpProto(19); // DCN measurement subsystems
    pub const HMP: IpProto = IpProto(20); // host monitoring protocol
    pub const PRM: IpProto = IpProto(21); // packet radio measurement
    pub const XNS_IDP: IpProto = IpProto(22); // Xerox NS IDP
    pub const TRUNK1: IpProto = IpProto(23); // Trunk-1
    pub const TRUNK2: IpProto = IpProto(24); // Trunk-2
    pub const LEAF1: IpProto = IpProto(25); // Leaf-1
    pub const LEAF2: IpProto = IpProto(26); // Leaf-2
    pub const RDP: IpProto = IpProto(27); // "reliable datagram" protocol
    pub const IRTP: IpProto = IpProto(28); // IRTP
    pub const ISO_TP4: IpProto = IpProto(29); // ISO Transport Protocol class 4 [RFC905]
    pub const NETBLT: IpProto = IpProto(30); // bulk data transfer protocol
    pub const MFE_NSP: IpProto = IpProto(31); // MFE network services protocol
    pub const MERIT_INP: IpProto = IpProto(32); // Merit inter nodal protocol
    pub const DCCP: IpProto = IpProto(33); // Datagram Congestion Control Prot. [RFC4340]
    pub const _3PC: IpProto = IpProto(34); // Third party connect protocol
    pub const IDPR: IpProto = IpProto(35); // Inter domain policy routing protocol
    pub const XTP: IpProto = IpProto(36); // Xpress Transfer Protocol
    pub const DDP: IpProto = IpProto(37); // Datagram Delivery Protocol
    pub const IDPR_CMTP: IpProto = IpProto(38); // IDPR Control Message Transport
    pub const TP_PP: IpProto = IpProto(39); // TP++ transport protocol
    pub const IL: IpProto = IpProto(40); // IL transport protocol
    pub const IPV6: IpProto = IpProto(41); // Internet Protocol, version 6
    pub const SDRP: IpProto = IpProto(42); // Source demand routing protocol
    pub const IPV6_ROUTE: IpProto = IpProto(43); // Routing Header for IPv6
    pub const IPV6_FRAG: IpProto = IpProto(44); // Fragment Header for IPv6
    pub const IDRP: IpProto = IpProto(45); // Inter-Domain Routing Protocol
    pub const RSVP: IpProto = IpProto(46); // Reservation Protocol
    pub const GRE: IpProto = IpProto(47); // General Routing Encapsulation
    pub const BNA: IpProto = IpProto(49); // Burroughs Network Architecture
    pub const ESP: IpProto = IpProto(50); // Encapsulating Security Payload RFC 4303
    pub const AH: IpProto = IpProto(51); // Authentication Header RFC 4302
    pub const I_NLSP: IpProto = IpProto(52); // Integrated Net Layer Security Protocol TUBA
    pub const SWIPE: IpProto = IpProto(53); // SwIPe IP with Encryption
    pub const NARP: IpProto = IpProto(54); // NBMA Address Resolution Protocol RFC 1735
    pub const MOBILE: IpProto = IpProto(55); // IP Mobility (Min Encap) RFC 2004
    pub const TLSP: IpProto = IpProto(56); // Transport Layer Security Protocol (using Kryptonet key management)
    pub const SKIP: IpProto = IpProto(57); // Simple Key-Management for Internet Protocol RFC 2356
    pub const ICMP6: IpProto = IpProto(58); // ICMP for IPv6 RFC 4443, RFC 4884 (alias)
    pub const IPV6_ICMP: IpProto = IpProto(58); // ICMP for IPv6 RFC 4443, RFC 4884
    pub const IPV6_NONXT: IpProto = IpProto(59); // No Next Header for IPv6 RFC 8200
    pub const IPV6_OPTS: IpProto = IpProto(60); // Destination Options for IPv6 RFC 8200
    pub const CFTP: IpProto = IpProto(62); // CFTP
    pub const SAT_EXPAK: IpProto = IpProto(64); // SATNET and Backroom EXPAK
    pub const KRYPTOLAN: IpProto = IpProto(65); // Kryptolan
    pub const RVD: IpProto = IpProto(66); // MIT Remote Virtual Disk Protocol
    pub const IPPC: IpProto = IpProto(67); // Internet Pluribus Packet Core
    pub const SAT_MON: IpProto = IpProto(69); // SATNET Monitoring
    pub const VISA: IpProto = IpProto(70); // VISA Protocol
    pub const IPCU: IpProto = IpProto(71); // Internet Packet Core Utility
    pub const CPNX: IpProto = IpProto(72); // Computer Protocol Network Executive
    pub const CPHB: IpProto = IpProto(73); // Computer Protocol Heart Beat
    pub const WSN: IpProto = IpProto(74); // Wang Span Network
    pub const PVP: IpProto = IpProto(75); // Packet Video Protocol
    pub const BR_SAT_MON: IpProto = IpProto(76); // Backroom SATNET Monitoring
    pub const SUN_ND: IpProto = IpProto(77); // SUN ND PROTOCOL-Temporary
    pub const WB_MON: IpProto = IpProto(78); // WIDEBAND Monitoring
    pub const WB_EXPAK: IpProto = IpProto(79); // WIDEBAND EXPAK
    pub const ISO_IP: IpProto = IpProto(80); // International Organization for Standardization Internet Protocol
    pub const VMTP: IpProto = IpProto(81); // Versatile Message Transaction Protocol RFC 1045
    pub const SECURE_VMTP: IpProto = IpProto(82); // Secure Versatile Message Transaction Protocol RFC 1045
    pub const VINES: IpProto = IpProto(83); // VINES
    pub const IPTM: IpProto = IpProto(84); // Internet Protocol Traffic Manager (same as TTP)
    pub const NSFNET_IGP: IpProto = IpProto(85); // NSFNET-IGP
    pub const DGP: IpProto = IpProto(86); // Dissimilar Gateway Protocol
    pub const TCF: IpProto = IpProto(87); // TCF
    pub const EIGRP: IpProto = IpProto(88); // EIGRP
    pub const OSPF: IpProto = IpProto(89); // Open Shortest Path First RFC 1583
    pub const SPRITE_RPC: IpProto = IpProto(90); // Sprite RPC Protocol
    pub const LARP: IpProto = IpProto(91); // Locus Address Resolution Protocol
    pub const MTP: IpProto = IpProto(92); // Multicast Transport Protocol
    pub const AX_25: IpProto = IpProto(93); // AX.25
    pub const OS: IpProto = IpProto(94); // KA9Q NOS compatible IP over IP tunneling
    pub const MICP: IpProto = IpProto(95); // Mobile Internetworking Control Protocol
    pub const SCC_SP: IpProto = IpProto(96); // Semaphore Communications Sec. Pro
    pub const ETHERIP: IpProto = IpProto(97); // Ethernet-within-IP Encapsulation RFC 3378
    pub const ENCAP: IpProto = IpProto(98); // Encapsulation Header RFC 1241
    pub const GMTP: IpProto = IpProto(100); // GMTP
    pub const IFMP: IpProto = IpProto(101); // Ipsilon Flow Management Protocol
    pub const PNNI: IpProto = IpProto(102); // PNNI over IP
    pub const PIM: IpProto = IpProto(103); // Protocol Independent Multicast
    pub const ARIS: IpProto = IpProto(104); // IBM's ARIS (Aggregate Route IP Switching) Protocol
    pub const SCPS: IpProto = IpProto(105); // SCPS (Space Communications Protocol Standards) SCPS-TP[2]
    pub const QNX: IpProto = IpProto(106); // QNX
    pub const AN: IpProto = IpProto(107); // Active Networks
    pub const IPCOMP: IpProto = IpProto(108); // IP Payload Compression Protocol RFC 3173
    pub const SNP: IpProto = IpProto(109); // Sitara Networks Protocol
    pub const COMPAQ_PEER: IpProto = IpProto(110); // Compaq Peer Protocol
    pub const IPX_IN_IP: IpProto = IpProto(111); // IPX in IP
    pub const VRRP: IpProto = IpProto(112); // Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned) VRRP:RFC 3768
    pub const PGM: IpProto = IpProto(113); // PGM Reliable Transport Protocol RFC 3208
    pub const L2TP: IpProto = IpProto(115); // Layer Two Tunneling Protocol Version 3 RFC 3931
    pub const DDX: IpProto = IpProto(116); // D-II Data Exchange (DDX)
    pub const IATP: IpProto = IpProto(117); // Interactive Agent Transfer Protocol
    pub const STP: IpProto = IpProto(118); // Schedule Transfer Protocol
    pub const SRP: IpProto = IpProto(119); // SpectraLink Radio Protocol
    pub const UTI: IpProto = IpProto(120); // Universal Transport Interface Protocol
    pub const SMP: IpProto = IpProto(121); // Simple Message Protocol
    pub const SM: IpProto = IpProto(122); // Simple Multicast Protocol draft-perlman-simple-multicast-03
    pub const PTP: IpProto = IpProto(123); // Performance Transparency Protocol
    pub const IS_IS: IpProto = IpProto(124); // Intermediate System to Intermediate System (IS-IS) Protocol over IPv4 RFC 1142 and RFC 1195
    pub const FIRE: IpProto = IpProto(125); // Flexible Intra-AS Routing Environment
    pub const CRTP: IpProto = IpProto(126); // Combat Radio Transport Protocol
    pub const CRUDP: IpProto = IpProto(127); // Combat Radio User Datagram
    pub const SSCOPMCE: IpProto = IpProto(128); // Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment ITU-T Q.2111 (1999)
    pub const IPLT: IpProto = IpProto(129); // IPLT
    pub const SPS: IpProto = IpProto(130); // Secure Packet Shield
    pub const PIPE: IpProto = IpProto(131); // Private IP Encapsulation within IP Expired I-D draft-petri-mobileip-pipe-00.txt
    pub const SCTP: IpProto = IpProto(132); // Stream Control Transmission Protocol RFC 4960
    pub const FC: IpProto = IpProto(133); // Fibre Channel
    pub const RSVP_E2E: IpProto = IpProto(134); // Reservation Protocol (RSVP) End-to-End Ignore RFC 3175
    pub const IPV6_MOBILITY: IpProto = IpProto(135); // Mobility Extension Header for IPv6 RFC 6275
    pub const UDPLITE: IpProto = IpProto(136); // Lightweight User Datagram Protocol RFC 3828
    pub const MPLS_IN_IP: IpProto = IpProto(137); // Multiprotocol Label Switching Encapsulated in IP RFC 4023, RFC 5332
    pub const MANET: IpProto = IpProto(138); // MANET Protocols RFC 5498
    pub const HIP: IpProto = IpProto(139); // Host Identity Protocol RFC 5201
    pub const SHIM6: IpProto = IpProto(140); // Site Multihoming by IPv6 Intermediation RFC 5533
    pub const WESP: IpProto = IpProto(141); // Wrapped Encapsulating Security Payload RFC 5840
    pub const ROHC: IpProto = IpProto(142); // Robust Header Compression RFC 5856
    pub const ANY: IpProto = IpProto(255); // Raw/ANY IP packets
}

/// Returns the string literal name for a known IP protocol, or None for unknown protocols
fn to_string_literal(proto: IpProto) -> Option<&'static str> {
    let name = match proto {
        IpProto::IPV6_HOPOPT => "ipv6-hopopt",
        IpProto::ICMP => "icmp",
        IpProto::IGMP => "igmp",
        IpProto::GGP => "ggp",
        IpProto::IP_ENCAP => "ip-encap",
        IpProto::ST => "st",
        IpProto::TCP => "tcp",
        IpProto::CBT => "cbt",
        IpProto::EGP => "egp",
        IpProto::IGP => "igp",
        IpProto::BBN_RCC => "bbn-rcc",
        IpProto::NVP => "nvp",
        IpProto::PUP => "pup",
        IpProto::ARGUS => "argus",
        IpProto::EMCON => "emcon",
        IpProto::XNET => "xnet",
        IpProto::CHAOS => "chaos",
        IpProto::UDP => "udp",
        IpProto::MUX => "mux",
        IpProto::DCN_MEAS => "dcn-meas",
        IpProto::HMP => "hmp",
        IpProto::PRM => "prm",
        IpProto::XNS_IDP => "xns-idp",
        IpProto::TRUNK1 => "trunk1",
        IpProto::TRUNK2 => "trunk2",
        IpProto::LEAF1 => "leaf1",
        IpProto::LEAF2 => "leaf2",
        IpProto::RDP => "rdp",
        IpProto::IRTP => "irtp",
        IpProto::ISO_TP4 => "iso-tp4",
        IpProto::NETBLT => "netblt",
        IpProto::MFE_NSP => "mfe-nsp",
        IpProto::MERIT_INP => "merit-inp",
        IpProto::DCCP => "dccp",
        IpProto::_3PC => "3pc",
        IpProto::IDPR => "idpr",
        IpProto::XTP => "xtp",
        IpProto::DDP => "ddp",
        IpProto::IDPR_CMTP => "idpr-cmtp",
        IpProto::TP_PP => "tp-pp",
        IpProto::IL => "il",
        IpProto::IPV6 => "ipv6",
        IpProto::SDRP => "sdrp",
        IpProto::IPV6_ROUTE => "ipv6-route",
        IpProto::IPV6_FRAG => "ipv6-frag",
        IpProto::IDRP => "idrp",
        IpProto::RSVP => "rsvp",
        IpProto::GRE => "gre",
        IpProto::BNA => "bna",
        IpProto::ESP => "esp",
        IpProto::AH => "ah",
        IpProto::I_NLSP => "i-nlsp",
        IpProto::SWIPE => "swipe",
        IpProto::NARP => "narp",
        IpProto::MOBILE => "mobile",
        IpProto::TLSP => "tlsp",
        IpProto::SKIP => "skip",
        IpProto::IPV6_ICMP => "icmp6",
        IpProto::IPV6_NONXT => "ipv6-nonxt",
        IpProto::IPV6_OPTS => "ipv6-opts",
        IpProto::CFTP => "cftp",
        IpProto::SAT_EXPAK => "sat-expak",
        IpProto::KRYPTOLAN => "kryptolan",
        IpProto::RVD => "rvd",
        IpProto::IPPC => "ippc",
        IpProto::SAT_MON => "sat-mon",
        IpProto::VISA => "visa",
        IpProto::IPCU => "ipcu",
        IpProto::CPNX => "cpnx",
        IpProto::CPHB => "cphb",
        IpProto::WSN => "wsn",
        IpProto::PVP => "pvp",
        IpProto::BR_SAT_MON => "br-sat-mon",
        IpProto::SUN_ND => "sun-nd",
        IpProto::WB_MON => "wb-mon",
        IpProto::WB_EXPAK => "wb-expak",
        IpProto::ISO_IP => "iso-ip",
        IpProto::VMTP => "vmtp",
        IpProto::SECURE_VMTP => "secure-vmtp",
        IpProto::VINES => "vines",
        IpProto::IPTM => "iptm", // same value as TTP
        IpProto::NSFNET_IGP => "nsfnet-igp",
        IpProto::DGP => "dgp",
        IpProto::TCF => "tcf",
        IpProto::EIGRP => "eigrp",
        IpProto::OSPF => "ospf",
        IpProto::SPRITE_RPC => "sprite-rpc",
        IpProto::LARP => "larp",
        IpProto::MTP => "mtp",
        IpProto::AX_25 => "ax-25",
        IpProto::OS => "os",
        IpProto::MICP => "micp",
        IpProto::SCC_SP => "scc-sp",
        IpProto::ETHERIP => "etherip",
        IpProto::ENCAP => "encap",
        IpProto::GMTP => "gmtp",
        IpProto::IFMP => "ifmp",
        IpProto::PNNI => "pnni",
        IpProto::PIM => "pim",
        IpProto::ARIS => "aris",
        IpProto::SCPS => "scps",
        IpProto::QNX => "qnx",
        IpProto::AN => "an",
        IpProto::IPCOMP => "ipcomp",
        IpProto::SNP => "snp",
        IpProto::COMPAQ_PEER => "compaq-peer",
        IpProto::IPX_IN_IP => "ipx-in-ip",
        IpProto::VRRP => "vrrp",
        IpProto::PGM => "pgm",
        IpProto::L2TP => "l2tp",
        IpProto::DDX => "ddx",
        IpProto::IATP => "iatp",
        IpProto::STP => "stp",
        IpProto::SRP => "srp",
        IpProto::UTI => "uti",
        IpProto::SMP => "smp",
        IpProto::SM => "sm",
        IpProto::PTP => "ptp",
        IpProto::IS_IS => "is-is",
        IpProto::FIRE => "fire",
        IpProto::CRTP => "crtp",
        IpProto::CRUDP => "crudp",
        IpProto::SSCOPMCE => "sscopmce",
        IpProto::IPLT => "iplt",
        IpProto::SPS => "sps",
        IpProto::PIPE => "pipe",
        IpProto::SCTP => "sctp",
        IpProto::FC => "fc",
        IpProto::RSVP_E2E => "rsvp-e2e",
        IpProto::IPV6_MOBILITY => "ipv6-mobility",
        IpProto::UDPLITE => "udplite",
        IpProto::MPLS_IN_IP => "mpls-in-ip",
        IpProto::MANET => "manet",
        IpProto::HIP => "hip",
        IpProto::SHIM6 => "shim6",
        IpProto::WESP => "wesp",
        IpProto::ROHC => "rohc",
        IpProto::ANY => "any",
        _ => return None,
    };
    Some(name)
}

impl Display for IpProto {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match to_string_literal(*self) {
            Some(name) => write!(f, "{}", name),
            None => write!(f, "0x{:04x}", self.0),
        }
    }
}

impl From<u8> for IpProto {
    fn from(value: u8) -> Self {
        IpProto(value)
    }
}

impl From<IpProto> for u8 {
    fn from(value: IpProto) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_constants() {
        assert_eq!(IpProto::TCP.0, 6);
        assert_eq!(IpProto::UDP.0, 17);
        assert_eq!(IpProto::ICMP.0, 1);
        assert_eq!(IpProto::IPV6.0, 41);
        assert_eq!(IpProto::IPV6_HOPOPT.0, 0);
        assert_eq!(IpProto::IPV6_ROUTE.0, 43);
        assert_eq!(IpProto::IPV6_FRAG.0, 44);
        assert_eq!(IpProto::IPV6_ICMP.0, 58);
        assert_eq!(IpProto::IPV6_NONXT.0, 59);
        assert_eq!(IpProto::IPV6_OPTS.0, 60);
        assert_eq!(IpProto::ANY.0, 255);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", IpProto::TCP), "tcp");
        assert_eq!(format!("{}", IpProto::UDP), "udp");
        assert_eq!(format!("{}", IpProto::ICMP), "icmp");
        assert_eq!(format!("{}", IpProto::IPV6_ICMP), "icmp6");
        assert_eq!(format!("{}", IpProto::IPV6_ROUTE), "ipv6-route");
        assert_eq!(format!("{}", IpProto::IPV6_FRAG), "ipv6-frag");
        assert_eq!(format!("{}", IpProto::IPV6_OPTS), "ipv6-opts");
        assert_eq!(format!("{}", IpProto::IPV6_NONXT), "ipv6-nonxt");
        assert_eq!(format!("{}", IpProto::_3PC), "3pc");
        assert_eq!(format!("{}", IpProto::ANY), "any");
    }

    #[test]
    fn test_protocol_display_unknown() {
        let unknown = IpProto(200);
        assert_eq!(format!("{}", unknown), "0x00c8");
    }

    #[test]
    fn test_protocol_from_u8() {
        let proto = IpProto::from(6);
        assert_eq!(proto, IpProto::TCP);

        let proto = IpProto::from(17);
        assert_eq!(proto, IpProto::UDP);
    }

    #[test]
    fn test_protocol_into_u8() {
        let value: u8 = IpProto::TCP.into();
        assert_eq!(value, 6);

        let value: u8 = IpProto::UDP.into();
        assert_eq!(value, 17);
    }

    #[test]
    fn test_protocol_equality() {
        assert_eq!(IpProto::TCP, IpProto::TCP);
        assert_ne!(IpProto::TCP, IpProto::UDP);
        assert_eq!(IpProto::from(6), IpProto::TCP);
    }

    #[test]
    fn test_protocol_is_valid() {
        // Known protocols should be valid
        assert!(IpProto::TCP.is_valid());
        assert!(IpProto::UDP.is_valid());
        assert!(IpProto::ICMP.is_valid());
        assert!(IpProto::IPV6.is_valid());
        assert!(IpProto::IPV6_HOPOPT.is_valid());
        assert!(IpProto::IPV6_ROUTE.is_valid());
        assert!(IpProto::IPV6_FRAG.is_valid());
        assert!(IpProto::ANY.is_valid());

        // Unknown protocols should be invalid
        assert!(!IpProto::from(200).is_valid());
        assert!(!IpProto::from(150).is_valid());
        assert!(!IpProto::from(48).is_valid()); // Gap in protocol numbers
        assert!(!IpProto::from(61).is_valid()); // Gap in protocol numbers
        assert!(!IpProto::from(254).is_valid());
    }
}
