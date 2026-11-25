//! Ethernet EtherTypes and IANA IP Protocol Numbers
//!
//! This module defines IEEE 802.3 / Linux SLL protocol identifiers ([`EtherProto`]) and IANA IP
//! protocol numbers ([`IpProto`]) used in Ethernet, SLL, IPv4 (`Protocol`), and IPv6 (`Next Header`)
//! headers, along with zero-allocation symbolic `kebab-case` formatting ([`ProtoName`]) and
//! [`std::str::FromStr`] parsing.
//!
//! # Examples
//!
//! ```
//! use packet_strata::packet::protocol::{EtherProto, IpProto};
//!
//! // Common protocols
//! let tcp = IpProto::TCP;
//! let udp = IpProto::UDP;
//!
//! // Zero-allocation static str & Display
//! assert_eq!(tcp.as_str(), Some("tcp"));
//! assert_eq!(format!("{}", udp), "udp");
//! assert_eq!(format!("{}", IpProto::IPV6_ICMP), "ipv6-icmp");
//! assert_eq!(EtherProto::PROFINET.as_str(), Some("profinet"));
//! assert_eq!(EtherProto::IEEE_802_3.as_str(), Some("ieee-802-3"));
//!
//! // Parse from symbolic name, alias, hex, or decimal
//! assert_eq!("tcp".parse::<IpProto>().unwrap(), IpProto::TCP);
//! assert_eq!("icmp6".parse::<IpProto>().unwrap(), IpProto::IPV6_ICMP);
//! assert_eq!("6".parse::<IpProto>().unwrap(), IpProto::TCP);
//! assert_eq!("0x0806".parse::<EtherProto>().unwrap(), EtherProto::ARP);
//! ```

use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use smol_str::SmolStr;
use thiserror::Error;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

/// Error returned when parsing an [`IpProto`] or [`EtherProto`] from a string fails.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown protocol: {0}")]
pub struct ParseProtoError(pub SmolStr);

/// Zero-allocation, `Copy` symbolic representation of an [`IpProto`] or [`EtherProto`].
///
/// Holds either a `'static` `kebab-case` protocol name (e.g. `"tcp"`, `"ipv6-icmp"`, `"arp"`,
/// `"ieee-802-3"`) or a stack-formatted lowercase hexadecimal fallback (`"0xc8"`, `"0x9999"`).
#[derive(Clone, Copy)]
pub enum ProtoName {
    Static(&'static str),
    Hex { buf: [u8; 6], len: u8 },
}

#[inline(always)]
const fn hex_digit(nibble: u8) -> u8 {
    let n = nibble & 0x0f;
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

impl ProtoName {
    /// Empty static protocol name (`""`), useful for absent L4 protocols on pure Layer-2 flows.
    pub const EMPTY: Self = Self::Static("");

    /// Wraps a `'static` protocol name with zero allocation.
    #[inline(always)]
    pub const fn from_static(s: &'static str) -> Self {
        Self::Static(s)
    }

    /// Formats an unassigned `u8` protocol number as lowercase `"0x..."` on the stack (`"0x0".."0xff"`).
    #[inline(always)]
    pub const fn from_hex_u8(val: u8) -> Self {
        if val < 0x10 {
            Self::Hex {
                buf: [b'0', b'x', hex_digit(val), 0, 0, 0],
                len: 3,
            }
        } else {
            Self::Hex {
                buf: [b'0', b'x', hex_digit(val >> 4), hex_digit(val), 0, 0],
                len: 4,
            }
        }
    }

    /// Formats an unmapped `u16` EtherType as 4-digit lowercase `"0xXXXX"` on the stack.
    #[inline(always)]
    pub const fn from_hex_u16(val: u16) -> Self {
        Self::Hex {
            buf: [
                b'0',
                b'x',
                hex_digit((val >> 12) as u8),
                hex_digit((val >> 8) as u8),
                hex_digit((val >> 4) as u8),
                hex_digit(val as u8),
            ],
            len: 6,
        }
    }

    /// Returns the string slice representation of this protocol name.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Static(s) => s,
            Self::Hex { buf, len } => {
                let slice = buf.get(..usize::from(*len)).unwrap_or(&[]);
                std::str::from_utf8(slice).unwrap_or("")
            }
        }
    }
}

impl Default for ProtoName {
    #[inline(always)]
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Deref for ProtoName {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ProtoName {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for ProtoName {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for ProtoName {}

impl PartialEq<str> for ProtoName {
    #[inline(always)]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ProtoName {
    #[inline(always)]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Hash for ProtoName {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl fmt::Debug for ProtoName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for ProtoName {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for ProtoName {
    #[inline(always)]
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

crate::protocol_constants! {
    EtherProto, U16<BigEndian>, u16:
        LOOP = 0x0060;
        PUP = 0x0200;
        PUPAT = 0x0201;
        #[default] IPV4 = 0x0800;
        X25 = 0x0805;
        ARP = 0x0806;
        BPQ = 0x08FF;
        IEEEPUP = 0x0a00;
        IEEEPUPAT = 0x0a01;
        BATMAN = 0x4305;
        DEC = 0x6000;
        DNA_DL = 0x6001;
        DNA_RC = 0x6002;
        DNA_RT = 0x6003;
        LAT = 0x6004;
        DIAG = 0x6005;
        CUST = 0x6006;
        SCA = 0x6007;
        TEB = 0x6558;
        RARP = 0x8035;
        ATALK = 0x809B;
        AARP = 0x80F3;
        VLAN_8021Q = 0x8100;
        IPX = 0x8137;
        IPV6 = 0x86DD;
        PAUSE = 0x8808;
        SLOW = 0x8809;
        PPP = 0x880B;
        WCCP = 0x883E;
        MPLS_UC = 0x8847;
        MPLS_MC = 0x8848;
        ATMMPOA = 0x884c;
        PPP_DISC = 0x8863;
        PPP_SES = 0x8864;
        LINK_CTL = 0x886c;
        ATMFATE = 0x8884;
        PAE = 0x888E;
        PROFINET = 0x8892;
        AOE = 0x88A2;
        ETHERCAT = 0x88A4;
        VLAN_8021AD = 0x88A8;
        POWERLINK = 0x88AB;
        IEEE_802_EX1 = 0x88B5;
        GOOSE = 0x88B8;
        SV = 0x88BA;
        TIPC = 0x88CA;
        LLDP = 0x88CC;
        MRP = 0x88E3;
        MACSEC = 0x88E5;
        VLAN_8021AH = 0x88E7;
        MVRP = 0x88F5;
        IEEE_1588 = 0x88F7;
        PRP = 0x88FB;
        CFM = 0x8902;
        FCOE = 0x8906;
        TDLS = 0x890D;
        FIP = 0x8914;
        ROCE = 0x8915;
        IEEE_80221 = 0x8917;
        HSR = 0x892F;
        LOOPBACK = 0x9000;
        QINQ1 = 0x9100;
        QINQ2 = 0x9200;
        QINQ3 = 0x9300;
        EDSA = 0xDADA;
        AF_IUCV = 0xFBFB;
        IEEE_802_3_MIN = 0x0600;
        IEEE_802_3 = 0x0001;
        AX25 = 0x0002;
        ALL = 0x0003;
        IEEE_802_2 = 0x0004;
        SNAP = 0x0005;
        DDCMP = 0x0006;
        WAN_PPP = 0x0007;
        PPP_MP = 0x0008;
        LOCALTALK = 0x0009;
        CAN = 0x000C;
        CANFD = 0x000D;
        PPPTALK = 0x0010;
        TR_802_2 = 0x0011;
        MOBITEX = 0x0015;
        CONTROL = 0x0016;
        IRDA = 0x0017;
        ECONET = 0x0018;
        HDLC = 0x0019;
        ARCNET = 0x001A;
        DSA = 0x001B;
        TRAILER = 0x001C;
        PHONET = 0x00F5;
        IEEE802154 = 0x00F6;
        CAIF = 0x00F7;
}

impl EtherProto {
    #[inline]
    fn parse_alias(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("ieee-802.3") || s.eq_ignore_ascii_case("802.3") {
            Some(Self::IEEE_802_3)
        } else if s.eq_ignore_ascii_case("vlan") {
            Some(Self::VLAN_8021Q)
        } else if s.eq_ignore_ascii_case("qinq") {
            Some(Self::VLAN_8021AD)
        } else if s.eq_ignore_ascii_case("mpls") {
            Some(Self::MPLS_UC)
        } else if s.eq_ignore_ascii_case("pppoe-discovery") {
            Some(Self::PPP_DISC)
        } else if s.eq_ignore_ascii_case("pppoe-session") {
            Some(Self::PPP_SES)
        } else if s.eq_ignore_ascii_case("eapol") {
            Some(Self::PAE)
        } else if s.eq_ignore_ascii_case("ptp") {
            Some(Self::IEEE_1588)
        } else {
            None
        }
    }
}

crate::protocol_constants! {
    IpProto, u8, u8:
        IPV6_HOPOPT = 0;
        ICMP = 1;
        IGMP = 2;
        GGP = 3;
        IP_ENCAP = 4;
        ST = 5;
        TCP = 6;
        CBT = 7;
        EGP = 8;
        IGP = 9;
        BBN_RCC = 10;
        NVP = 11;
        PUP = 12;
        ARGUS = 13;
        EMCON = 14;
        XNET = 15;
        CHAOS = 16;
        UDP = 17;
        MUX = 18;
        DCN_MEAS = 19;
        HMP = 20;
        PRM = 21;
        XNS_IDP = 22;
        TRUNK1 = 23;
        TRUNK2 = 24;
        LEAF1 = 25;
        LEAF2 = 26;
        RDP = 27;
        IRTP = 28;
        ISO_TP4 = 29;
        NETBLT = 30;
        MFE_NSP = 31;
        MERIT_INP = 32;
        DCCP = 33;
        _3PC = 34;
        IDPR = 35;
        XTP = 36;
        DDP = 37;
        IDPR_CMTP = 38;
        TP_PP = 39;
        IL = 40;
        IPV6 = 41;
        SDRP = 42;
        IPV6_ROUTE = 43;
        IPV6_FRAG = 44;
        IDRP = 45;
        RSVP = 46;
        GRE = 47;
        BNA = 49;
        ESP = 50;
        AH = 51;
        I_NLSP = 52;
        SWIPE = 53;
        NARP = 54;
        MOBILE = 55;
        TLSP = 56;
        SKIP = 57;
        IPV6_ICMP = 58;
        IPV6_NONXT = 59;
        IPV6_OPTS = 60;
        CFTP = 62;
        SAT_EXPAK = 64;
        KRYPTOLAN = 65;
        RVD = 66;
        IPPC = 67;
        SAT_MON = 69;
        VISA = 70;
        IPCU = 71;
        CPNX = 72;
        CPHB = 73;
        WSN = 74;
        PVP = 75;
        BR_SAT_MON = 76;
        SUN_ND = 77;
        WB_MON = 78;
        WB_EXPAK = 79;
        ISO_IP = 80;
        VMTP = 81;
        SECURE_VMTP = 82;
        VINES = 83;
        IPTM = 84;
        NSFNET_IGP = 85;
        DGP = 86;
        TCF = 87;
        EIGRP = 88;
        OSPF = 89;
        SPRITE_RPC = 90;
        LARP = 91;
        MTP = 92;
        AX_25 = 93;
        OS = 94;
        MICP = 95;
        SCC_SP = 96;
        ETHERIP = 97;
        ENCAP = 98;
        GMTP = 100;
        IFMP = 101;
        PNNI = 102;
        PIM = 103;
        ARIS = 104;
        SCPS = 105;
        QNX = 106;
        AN = 107;
        IPCOMP = 108;
        SNP = 109;
        COMPAQ_PEER = 110;
        IPX_IN_IP = 111;
        VRRP = 112;
        PGM = 113;
        L2TP = 115;
        DDX = 116;
        IATP = 117;
        STP = 118;
        SRP = 119;
        UTI = 120;
        SMP = 121;
        SM = 122;
        PTP = 123;
        IS_IS = 124;
        FIRE = 125;
        CRTP = 126;
        CRUDP = 127;
        SSCOPMCE = 128;
        IPLT = 129;
        SPS = 130;
        PIPE = 131;
        SCTP = 132;
        FC = 133;
        RSVP_E2E = 134;
        IPV6_MOBILITY = 135;
        UDPLITE = 136;
        MPLS_IN_IP = 137;
        MANET = 138;
        HIP = 139;
        SHIM6 = 140;
        WESP = 141;
        ROHC = 142;
        #[default] ANY = 255;
}

impl IpProto {
    #[inline]
    fn parse_alias(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("icmp6") || s.eq_ignore_ascii_case("icmpv6") {
            Some(Self::IPV6_ICMP)
        } else if s.eq_ignore_ascii_case("ipip") || s.eq_ignore_ascii_case("ip-in-ip") {
            Some(Self::IP_ENCAP)
        } else if s.eq_ignore_ascii_case("hopopt") {
            Some(Self::IPV6_HOPOPT)
        } else {
            None
        }
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
    fn test_protocol_display_and_as_str() {
        assert_eq!(IpProto::TCP.as_str(), Some("tcp"));
        assert_eq!(format!("{}", IpProto::TCP), "tcp");
        assert_eq!(format!("{}", IpProto::UDP), "udp");
        assert_eq!(format!("{}", IpProto::ICMP), "icmp");
        assert_eq!(format!("{}", IpProto::IPV6_ICMP), "ipv6-icmp");
        assert_eq!(format!("{}", IpProto::IPV6_ROUTE), "ipv6-route");
        assert_eq!(format!("{}", IpProto::IPV6_FRAG), "ipv6-frag");
        assert_eq!(format!("{}", IpProto::IPV6_OPTS), "ipv6-opts");
        assert_eq!(format!("{}", IpProto::IPV6_NONXT), "ipv6-nonxt");
        assert_eq!(format!("{}", IpProto::_3PC), "3pc");
        assert_eq!(format!("{}", IpProto::ANY), "any");

        assert_eq!(EtherProto::IPV4.as_str(), Some("ipv4"));
        assert_eq!(EtherProto::IPV6.as_str(), Some("ipv6"));
        assert_eq!(EtherProto::ARP.as_str(), Some("arp"));
        assert_eq!(EtherProto::IEEE_802_3.as_str(), Some("ieee-802-3"));
        assert_eq!(EtherProto::CAN.as_str(), Some("can"));
        assert_eq!(EtherProto::WAN_PPP.as_str(), Some("wan-ppp"));
        assert_eq!(EtherProto::PROFINET.as_str(), Some("profinet"));
        assert_eq!(EtherProto::ETHERCAT.as_str(), Some("ethercat"));
        assert_eq!(EtherProto::POWERLINK.as_str(), Some("powerlink"));
        assert_eq!(EtherProto::LLDP.as_str(), Some("lldp"));
        assert_eq!(EtherProto::GOOSE.as_str(), Some("goose"));
        assert_eq!(EtherProto::from(0x9999u16).as_str(), None);
        assert_eq!(EtherProto::from(0x9999u16).proto_name(), "0x9999");
    }

    #[test]
    fn test_protocol_display_unknown() {
        let unknown = IpProto(200);
        assert_eq!(unknown.as_str(), None);
        assert_eq!(format!("{}", unknown), "0xc8");
        assert_eq!(IpProto(5).as_str(), Some("st"));
        assert_eq!(format!("{}", IpProto(48)), "0x30");
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!("tcp".parse::<IpProto>().unwrap(), IpProto::TCP);
        assert_eq!("TCP".parse::<IpProto>().unwrap(), IpProto::TCP);
        assert_eq!("ipv6-icmp".parse::<IpProto>().unwrap(), IpProto::IPV6_ICMP);
        assert_eq!("icmp6".parse::<IpProto>().unwrap(), IpProto::IPV6_ICMP);
        assert_eq!("icmpv6".parse::<IpProto>().unwrap(), IpProto::IPV6_ICMP);
        assert_eq!("ipip".parse::<IpProto>().unwrap(), IpProto::IP_ENCAP);
        assert_eq!("3pc".parse::<IpProto>().unwrap(), IpProto::_3PC);
        assert_eq!("6".parse::<IpProto>().unwrap(), IpProto::TCP);
        assert_eq!("0xc8".parse::<IpProto>().unwrap(), IpProto(200));
        assert!("not-a-proto".parse::<IpProto>().is_err());

        assert_eq!("ipv4".parse::<EtherProto>().unwrap(), EtherProto::IPV4);
        assert_eq!("ARP".parse::<EtherProto>().unwrap(), EtherProto::ARP);
        assert_eq!("profinet".parse::<EtherProto>().unwrap(), EtherProto::PROFINET);
        assert_eq!("ieee-802-3".parse::<EtherProto>().unwrap(), EtherProto::IEEE_802_3);
        assert_eq!("ieee-802.3".parse::<EtherProto>().unwrap(), EtherProto::IEEE_802_3);
        assert_eq!("vlan".parse::<EtherProto>().unwrap(), EtherProto::VLAN_8021Q);
        assert_eq!("2048".parse::<EtherProto>().unwrap(), EtherProto::IPV4);
        assert_eq!("0x9999".parse::<EtherProto>().unwrap(), EtherProto::from(0x9999u16));
        assert!("not-an-ethertype".parse::<EtherProto>().is_err());
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
        assert!(IpProto::TCP.is_valid());
        assert!(IpProto::UDP.is_valid());
        assert!(IpProto::ICMP.is_valid());
        assert!(IpProto::IPV6.is_valid());
        assert!(IpProto::IPV6_HOPOPT.is_valid());
        assert!(IpProto::IPV6_ROUTE.is_valid());
        assert!(IpProto::IPV6_FRAG.is_valid());
        assert!(IpProto::ANY.is_valid());
        assert!(EtherProto::CAN.is_valid());
        assert!(EtherProto::WAN_PPP.is_valid());
        assert!(EtherProto::IEEE_802_3.is_valid());

        assert!(!IpProto::from(200).is_valid());
        assert!(!IpProto::from(150).is_valid());
        assert!(!IpProto::from(48).is_valid());
        assert!(!IpProto::from(61).is_valid());
        assert!(!IpProto::from(254).is_valid());
    }

    #[cfg(feature = "strata_protocol_names")]
    #[test]
    fn test_strata_protocol_names_serde_json() {
        assert_eq!(serde_json::to_string(&IpProto::TCP).unwrap(), "\"tcp\"");
        assert_eq!(
            serde_json::to_string(&IpProto::IPV6_ICMP).unwrap(),
            "\"ipv6-icmp\""
        );
        assert_eq!(serde_json::to_string(&IpProto(200)).unwrap(), "\"0xc8\"");
        assert_eq!(
            serde_json::to_string(&EtherProto::IPV4).unwrap(),
            "\"ipv4\""
        );
        assert_eq!(
            serde_json::to_string(&EtherProto::PROFINET).unwrap(),
            "\"profinet\""
        );
        assert_eq!(
            serde_json::to_string(&EtherProto::IEEE_802_3).unwrap(),
            "\"ieee-802-3\""
        );
        assert_eq!(
            serde_json::to_string(&EtherProto::CAN).unwrap(),
            "\"can\""
        );
        assert_eq!(
            serde_json::to_string(&EtherProto::from(0x9999u16)).unwrap(),
            "\"0x9999\""
        );

        // Deserialize from symbolic string, alias, hex, and legacy integer
        assert_eq!(
            serde_json::from_str::<IpProto>("\"tcp\"").unwrap(),
            IpProto::TCP
        );
        assert_eq!(
            serde_json::from_str::<IpProto>("\"icmp6\"").unwrap(),
            IpProto::IPV6_ICMP
        );
        assert_eq!(serde_json::from_str::<IpProto>("6").unwrap(), IpProto::TCP);
        assert_eq!(
            serde_json::from_str::<IpProto>("\"0xc8\"").unwrap(),
            IpProto(200)
        );
        assert_eq!(
            serde_json::from_str::<EtherProto>("\"arp\"").unwrap(),
            EtherProto::ARP
        );
        assert_eq!(
            serde_json::from_str::<EtherProto>("2048").unwrap(),
            EtherProto::IPV4
        );
        assert_eq!(
            serde_json::from_str::<EtherProto>("\"ieee-802-3\"").unwrap(),
            EtherProto::IEEE_802_3
        );
    }
}
