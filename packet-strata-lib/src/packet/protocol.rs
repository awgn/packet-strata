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
//! assert_eq!(format!("{}", IpProto::IPV6_ICMP), "ipv6-icmp");
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

use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

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
        WCCP = 0x883E;
        MPLS_UC = 0x8847;
        MPLS_MC = 0x8848;
        ATMMPOA = 0x884c;
        PPP_DISC = 0x8863;
        PPP_SES = 0x8864;
        LINK_CTL = 0x886c;
        ATMFATE = 0x8884;
        PAE = 0x888E;
        AOE = 0x88A2;
        VLAN_8021AD = 0x88A8;
        IEEE_802_EX1 = 0x88B5;
        TIPC = 0x88CA;
        VLAN_8021AH = 0x88E7;
        MVRP = 0x88F5;
        IEEE_1588 = 0x88F7;
        PRP = 0x88FB;
        FCOE = 0x8906;
        TDLS = 0x890D;
        FIP = 0x8914;
        IEEE_80221 = 0x8917;
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
        assert_eq!(format!("{}", IpProto::IPV6_ICMP), "ipv6-icmp");
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
        assert_eq!(format!("{}", unknown), "0xc8");
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
