use std::fmt::{self, Formatter};

use crate::packet::protocol::IpProto;
use crate::packet::PacketHeaderError;

// IPv6 Extension Header Types
pub const EXT_HOPBYHOP: u8 = 0; // Hop-by-Hop Options
pub const EXT_ROUTING: u8 = 43; // Routing
pub const EXT_FRAGMENT: u8 = 44; // Fragment
pub const EXT_DSTOPTS: u8 = 60; // Destination Options
pub const EXT_MOBILITY: u8 = 135; // Mobility
pub const EXT_AH: u8 = 51; // Authentication Header
pub const EXT_ESP: u8 = 50; // Encapsulating Security Payload

/// IPv6 Extension Header Element
#[derive(Debug, Clone)]
pub enum Ipv6ExtensionHeader<'a> {
    /// Hop-by-Hop Options Header
    HopByHop {
        next_header: IpProto,
        options: &'a [u8],
    },
    /// Routing Header
    Routing {
        next_header: IpProto,
        routing_type: u8,
        segments_left: u8,
        data: &'a [u8],
    },
    /// Fragment Header
    Fragment {
        next_header: IpProto,
        fragment_offset: u16,
        more_fragments: bool,
        identification: u32,
    },
    /// Destination Options Header
    DestinationOptions {
        next_header: IpProto,
        options: &'a [u8],
    },
    /// Mobility Header
    Mobility {
        next_header: IpProto,
        mh_type: u8,
        data: &'a [u8],
    },
    /// Authentication Header
    AuthenticationHeader {
        next_header: IpProto,
        spi: u32,
        sequence: u32,
        data: &'a [u8],
    },
    /// Unknown Extension Header
    Unknown {
        header_type: u8,
        next_header: IpProto,
        data: &'a [u8],
    },
}

impl<'a> Ipv6ExtensionHeader<'a> {
    /// Returns the next header type
    pub fn next_header(&self) -> IpProto {
        match self {
            Self::HopByHop { next_header, .. }
            | Self::Routing { next_header, .. }
            | Self::Fragment { next_header, .. }
            | Self::DestinationOptions { next_header, .. }
            | Self::Mobility { next_header, .. }
            | Self::AuthenticationHeader { next_header, .. }
            | Self::Unknown { next_header, .. } => *next_header,
        }
    }

    /// Returns the total length of this extension header in bytes
    pub fn header_len(&self) -> usize {
        match self {
            Self::Fragment { .. } => 8, // Fragment header is always 8 bytes
            Self::HopByHop { options, .. } | Self::DestinationOptions { options, .. } => {
                // Total = next_header(1) + hdr_ext_len(1) + options
                // options already represents the full data portion
                2 + options.len()
            }
            Self::Routing { data, .. } => {
                // Total = next_header(1) + hdr_ext_len(1) + routing_type(1) + segments_left(1) + data
                // data here is routing_data (after routing_type and segments_left)
                4 + data.len()
            }
            Self::Mobility { data, .. } => {
                // Total = next_header(1) + hdr_ext_len(1) + data
                // data includes mh_type and all remaining fields
                2 + data.len()
            }
            Self::AuthenticationHeader { data, .. } => {
                // Total = next_header(1) + payload_len(1) + reserved(2) + spi(4) + seq(4) + ICV
                12 + data.len()
            }
            Self::Unknown { data, .. } => {
                // Total = next_header(1) + hdr_ext_len(1) + data
                2 + data.len()
            }
        }
    }

    /// Returns true if this is a fragment header
    pub fn is_fragment(&self) -> bool {
        matches!(self, Self::Fragment { .. })
    }

    /// Returns true if this extension header type is recognized
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. })
    }
}

impl fmt::Display for Ipv6ExtensionHeader<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::HopByHop { .. } => write!(f, "HopByHop"),
            Self::Routing {
                routing_type,
                segments_left,
                ..
            } => {
                write!(f, "Routing(type={},segs={})", routing_type, segments_left)
            }
            Self::Fragment {
                fragment_offset,
                more_fragments,
                identification,
                ..
            } => {
                write!(
                    f,
                    "Fragment(off={},M={},id=0x{:x})",
                    fragment_offset,
                    if *more_fragments { 1 } else { 0 },
                    identification
                )
            }
            Self::DestinationOptions { .. } => write!(f, "DstOpts"),
            Self::Mobility { mh_type, .. } => write!(f, "Mobility(type={})", mh_type),
            Self::AuthenticationHeader { spi, sequence, .. } => {
                write!(f, "AH(spi=0x{:x},seq={})", spi, sequence)
            }
            Self::Unknown { header_type, .. } => write!(f, "UNK({})", header_type),
        }
    }
}

/// Iterator over IPv6 Extension Headers
pub struct Ipv6ExtensionHeadersIter<'a> {
    cursor: &'a [u8],
    next_header: IpProto,
    finished: bool,
}

impl<'a> Ipv6ExtensionHeadersIter<'a> {
    /// Create a new iterator starting with the given next_header and buffer
    pub fn new(next_header: IpProto, data: &'a [u8]) -> Self {
        Self {
            cursor: data,
            next_header,
            finished: false,
        }
    }

    /// Check if the current next_header is an extension header
    fn is_extension_header(next_header: IpProto) -> bool {
        matches!(
            next_header.0,
            EXT_HOPBYHOP
                | EXT_ROUTING
                | EXT_FRAGMENT
                | EXT_DSTOPTS
                | EXT_MOBILITY
                | EXT_AH
                | EXT_ESP
        )
    }
}

impl<'a> Iterator for Ipv6ExtensionHeadersIter<'a> {
    type Item = Result<Ipv6ExtensionHeader<'a>, PacketHeaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Stop if already finished or if next header is not an extension header
        if self.finished || !Self::is_extension_header(self.next_header) {
            return None;
        }

        // Need at least 2 bytes for next_header and length
        if self.cursor.len() < 2 {
            self.finished = true;
            return Some(Err(PacketHeaderError::TooShort("IPv6ExtensionHeader")));
        }

        let header_type = self.next_header.0;
        let next_header = IpProto::from(self.cursor[0]);

        // Parse based on header type
        let result = match header_type {
            EXT_FRAGMENT => {
                // Fragment header is special - fixed 8 bytes
                if self.cursor.len() < 8 {
                    self.finished = true;
                    return Some(Err(PacketHeaderError::TooShort("FragmentHeader")));
                }

                // Fragment Header format (8 bytes):
                // 0: Next Header
                // 1: Reserved
                // 2-3: Fragment Offset (13 bits) + Res (2 bits) + M flag (1 bit)
                // 4-7: Identification
                let offset_flags = u16::from_be_bytes([self.cursor[2], self.cursor[3]]);
                let fragment_offset = (offset_flags >> 3) & 0x1FFF;
                let more_fragments = (offset_flags & 0x0001) != 0;
                let identification = u32::from_be_bytes([
                    self.cursor[4],
                    self.cursor[5],
                    self.cursor[6],
                    self.cursor[7],
                ]);

                self.cursor = &self.cursor[8..];
                self.next_header = next_header;

                Ok(Ipv6ExtensionHeader::Fragment {
                    next_header,
                    fragment_offset,
                    more_fragments,
                    identification,
                })
            }
            EXT_AH => {
                // Authentication Header
                // 0: Next Header
                // 1: Payload Len (in 4-byte units, minus 2)
                // 2-3: Reserved
                // 4-7: SPI
                // 8-11: Sequence Number
                // 12+: ICV (variable length)
                if self.cursor.len() < 12 {
                    self.finished = true;
                    return Some(Err(PacketHeaderError::TooShort("AuthenticationHeader")));
                }

                let payload_len = self.cursor[1] as usize;
                let total_len = (payload_len + 2) * 4; // Convert to bytes

                if self.cursor.len() < total_len {
                    self.finished = true;
                    return Some(Err(PacketHeaderError::TooShort("AuthenticationHeader")));
                }

                let spi = u32::from_be_bytes([
                    self.cursor[4],
                    self.cursor[5],
                    self.cursor[6],
                    self.cursor[7],
                ]);
                let sequence = u32::from_be_bytes([
                    self.cursor[8],
                    self.cursor[9],
                    self.cursor[10],
                    self.cursor[11],
                ]);
                let icv_data = if total_len > 12 {
                    &self.cursor[12..total_len]
                } else {
                    &[]
                };

                self.cursor = &self.cursor[total_len..];
                self.next_header = next_header;

                Ok(Ipv6ExtensionHeader::AuthenticationHeader {
                    next_header,
                    spi,
                    sequence,
                    data: icv_data,
                })
            }
            EXT_HOPBYHOP | EXT_ROUTING | EXT_DSTOPTS | EXT_MOBILITY => {
                // Standard extension header format:
                // 0: Next Header
                // 1: Hdr Ext Len (in 8-byte units, not including first 8 bytes)
                // 2+: Type-specific data
                let hdr_ext_len = self.cursor[1] as usize;
                let total_len = (hdr_ext_len + 1) * 8;

                if self.cursor.len() < total_len {
                    self.finished = true;
                    return Some(Err(PacketHeaderError::TooShort("IPv6ExtensionHeader")));
                }

                let data = &self.cursor[2..total_len];
                self.cursor = &self.cursor[total_len..];
                self.next_header = next_header;

                match header_type {
                    EXT_HOPBYHOP => Ok(Ipv6ExtensionHeader::HopByHop {
                        next_header,
                        options: data,
                    }),
                    EXT_DSTOPTS => Ok(Ipv6ExtensionHeader::DestinationOptions {
                        next_header,
                        options: data,
                    }),
                    EXT_ROUTING => {
                        // Routing header has additional fields
                        // 2: Routing Type
                        // 3: Segments Left
                        // 4+: Type-specific data
                        if data.len() < 2 {
                            return Some(Ok(Ipv6ExtensionHeader::Unknown {
                                header_type,
                                next_header,
                                data,
                            }));
                        }
                        let routing_type = data[0];
                        let segments_left = data[1];
                        let routing_data = if data.len() > 2 { &data[2..] } else { &[] };

                        Ok(Ipv6ExtensionHeader::Routing {
                            next_header,
                            routing_type,
                            segments_left,
                            data: routing_data,
                        })
                    }
                    EXT_MOBILITY => {
                        // Mobility header
                        // 2: MH Type
                        // 3: Reserved
                        // 4-5: Checksum
                        // 6+: Type-specific data
                        if data.is_empty() {
                            return Some(Ok(Ipv6ExtensionHeader::Unknown {
                                header_type,
                                next_header,
                                data,
                            }));
                        }
                        let mh_type = data[0];

                        Ok(Ipv6ExtensionHeader::Mobility {
                            next_header,
                            mh_type,
                            data,
                        })
                    }
                    _ => Ok(Ipv6ExtensionHeader::Unknown {
                        header_type,
                        next_header,
                        data,
                    }),
                }
            }
            _ => {
                // Unknown extension header - try to parse it generically
                let hdr_ext_len = self.cursor[1] as usize;
                let total_len = (hdr_ext_len + 1) * 8;

                if self.cursor.len() < total_len {
                    self.finished = true;
                    return Some(Err(PacketHeaderError::TooShort("IPv6ExtensionHeader")));
                }

                let data = &self.cursor[2..total_len];
                self.cursor = &self.cursor[total_len..];
                self.next_header = next_header;

                Ok(Ipv6ExtensionHeader::Unknown {
                    header_type,
                    next_header,
                    data,
                })
            }
        };

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_header() {
        // Fragment Header: Next=TCP(6), Reserved(0), Offset=185, M=1, ID=12345
        let data = [
            6, // Next Header: TCP
            0, // Reserved
            0x05, 0xC9, // Offset: 185 << 3 | 0 << 1 | 1 = 0x05C9
            0x00, 0x00, 0x30, 0x39, // Identification: 12345
        ];

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_FRAG, &data);
        let ext = iter.next().unwrap().unwrap();

        match ext {
            Ipv6ExtensionHeader::Fragment {
                next_header,
                fragment_offset,
                more_fragments,
                identification,
            } => {
                assert_eq!(next_header, IpProto::TCP);
                assert_eq!(fragment_offset, 185);
                assert!(more_fragments);
                assert_eq!(identification, 12345);
                assert_eq!(ext.header_len(), 8);
            }
            _ => panic!("Expected Fragment header"),
        }

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_hop_by_hop_header() {
        // Hop-by-Hop: Next=TCP(6), Len=0 (8 bytes total), Options(6 bytes)
        let mut data = vec![
            6, // Next Header: TCP
            0, // Hdr Ext Len: 0 (means 8 bytes total)
        ];
        // Add 6 bytes of options (e.g., PadN)
        data.extend_from_slice(&[1, 4, 0, 0, 0, 0]); // PadN: type=1, len=4, padding

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_HOPOPT, &data);
        let ext = iter.next().unwrap().unwrap();

        match ext {
            Ipv6ExtensionHeader::HopByHop {
                next_header,
                options,
            } => {
                assert_eq!(next_header, IpProto::TCP);
                assert_eq!(options.len(), 6);
                assert_eq!(ext.header_len(), 8); // 2 + 6 = 8
            }
            _ => panic!("Expected HopByHop header"),
        }
    }

    #[test]
    fn test_routing_header() {
        // Routing Header: Next=TCP(6), Len=2 (24 bytes total)
        let mut data = vec![
            6, // Next Header: TCP
            2, // Hdr Ext Len: 2 (3*8 = 24 bytes total)
            0, // Routing Type: 0 (deprecated Type 0)
            2, // Segments Left: 2
        ];
        // Add routing data (20 bytes to reach 24 total: 2 header + 2 fields + 20 data)
        data.extend_from_slice(&[0u8; 20]); // 20 bytes of data

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_ROUTE, &data);
        let ext = iter.next().unwrap().unwrap();

        match ext {
            Ipv6ExtensionHeader::Routing {
                next_header,
                routing_type,
                segments_left,
                data,
            } => {
                assert_eq!(next_header, IpProto::TCP);
                assert_eq!(routing_type, 0);
                assert_eq!(segments_left, 2);
                assert_eq!(data.len(), 20);
                assert_eq!(ext.header_len(), 24); // 4 + 20 = 24
            }
            _ => panic!("Expected Routing header"),
        }
    }

    #[test]
    fn test_destination_options_header() {
        // Destination Options: Next=TCP(6), Len=1 (16 bytes total)
        let mut data = vec![
            6, // Next Header: TCP
            1, // Hdr Ext Len: 1 (2*8 = 16 bytes total)
        ];
        data.extend_from_slice(&[0u8; 14]); // 14 bytes of options

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_OPTS, &data);
        let ext = iter.next().unwrap().unwrap();

        match ext {
            Ipv6ExtensionHeader::DestinationOptions {
                next_header,
                options,
            } => {
                assert_eq!(next_header, IpProto::TCP);
                assert_eq!(options.len(), 14);
                assert_eq!(ext.header_len(), 16); // 2 + 14 = 16
            }
            _ => panic!("Expected DestinationOptions header"),
        }
    }

    #[test]
    fn test_multiple_extension_headers() {
        let mut data = Vec::new();

        // First: Hop-by-Hop (Next=Routing)
        data.extend_from_slice(&[
            43, // Next Header: Routing
            0,  // Len: 0
            1, 4, 0, 0, 0, 0, // Options
        ]);

        // Second: Routing (Next=Fragment)
        data.extend_from_slice(&[
            44, // Next Header: Fragment
            0,  // Len: 0
            0,  // Routing Type
            0,  // Segments Left
            0, 0, 0, 0, // Routing data
        ]);

        // Third: Fragment (Next=TCP)
        data.extend_from_slice(&[
            6, // Next Header: TCP
            0, // Reserved
            0x00, 0x00, // Offset=0, M=0
            0x00, 0x00, 0x00, 0x01, // ID=1
        ]);

        let iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_HOPOPT, &data);
        let headers: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(headers.len(), 3);
        assert!(matches!(headers[0], Ipv6ExtensionHeader::HopByHop { .. }));
        assert!(matches!(headers[1], Ipv6ExtensionHeader::Routing { .. }));
        assert!(matches!(headers[2], Ipv6ExtensionHeader::Fragment { .. }));

        // Verify next_header chaining
        assert_eq!(headers[0].next_header(), IpProto::IPV6_ROUTE);
        assert_eq!(headers[1].next_header(), IpProto::IPV6_FRAG);
        assert_eq!(headers[2].next_header(), IpProto::TCP);
    }

    #[test]
    fn test_extension_header_stops_at_tcp() {
        let mut data = Vec::new();

        // Hop-by-Hop (Next=TCP)
        data.extend_from_slice(&[
            6, // Next Header: TCP
            0, // Len: 0
            1, 4, 0, 0, 0, 0, // Options
        ]);

        // Some TCP data (should not be parsed as extension header)
        data.extend_from_slice(&[0u8; 20]);

        let iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_HOPOPT, &data);
        let headers: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(headers.len(), 1);
        assert!(matches!(headers[0], Ipv6ExtensionHeader::HopByHop { .. }));
    }

    #[test]
    fn test_extension_header_too_short() {
        // Only 1 byte - not enough for any extension header
        let data = [6];

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_HOPOPT, &data);
        let result = iter.next().unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn test_fragment_header_too_short() {
        // Fragment header needs 8 bytes, only provide 4
        let data = [6, 0, 0, 0];

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_FRAG, &data);
        let result = iter.next().unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn test_extension_header_length_exceeds_buffer() {
        // Claims length of 2 (24 bytes) but only 10 bytes available
        let data = [6, 2, 0, 0, 0, 0, 0, 0, 0, 0];

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_HOPOPT, &data);
        let result = iter.next().unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn test_authentication_header() {
        // AH: Next=TCP, Payload Len=1 (12 bytes: 2+2+4+4)
        let mut data = vec![
            6, // Next Header: TCP
            1, // Payload Len: 1 ((1+2)*4 = 12 bytes)
            0, 0, // Reserved
        ];
        data.extend_from_slice(&0x12345678u32.to_be_bytes()); // SPI
        data.extend_from_slice(&0xABCDEF00u32.to_be_bytes()); // Sequence

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::from(EXT_AH), &data);
        let ext = iter.next().unwrap().unwrap();

        match ext {
            Ipv6ExtensionHeader::AuthenticationHeader {
                next_header,
                spi,
                sequence,
                data,
            } => {
                assert_eq!(next_header, IpProto::TCP);
                assert_eq!(spi, 0x12345678);
                assert_eq!(sequence, 0xABCDEF00);
                assert_eq!(data.len(), 0);
            }
            _ => panic!("Expected AuthenticationHeader"),
        }
    }

    #[test]
    fn test_mobility_header() {
        // Mobility: Next=TCP, Len=1 (16 bytes)
        let mut data = vec![
            6, // Next Header: TCP
            1, // Hdr Ext Len: 1
            5, // MH Type: 5 (Binding Update)
        ];
        data.extend_from_slice(&[0u8; 13]); // Rest of data

        let mut iter = Ipv6ExtensionHeadersIter::new(IpProto::IPV6_MOBILITY, &data);
        let ext = iter.next().unwrap().unwrap();

        match ext {
            Ipv6ExtensionHeader::Mobility {
                next_header,
                mh_type,
                data,
            } => {
                assert_eq!(next_header, IpProto::TCP);
                assert_eq!(mh_type, 5);
                assert_eq!(data.len(), 14);
            }
            _ => panic!("Expected Mobility header"),
        }
    }

    #[test]
    fn test_is_fragment() {
        let frag = Ipv6ExtensionHeader::Fragment {
            next_header: IpProto::TCP,
            fragment_offset: 0,
            more_fragments: false,
            identification: 1,
        };
        assert!(frag.is_fragment());

        let hop = Ipv6ExtensionHeader::HopByHop {
            next_header: IpProto::TCP,
            options: &[],
        };
        assert!(!hop.is_fragment());
    }

    #[test]
    fn test_is_known() {
        let hop = Ipv6ExtensionHeader::HopByHop {
            next_header: IpProto::TCP,
            options: &[],
        };
        assert!(hop.is_known());

        let unknown = Ipv6ExtensionHeader::Unknown {
            header_type: 99,
            next_header: IpProto::TCP,
            data: &[],
        };
        assert!(!unknown.is_known());
    }
}
