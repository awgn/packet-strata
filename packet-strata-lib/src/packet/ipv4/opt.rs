use std::fmt::{self, Formatter};

use crate::packet::PacketHeaderError;

// Common IPv4 Option Types (from RFC 791 and related RFCs)
const OPT_EOL: u8 = 0; // End of Option List
const OPT_NOP: u8 = 1; // No Operation
const OPT_SEC: u8 = 130; // Security (copied)
const OPT_LSRR: u8 = 131; // Loose Source and Record Route (copied)
const OPT_TS: u8 = 68; // Timestamp
#[allow(dead_code)]
const OPT_ESEC: u8 = 133; // Extended Security (copied)
const OPT_RR: u8 = 7; // Record Route
const OPT_SID: u8 = 136; // Stream ID (copied)
const OPT_SSRR: u8 = 137; // Strict Source and Record Route (copied)
#[allow(dead_code)]
const OPT_ZSU: u8 = 10; // Experimental Measurement
#[allow(dead_code)]
const OPT_MTUP: u8 = 11; // MTU Probe
#[allow(dead_code)]
const OPT_MTUR: u8 = 12; // MTU Reply
#[allow(dead_code)]
const OPT_FINN: u8 = 205; // Experimental Flow Control
#[allow(dead_code)]
const OPT_VISA: u8 = 142; // Experimental Access Control
#[allow(dead_code)]
const OPT_ENCODE: u8 = 15; // ENCODE
#[allow(dead_code)]
const OPT_IMITD: u8 = 144; // IMI Traffic Descriptor
#[allow(dead_code)]
const OPT_EIP: u8 = 145; // Extended Internet Protocol
#[allow(dead_code)]
const OPT_TR: u8 = 82; // Traceroute
#[allow(dead_code)]
const OPT_ADDEXT: u8 = 147; // Address Extension
const OPT_RTRALT: u8 = 148; // Router Alert
#[allow(dead_code)]
const OPT_SDB: u8 = 149; // Selective Directed Broadcast
#[allow(dead_code)]
const OPT_DPS: u8 = 151; // Dynamic Packet State
#[allow(dead_code)]
const OPT_UMP: u8 = 152; // Upstream Multicast Packet
const OPT_QS: u8 = 25; // Quick-Start

/// Timestamp flags for Timestamp option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampFlag {
    /// Timestamps only
    TimestampsOnly = 0,
    /// IP addresses and timestamps
    AddressAndTimestamp = 1,
    /// Prespecified addresses only
    PrespecifiedAddresses = 3,
}

impl TimestampFlag {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0F {
            0 => Some(TimestampFlag::TimestampsOnly),
            1 => Some(TimestampFlag::AddressAndTimestamp),
            3 => Some(TimestampFlag::PrespecifiedAddresses),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Ipv4OptionElement<'a> {
    /// End of Option List
    Eol,
    /// No Operation (padding)
    Nop,
    /// Security option (IPSO Basic Security Option)
    Security {
        classification: u16,
        protection_authority: u16,
    },
    /// Loose Source and Record Route
    LooseSourceRoute { pointer: u8, route_data: &'a [u8] },
    /// Record Route
    RecordRoute { pointer: u8, route_data: &'a [u8] },
    /// Strict Source and Record Route
    StrictSourceRoute { pointer: u8, route_data: &'a [u8] },
    /// Stream Identifier
    StreamId(u16),
    /// Timestamp
    Timestamp {
        pointer: u8,
        overflow: u8,
        flags: TimestampFlag,
        data: &'a [u8],
    },
    /// Router Alert
    RouterAlert(u16),
    /// Quick-Start
    QuickStart {
        func: u8,
        rate: u8,
        ttl: u8,
        nonce: u32,
    },
    /// Unknown or unsupported option
    Unknown { option_type: u8, data: &'a [u8] },
}

impl<'a> Ipv4OptionElement<'a> {
    /// Returns true if this option should be copied to all fragments
    pub fn is_copied(&self) -> bool {
        match self {
            Ipv4OptionElement::Eol | Ipv4OptionElement::Nop => false,
            Ipv4OptionElement::Security { .. }
            | Ipv4OptionElement::LooseSourceRoute { .. }
            | Ipv4OptionElement::StrictSourceRoute { .. }
            | Ipv4OptionElement::StreamId(_) => true,
            Ipv4OptionElement::RecordRoute { .. }
            | Ipv4OptionElement::Timestamp { .. }
            | Ipv4OptionElement::RouterAlert(_)
            | Ipv4OptionElement::QuickStart { .. } => false,
            Ipv4OptionElement::Unknown { option_type, .. } => (option_type & 0x80) != 0,
        }
    }

    /// Returns the option class (0-3)
    pub fn option_class(&self) -> u8 {
        match self {
            Ipv4OptionElement::Eol | Ipv4OptionElement::Nop => 0,
            Ipv4OptionElement::Security { .. } => 0,
            Ipv4OptionElement::LooseSourceRoute { .. }
            | Ipv4OptionElement::StrictSourceRoute { .. }
            | Ipv4OptionElement::RecordRoute { .. }
            | Ipv4OptionElement::StreamId(_) => 0,
            Ipv4OptionElement::Timestamp { .. } => 2,
            Ipv4OptionElement::RouterAlert(_) => 0,
            Ipv4OptionElement::QuickStart { .. } => 0,
            Ipv4OptionElement::Unknown { option_type, .. } => (option_type >> 5) & 0x03,
        }
    }
}

impl fmt::Display for Ipv4OptionElement<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Ipv4OptionElement::Eol => write!(f, "EOL"),
            Ipv4OptionElement::Nop => write!(f, "NOP"),
            Ipv4OptionElement::Security { classification, .. } => {
                write!(f, "SEC(class={})", classification)
            }
            Ipv4OptionElement::LooseSourceRoute { pointer, .. } => {
                write!(f, "LSRR(ptr={})", pointer)
            }
            Ipv4OptionElement::RecordRoute { pointer, .. } => {
                write!(f, "RR(ptr={})", pointer)
            }
            Ipv4OptionElement::StrictSourceRoute { pointer, .. } => {
                write!(f, "SSRR(ptr={})", pointer)
            }
            Ipv4OptionElement::StreamId(id) => write!(f, "SID({})", id),
            Ipv4OptionElement::Timestamp {
                flags, overflow, ..
            } => {
                write!(f, "TS({:?},ovf={})", flags, overflow)
            }
            Ipv4OptionElement::RouterAlert(value) => write!(f, "RTRALT({})", value),
            Ipv4OptionElement::QuickStart { func, rate, .. } => {
                write!(f, "QS(fn={},rate={})", func, rate)
            }
            Ipv4OptionElement::Unknown { option_type, .. } => {
                write!(f, "UNK({})", option_type)
            }
        }
    }
}

pub struct Ipv4OptionsIter<'a> {
    cursor: &'a [u8],
}

impl<'a> Ipv4OptionsIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { cursor: data }
    }
}

impl<'a> Iterator for Ipv4OptionsIter<'a> {
    type Item = Result<Ipv4OptionElement<'a>, PacketHeaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Check if we have bytes left
        if self.cursor.is_empty() {
            return None;
        }

        // Read option type (1 byte)
        let option_type = self.cursor[0];

        // Handle single-byte options (EOL, NOP)
        match option_type {
            OPT_EOL => {
                self.cursor = &[]; // Stop parsing
                return Some(Ok(Ipv4OptionElement::Eol));
            }
            OPT_NOP => {
                self.cursor = &self.cursor[1..];
                return Some(Ok(Ipv4OptionElement::Nop));
            }
            _ => {} // Variable length options continue below
        }

        // Read length (2nd byte)
        if self.cursor.len() < 2 {
            return Some(Err(PacketHeaderError::TooShort("IPv4Option")));
        }
        let len = self.cursor[1] as usize;

        // Length must be at least 2 (Type + Length)
        if len < 2 {
            return Some(Err(PacketHeaderError::Invalid("IPv4Option")));
        }

        // Bounds check
        if self.cursor.len() < len {
            return Some(Err(PacketHeaderError::TooShort("IPv4Option")));
        }

        // Extract data (excludes Type and Length bytes)
        let data = &self.cursor[2..len];

        // Advance cursor
        self.cursor = &self.cursor[len..];

        // Parse specific options
        let option_result = match option_type {
            OPT_SEC => {
                if data.len() < 4 {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let classification = u16::from_be_bytes([data[0], data[1]]);
                    let protection_authority = u16::from_be_bytes([data[2], data[3]]);
                    Ok(Ipv4OptionElement::Security {
                        classification,
                        protection_authority,
                    })
                }
            }
            OPT_LSRR => {
                if data.is_empty() {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let pointer = data[0];
                    let route_data = &data[1..];
                    Ok(Ipv4OptionElement::LooseSourceRoute {
                        pointer,
                        route_data,
                    })
                }
            }
            OPT_RR => {
                if data.is_empty() {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let pointer = data[0];
                    let route_data = &data[1..];
                    Ok(Ipv4OptionElement::RecordRoute {
                        pointer,
                        route_data,
                    })
                }
            }
            OPT_SSRR => {
                if data.is_empty() {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let pointer = data[0];
                    let route_data = &data[1..];
                    Ok(Ipv4OptionElement::StrictSourceRoute {
                        pointer,
                        route_data,
                    })
                }
            }
            OPT_SID => {
                if data.len() != 2 {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let stream_id = u16::from_be_bytes([data[0], data[1]]);
                    Ok(Ipv4OptionElement::StreamId(stream_id))
                }
            }
            OPT_TS => {
                if data.len() < 2 {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let pointer = data[0];
                    let overflow_flags = data[1];
                    let overflow = overflow_flags >> 4;
                    let flags = TimestampFlag::from_u8(overflow_flags & 0x0F)
                        .unwrap_or(TimestampFlag::TimestampsOnly);
                    let ts_data = &data[2..];
                    Ok(Ipv4OptionElement::Timestamp {
                        pointer,
                        overflow,
                        flags,
                        data: ts_data,
                    })
                }
            }
            OPT_RTRALT => {
                if data.len() != 2 {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let value = u16::from_be_bytes([data[0], data[1]]);
                    Ok(Ipv4OptionElement::RouterAlert(value))
                }
            }
            OPT_QS => {
                if data.len() < 6 {
                    Ok(Ipv4OptionElement::Unknown { option_type, data })
                } else {
                    let func = data[0] >> 4;
                    let rate = data[0] & 0x0F;
                    let ttl = data[1];
                    let nonce = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                    Ok(Ipv4OptionElement::QuickStart {
                        func,
                        rate,
                        ttl,
                        nonce,
                    })
                }
            }
            _ => Ok(Ipv4OptionElement::Unknown { option_type, data }),
        };

        Some(option_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_option_eol() {
        let data = [OPT_EOL, 0x00, 0x00];
        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, Ipv4OptionElement::Eol));

        // After EOL, iterator should stop
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ipv4_option_nop() {
        let data = [OPT_NOP, OPT_NOP, OPT_NOP];
        let mut iter = Ipv4OptionsIter::new(&data);

        for _ in 0..3 {
            let opt = iter.next().unwrap().unwrap();
            assert!(matches!(opt, Ipv4OptionElement::Nop));
        }

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ipv4_option_security() {
        // Security option: Type 130, Length 6, Classification, Protection Authority
        let data = [OPT_SEC, 0x06, 0x00, 0x01, 0x00, 0x02];
        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::Security {
                classification,
                protection_authority,
            } => {
                assert_eq!(classification, 1);
                assert_eq!(protection_authority, 2);
                assert!(opt.is_copied());
            }
            _ => panic!("Expected Security option"),
        }
    }

    #[test]
    fn test_ipv4_option_record_route() {
        // Record Route: Type 7, Length 11, Pointer 4, 2 IP addresses
        let mut data = vec![OPT_RR, 0x0B, 0x04];
        data.extend_from_slice(&[192, 168, 1, 1]); // IP 1
        data.extend_from_slice(&[192, 168, 1, 2]); // IP 2

        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::RecordRoute {
                pointer,
                route_data,
            } => {
                assert_eq!(pointer, 4);
                assert_eq!(route_data.len(), 8);
                assert!(!opt.is_copied());
            }
            _ => panic!("Expected RecordRoute option"),
        }
    }

    #[test]
    fn test_ipv4_option_loose_source_route() {
        // LSRR: Type 131, Length 11, Pointer 4, 2 IP addresses
        let mut data = vec![OPT_LSRR, 0x0B, 0x04];
        data.extend_from_slice(&[10, 0, 0, 1]);
        data.extend_from_slice(&[10, 0, 0, 2]);

        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::LooseSourceRoute {
                pointer,
                route_data,
            } => {
                assert_eq!(pointer, 4);
                assert_eq!(route_data.len(), 8);
                assert!(opt.is_copied());
            }
            _ => panic!("Expected LooseSourceRoute option"),
        }
    }

    #[test]
    fn test_ipv4_option_strict_source_route() {
        // SSRR: Type 137, Length 7, Pointer 4, 1 IP address
        let mut data = vec![OPT_SSRR, 0x07, 0x04];
        data.extend_from_slice(&[172, 16, 0, 1]);

        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::StrictSourceRoute {
                pointer,
                route_data,
            } => {
                assert_eq!(pointer, 4);
                assert_eq!(route_data.len(), 4);
                assert!(opt.is_copied());
            }
            _ => panic!("Expected StrictSourceRoute option"),
        }
    }

    #[test]
    fn test_ipv4_option_stream_id() {
        // Stream ID: Type 136, Length 4, Stream ID 0x1234
        let data = [OPT_SID, 0x04, 0x12, 0x34];
        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::StreamId(stream_id) => {
                assert_eq!(stream_id, 0x1234);
                assert!(opt.is_copied());
            }
            _ => panic!("Expected StreamId option"),
        }
    }

    #[test]
    fn test_ipv4_option_timestamp_timestamps_only() {
        // Timestamp: Type 68, Length 12, Pointer 5, Overflow 0, Flags 0
        let mut data = vec![OPT_TS, 0x0C, 0x05, 0x00]; // pointer=5, overflow=0, flags=0
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Timestamp 1
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // Timestamp 2

        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::Timestamp {
                pointer,
                overflow,
                flags,
                data,
            } => {
                assert_eq!(pointer, 5);
                assert_eq!(overflow, 0);
                assert_eq!(flags, TimestampFlag::TimestampsOnly);
                assert_eq!(data.len(), 8);
                assert!(!opt.is_copied());
                assert_eq!(opt.option_class(), 2);
            }
            _ => panic!("Expected Timestamp option"),
        }
    }

    #[test]
    fn test_ipv4_option_timestamp_with_addresses() {
        // Timestamp with addresses: Flags 1
        let mut data = vec![OPT_TS, 0x14, 0x05, 0x01]; // flags=1
        data.extend_from_slice(&[192, 168, 1, 1]); // IP 1
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Timestamp 1
        data.extend_from_slice(&[192, 168, 1, 2]); // IP 2
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // Timestamp 2

        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::Timestamp { flags, data, .. } => {
                assert_eq!(flags, TimestampFlag::AddressAndTimestamp);
                assert_eq!(data.len(), 16);
            }
            _ => panic!("Expected Timestamp option"),
        }
    }

    #[test]
    fn test_ipv4_option_router_alert() {
        // Router Alert: Type 148, Length 4, Value 0
        let data = [OPT_RTRALT, 0x04, 0x00, 0x00];
        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::RouterAlert(value) => {
                assert_eq!(value, 0);
                assert!(!opt.is_copied());
            }
            _ => panic!("Expected RouterAlert option"),
        }
    }

    #[test]
    fn test_ipv4_option_quick_start() {
        // Quick-Start: Type 25, Length 8
        let data = [OPT_QS, 0x08, 0x04, 0x40, 0x12, 0x34, 0x56, 0x78];
        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::QuickStart {
                func,
                rate,
                ttl,
                nonce,
            } => {
                assert_eq!(func, 0);
                assert_eq!(rate, 4);
                assert_eq!(ttl, 0x40);
                assert_eq!(nonce, 0x12345678);
            }
            _ => panic!("Expected QuickStart option"),
        }
    }

    #[test]
    fn test_ipv4_option_unknown() {
        // Unknown option: Type 99, Length 5
        let data = [99, 0x05, 0xAA, 0xBB, 0xCC];
        let mut iter = Ipv4OptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            Ipv4OptionElement::Unknown { option_type, data } => {
                assert_eq!(option_type, 99);
                assert_eq!(data, &[0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("Expected Unknown option"),
        }
    }

    #[test]
    fn test_ipv4_options_multiple_mixed() {
        let mut data = Vec::new();

        // NOP
        data.push(OPT_NOP);

        // Stream ID
        data.extend_from_slice(&[OPT_SID, 0x04, 0x00, 0x01]);

        // NOP
        data.push(OPT_NOP);

        // Record Route
        data.extend_from_slice(&[OPT_RR, 0x07, 0x04]);
        data.extend_from_slice(&[10, 0, 0, 1]);

        // Router Alert
        data.extend_from_slice(&[OPT_RTRALT, 0x04, 0x00, 0x00]);

        let opts: Vec<_> = Ipv4OptionsIter::new(&data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 5);

        assert!(matches!(opts[0], Ipv4OptionElement::Nop));
        assert!(matches!(opts[1], Ipv4OptionElement::StreamId(1)));
        assert!(matches!(opts[2], Ipv4OptionElement::Nop));
        assert!(matches!(opts[3], Ipv4OptionElement::RecordRoute { .. }));
        assert!(matches!(opts[4], Ipv4OptionElement::RouterAlert(0)));
    }

    #[test]
    fn test_ipv4_options_eol_stops_parsing() {
        let data = [OPT_NOP, OPT_SID, 0x04, 0x00, 0x01, OPT_EOL, OPT_NOP];
        let mut iter = Ipv4OptionsIter::new(&data);

        // NOP
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, Ipv4OptionElement::Nop));

        // Stream ID
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, Ipv4OptionElement::StreamId(1)));

        // EOL - should stop iteration
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, Ipv4OptionElement::Eol));

        // No more options after EOL
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ipv4_option_too_short_no_length() {
        // Option with type but no length byte
        let data = [OPT_RR];
        let mut iter = Ipv4OptionsIter::new(&data);

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_option_length_too_small() {
        // Option with length < 2
        let data = [OPT_RR, 0x01];
        let mut iter = Ipv4OptionsIter::new(&data);

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_option_length_exceeds_buffer() {
        // Option claims length 10 but only 5 bytes available
        let data = [OPT_TS, 0x0A, 0x00, 0x00, 0x00];
        let mut iter = Ipv4OptionsIter::new(&data);

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_options_empty_buffer() {
        let data: [u8; 0] = [];
        let mut iter = Ipv4OptionsIter::new(&data);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ipv4_option_copied_flag() {
        // Test copied flag for different options
        let sec = Ipv4OptionElement::Security {
            classification: 0,
            protection_authority: 0,
        };
        assert!(sec.is_copied());

        let rr = Ipv4OptionElement::RecordRoute {
            pointer: 4,
            route_data: &[],
        };
        assert!(!rr.is_copied());

        let lsrr = Ipv4OptionElement::LooseSourceRoute {
            pointer: 4,
            route_data: &[],
        };
        assert!(lsrr.is_copied());

        let ts = Ipv4OptionElement::Timestamp {
            pointer: 5,
            overflow: 0,
            flags: TimestampFlag::TimestampsOnly,
            data: &[],
        };
        assert!(!ts.is_copied());
    }

    #[test]
    fn test_ipv4_option_class() {
        let sec = Ipv4OptionElement::Security {
            classification: 0,
            protection_authority: 0,
        };
        assert_eq!(sec.option_class(), 0);

        let ts = Ipv4OptionElement::Timestamp {
            pointer: 5,
            overflow: 0,
            flags: TimestampFlag::TimestampsOnly,
            data: &[],
        };
        assert_eq!(ts.option_class(), 2);
    }

    #[test]
    fn test_timestamp_flag_conversion() {
        assert_eq!(
            TimestampFlag::from_u8(0),
            Some(TimestampFlag::TimestampsOnly)
        );
        assert_eq!(
            TimestampFlag::from_u8(1),
            Some(TimestampFlag::AddressAndTimestamp)
        );
        assert_eq!(
            TimestampFlag::from_u8(3),
            Some(TimestampFlag::PrespecifiedAddresses)
        );
        assert_eq!(TimestampFlag::from_u8(2), None);
        assert_eq!(TimestampFlag::from_u8(4), None);
    }

    #[test]
    fn test_ipv4_option_real_world_scenario() {
        // Simulate real IPv4 options from a packet
        let mut data = Vec::new();

        // NOP for alignment
        data.push(OPT_NOP);

        // Router Alert (used in IGMP, RSVP)
        data.extend_from_slice(&[OPT_RTRALT, 0x04, 0x00, 0x00]);

        // Record Route (7 bytes: Type, Len, Pointer, IP)
        data.extend_from_slice(&[OPT_RR, 0x07, 0x04]);
        data.extend_from_slice(&[192, 168, 1, 1]);

        let opts: Vec<_> = Ipv4OptionsIter::new(&data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 3);
        assert!(matches!(opts[0], Ipv4OptionElement::Nop));
        assert!(matches!(opts[1], Ipv4OptionElement::RouterAlert(0)));
        assert!(matches!(opts[2], Ipv4OptionElement::RecordRoute { .. }));
    }
}
