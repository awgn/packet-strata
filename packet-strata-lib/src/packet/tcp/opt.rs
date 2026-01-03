use std::fmt::{self, Formatter};

use zerocopy::{BigEndian, FromBytes, Immutable, Ref, Unaligned, U32};

use crate::packet::PacketHeaderError;

// Common TCP Option Kinds
const KIND_EOL: u8 = 0;
const KIND_NOP: u8 = 1;
const KIND_MSS: u8 = 2;
const KIND_WSCALE: u8 = 3;
const KIND_SACK_PERM: u8 = 4;
const KIND_SACK: u8 = 5;
const KIND_TIMESTAMP: u8 = 8;

#[derive(Debug)]
pub enum TcpOptionElement<'a> {
    Eol,                   // End of List
    Nop,                   // No Operation (padding)
    Mss(u16),              // Max Segment Size
    WindowScale(u8),       // Window Scale shift count
    SackPermitted,         // SACK Permitted
    Sack(&'a [SackBlock]), // SACK Blocks (cast directly from bytes)
    Timestamp(u32, u32),   // TS Value, TS Echo Reply
    Unknown { kind: u8, data: &'a [u8] },
}

// Struct representing a SACK block (Left Edge, Right Edge)
// We use this to cast the bytes directly.
#[derive(FromBytes, Unaligned, Immutable, Debug)]
#[repr(C)]
pub struct SackBlock {
    pub left_edge: U32<BigEndian>,
    pub right_edge: U32<BigEndian>,
}

impl fmt::Display for TcpOptionElement<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TcpOptionElement::Eol => write!(f, "EOL"),
            TcpOptionElement::Nop => write!(f, "NOP"),
            TcpOptionElement::Mss(mss) => write!(f, "MSS({})", mss),
            TcpOptionElement::WindowScale(shift) => write!(f, "WS({})", shift),
            TcpOptionElement::SackPermitted => write!(f, "SACK_OK"),
            TcpOptionElement::Sack(blocks) => {
                write!(f, "SACK(")?;
                for (i, block) in blocks.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}-{}", block.left_edge.get(), block.right_edge.get())?;
                }
                write!(f, ")")
            }
            TcpOptionElement::Timestamp(ts_val, ts_ecr) => {
                write!(f, "TS({},{})", ts_val, ts_ecr)
            }
            TcpOptionElement::Unknown { kind, .. } => write!(f, "UNK({})", kind),
        }
    }
}

pub struct TcpOptionsIter<'a> {
    cursor: &'a [u8],
}

impl<'a> TcpOptionsIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { cursor: data }
    }
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = Result<TcpOptionElement<'a>, PacketHeaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        // 1. Check if we have bytes left
        if self.cursor.is_empty() {
            return None;
        }

        // 2. Read Kind (1 byte)
        let kind = self.cursor[0];

        // Handle Single-Byte Options (EOL, NOP)
        match kind {
            KIND_EOL => {
                self.cursor = &[]; // Stop parsing
                return Some(Ok(TcpOptionElement::Eol));
            }
            KIND_NOP => {
                self.cursor = &self.cursor[1..];
                return Some(Ok(TcpOptionElement::Nop));
            }
            _ => {} // Variable length options continue below
        }

        // 3. Read Length (2nd byte)
        if self.cursor.len() < 2 {
            return Some(Err(PacketHeaderError::TooShort("TcpHeader"))); // Malformed: has kind but no len
        }
        let len = self.cursor[1] as usize;

        // Protocol requirement: Length must be at least 2 (Kind + Len)
        if len < 2 {
            return Some(Err(PacketHeaderError::Invalid("TcpHeader")));
        }

        // 4. Bounds Check
        if self.cursor.len() < len {
            return Some(Err(PacketHeaderError::TooShort("TcpHeader"))); // Declared len > remaining bytes
        }

        // 5. Extract Data
        // data slice excludes Kind and Len bytes
        let data = &self.cursor[2..len];

        // Advance cursor for next iteration
        self.cursor = &self.cursor[len..];

        // 6. Parse specific options
        let option_result = match kind {
            KIND_MSS => {
                if data.len() != 2 {
                    Ok(TcpOptionElement::Unknown { kind, data }) // Malformed MSS
                } else {
                    // Manual big-endian reading or use zerocopy::U16
                    let mss = u16::from_be_bytes([data[0], data[1]]);
                    Ok(TcpOptionElement::Mss(mss))
                }
            }
            KIND_WSCALE => {
                if data.len() != 1 {
                    Ok(TcpOptionElement::Unknown { kind, data })
                } else {
                    Ok(TcpOptionElement::WindowScale(data[0]))
                }
            }
            KIND_SACK_PERM => Ok(TcpOptionElement::SackPermitted),
            KIND_SACK => {
                // Cast the byte slice directly to a slice of SackBlock structs
                // slice_from requires alignment check, but SackBlock is Unaligned/U32
                match Ref::<_, [SackBlock]>::from_bytes(data) {
                    Ok(slice) => Ok(TcpOptionElement::Sack(Ref::into_ref(slice))),
                    Err(_) => Err(PacketHeaderError::Invalid("TcpHeader: OPT_SACK")), // Length not multiple of 8
                }
            }
            KIND_TIMESTAMP => {
                if data.len() != 8 {
                    Ok(TcpOptionElement::Unknown { kind, data })
                } else {
                    let ts_val = u32::from_be_bytes(data[0..4].try_into().unwrap());
                    let ts_ecr = u32::from_be_bytes(data[4..8].try_into().unwrap());
                    Ok(TcpOptionElement::Timestamp(ts_val, ts_ecr))
                }
            }
            _ => Ok(TcpOptionElement::Unknown { kind, data }),
        };

        Some(option_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_option_eol() {
        let data = [KIND_EOL, 0x00, 0x00];
        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, TcpOptionElement::Eol));

        // After EOL, iterator should stop
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_tcp_option_nop() {
        let data = [KIND_NOP, KIND_NOP, KIND_NOP];
        let mut iter = TcpOptionsIter::new(&data);

        for _ in 0..3 {
            let opt = iter.next().unwrap().unwrap();
            assert!(matches!(opt, TcpOptionElement::Nop));
        }

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_tcp_option_mss() {
        // MSS option: Kind 2, Length 4, MSS value 1460
        let data = [KIND_MSS, 0x04, 0x05, 0xB4];
        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Mss(mss) => assert_eq!(mss, 1460),
            _ => panic!("Expected MSS option"),
        }

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_tcp_option_mss_malformed() {
        // MSS with wrong length (should be 4, but is 3)
        let data = [KIND_MSS, 0x03, 0x05];
        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Unknown { kind, data } => {
                assert_eq!(kind, KIND_MSS);
                assert_eq!(data.len(), 1); // Length 3 - 2 (kind + len) = 1
            }
            _ => panic!("Expected Unknown option for malformed MSS"),
        }
    }

    #[test]
    fn test_tcp_option_window_scale() {
        // Window Scale option: Kind 3, Length 3, Shift count 7
        let data = [KIND_WSCALE, 0x03, 0x07];
        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::WindowScale(shift) => assert_eq!(shift, 7),
            _ => panic!("Expected WindowScale option"),
        }
    }

    #[test]
    fn test_tcp_option_sack_permitted() {
        // SACK Permitted option: Kind 4, Length 2
        let data = [KIND_SACK_PERM, 0x02];
        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, TcpOptionElement::SackPermitted));
    }

    #[test]
    fn test_tcp_option_sack_single_block() {
        // SACK option: Kind 5, Length 10 (2 + 8 for one block)
        // Left edge: 1000, Right edge: 2000
        let mut data = vec![KIND_SACK, 0x0A];
        data.extend_from_slice(&1000u32.to_be_bytes()); // Left edge
        data.extend_from_slice(&2000u32.to_be_bytes()); // Right edge

        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Sack(blocks) => {
                assert_eq!(blocks.len(), 1);
                assert_eq!(blocks[0].left_edge.get(), 1000);
                assert_eq!(blocks[0].right_edge.get(), 2000);
            }
            _ => panic!("Expected SACK option"),
        }
    }

    #[test]
    fn test_tcp_option_sack_multiple_blocks() {
        // SACK option with 3 blocks: Kind 5, Length 26 (2 + 24 for three blocks)
        let mut data = vec![KIND_SACK, 0x1A];
        // Block 1
        data.extend_from_slice(&1000u32.to_be_bytes());
        data.extend_from_slice(&2000u32.to_be_bytes());
        // Block 2
        data.extend_from_slice(&3000u32.to_be_bytes());
        data.extend_from_slice(&4000u32.to_be_bytes());
        // Block 3
        data.extend_from_slice(&5000u32.to_be_bytes());
        data.extend_from_slice(&6000u32.to_be_bytes());

        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Sack(blocks) => {
                assert_eq!(blocks.len(), 3);
                assert_eq!(blocks[0].left_edge.get(), 1000);
                assert_eq!(blocks[0].right_edge.get(), 2000);
                assert_eq!(blocks[1].left_edge.get(), 3000);
                assert_eq!(blocks[1].right_edge.get(), 4000);
                assert_eq!(blocks[2].left_edge.get(), 5000);
                assert_eq!(blocks[2].right_edge.get(), 6000);
            }
            _ => panic!("Expected SACK option"),
        }
    }

    #[test]
    fn test_tcp_option_sack_malformed() {
        // SACK with invalid length (not multiple of 8)
        let data = [KIND_SACK, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut iter = TcpOptionsIter::new(&data);

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_option_timestamp() {
        // Timestamp option: Kind 8, Length 10, TSval, TSecr
        let mut data = vec![KIND_TIMESTAMP, 0x0A];
        data.extend_from_slice(&12345678u32.to_be_bytes()); // TSval
        data.extend_from_slice(&87654321u32.to_be_bytes()); // TSecr

        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Timestamp(ts_val, ts_ecr) => {
                assert_eq!(ts_val, 12345678);
                assert_eq!(ts_ecr, 87654321);
            }
            _ => panic!("Expected Timestamp option"),
        }
    }

    #[test]
    fn test_tcp_option_timestamp_malformed() {
        // Timestamp with wrong length (should be 10)
        let data = [KIND_TIMESTAMP, 0x06, 0x00, 0x00, 0x00, 0x00];
        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Unknown { kind, .. } => {
                assert_eq!(kind, KIND_TIMESTAMP);
            }
            _ => panic!("Expected Unknown option for malformed Timestamp"),
        }
    }

    #[test]
    fn test_tcp_option_unknown() {
        // Unknown option kind: Kind 99, Length 5, arbitrary data
        let data = [99, 0x05, 0xAA, 0xBB, 0xCC];
        let mut iter = TcpOptionsIter::new(&data);

        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Unknown { kind, data } => {
                assert_eq!(kind, 99);
                assert_eq!(data, &[0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("Expected Unknown option"),
        }
    }

    #[test]
    fn test_tcp_options_multiple_mixed() {
        let mut data = Vec::new();

        // NOP
        data.push(KIND_NOP);

        // MSS: 1460
        data.extend_from_slice(&[KIND_MSS, 0x04, 0x05, 0xB4]);

        // NOP
        data.push(KIND_NOP);

        // Window Scale: 7
        data.extend_from_slice(&[KIND_WSCALE, 0x03, 0x07]);

        // SACK Permitted
        data.extend_from_slice(&[KIND_SACK_PERM, 0x02]);

        // Timestamp
        data.push(KIND_TIMESTAMP);
        data.push(0x0A);
        data.extend_from_slice(&123u32.to_be_bytes());
        data.extend_from_slice(&456u32.to_be_bytes());

        let mut iter = TcpOptionsIter::new(&data);

        // Check NOP
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, TcpOptionElement::Nop));

        // Check MSS
        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Mss(mss) => assert_eq!(mss, 1460),
            _ => panic!("Expected MSS"),
        }

        // Check NOP
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, TcpOptionElement::Nop));

        // Check Window Scale
        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::WindowScale(shift) => assert_eq!(shift, 7),
            _ => panic!("Expected WindowScale"),
        }

        // Check SACK Permitted
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, TcpOptionElement::SackPermitted));

        // Check Timestamp
        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Timestamp(ts_val, ts_ecr) => {
                assert_eq!(ts_val, 123);
                assert_eq!(ts_ecr, 456);
            }
            _ => panic!("Expected Timestamp"),
        }

        // No more options
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_tcp_options_eol_stops_parsing() {
        let data = [
            KIND_NOP, KIND_MSS, 0x04, 0x05, 0xB4, KIND_EOL, KIND_NOP, KIND_NOP,
        ];
        let mut iter = TcpOptionsIter::new(&data);

        // NOP
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, TcpOptionElement::Nop));

        // MSS
        let opt = iter.next().unwrap().unwrap();
        match opt {
            TcpOptionElement::Mss(mss) => assert_eq!(mss, 1460),
            _ => panic!("Expected MSS"),
        }

        // EOL - should stop iteration
        let opt = iter.next().unwrap().unwrap();
        assert!(matches!(opt, TcpOptionElement::Eol));

        // No more options after EOL
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_tcp_option_too_short_no_length() {
        // Option with kind but no length byte
        let data = [KIND_MSS]; // Missing length and data
        let mut iter = TcpOptionsIter::new(&data);

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_option_length_too_small() {
        // Option with length < 2 (invalid per protocol)
        let data = [KIND_MSS, 0x01]; // Length 1 is invalid
        let mut iter = TcpOptionsIter::new(&data);

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_option_length_exceeds_buffer() {
        // Option claims length 10 but only 5 bytes available
        let data = [KIND_TIMESTAMP, 0x0A, 0x00, 0x00, 0x00];
        let mut iter = TcpOptionsIter::new(&data);

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_options_empty_buffer() {
        let data: [u8; 0] = [];
        let mut iter = TcpOptionsIter::new(&data);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_tcp_option_real_world_syn() {
        // Real-world TCP SYN options: MSS, SACK Permitted, Timestamp, NOP, Window Scale
        let mut data = Vec::new();

        // MSS
        data.extend_from_slice(&[KIND_MSS, 0x04, 0x05, 0xB4]); // MSS 1460

        // SACK Permitted
        data.extend_from_slice(&[KIND_SACK_PERM, 0x02]);

        // Timestamp
        data.push(KIND_TIMESTAMP);
        data.push(0x0A);
        data.extend_from_slice(&3845678901u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());

        // NOP
        data.push(KIND_NOP);

        // Window Scale
        data.extend_from_slice(&[KIND_WSCALE, 0x03, 0x07]);

        let opts: Vec<_> = TcpOptionsIter::new(&data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 5);

        // Verify each option
        assert!(matches!(opts[0], TcpOptionElement::Mss(1460)));
        assert!(matches!(opts[1], TcpOptionElement::SackPermitted));
        assert!(matches!(
            opts[2],
            TcpOptionElement::Timestamp(3845678901, 0)
        ));
        assert!(matches!(opts[3], TcpOptionElement::Nop));
        assert!(matches!(opts[4], TcpOptionElement::WindowScale(7)));
    }
}
