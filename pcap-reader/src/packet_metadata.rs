use std::cmp::min;

use chrono::DateTime;
use pcap_parser::{EnhancedPacketBlock, LegacyPcapBlock, SimplePacketBlock};

pub struct Timestamp {
    sec: u32,
    nsec: u32,
}

pub trait PacketMetadata {
    fn caplen(&self) -> u32;
    fn origlen(&self) -> u32;
    fn data(&self) -> &[u8];
    fn timestamp(&self) -> Timestamp;
    fn timestamp_string(&self) -> String {
        let ts = self.timestamp();
        if let Some(date_time) = DateTime::from_timestamp(ts.sec as i64, ts.nsec) {
            date_time.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string()
        } else {
            "".into()
        }
    }
}

impl<'a> PacketMetadata for LegacyPcapBlock<'a> {
    #[inline]
    fn timestamp(&self) -> Timestamp {
        Timestamp {
            sec: self.ts_sec,
            nsec: self.ts_usec * 1000,
        }
    }

    #[inline]
    fn caplen(&self) -> u32 {
        self.caplen
    }

    #[inline]
    fn origlen(&self) -> u32 {
        self.origlen
    }

    #[inline]
    fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> PacketMetadata for EnhancedPacketBlock<'a> {
    #[inline]
    fn timestamp(&self) -> Timestamp {
        let raw_ts = ((self.ts_high as u64) << 32) | (self.ts_low as u64);
        let sec_nano = raw_ts / 1_000_000_000;

        // Heuristic Thresholds:
        // Lower: 100_000_000 (Year 1973).
        //        Safe because modern microsecond timestamps / 10^9 result in ~1.7 million,
        //        which is well below this 100 million threshold.
        // Upper: 4_300_000_000 (Year 2106).
        //        Prevents u32 overflow.

        if sec_nano >= 100_000_000 && sec_nano <= 4_000_000_000 {
            Timestamp {
                sec: sec_nano as u32,
                nsec: (raw_ts % 1_000_000_000) as u32,
            }
        } else {
            let sec = raw_ts / 1_000_000;
            let usec = raw_ts % 1_000_000;
            Timestamp {
                sec: sec as u32,
                nsec: (usec * 1000) as u32,
            }
        }
    }

    #[inline]
    fn caplen(&self) -> u32 {
        self.caplen
    }

    #[inline]
    fn origlen(&self) -> u32 {
        self.origlen
    }

    #[inline]
    fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> PacketMetadata for SimplePacketBlock<'a> {
    #[inline]
    fn timestamp(&self) -> Timestamp {
        Timestamp { sec: 0, nsec: 0 }
    }

    #[inline]
    fn caplen(&self) -> u32 {
        min(self.origlen, self.data.len() as u32)
    }

    #[inline]
    fn origlen(&self) -> u32 {
        self.origlen
    }

    #[inline]
    fn data(&self) -> &[u8] {
        self.data
    }
}
