use std::{cmp::min, fmt::{self, Display}};

use chrono::DateTime;
use pcap_parser::{EnhancedPacketBlock, LegacyPcapBlock, SimplePacketBlock};

#[derive (Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimestampNsec(u64);

impl Display for TimestampNsec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(date_time) = DateTime::from_timestamp(self.0 as i64 / 1_000_000_000, (self.0 % 1_000_000_000) as u32)
        {
            if !f.alternate() {
                return write!(f, "{}", date_time.format("%Y-%m-%d %H:%M:%S%.6f UTC"));
            }
        }

        write!(f, "{}.{:09}", self.0 / 1_000_000_000, self.0 % 1_000_000_000)
    }
}

pub trait PacketMetadata {
    fn caplen(&self) -> u32;
    fn origlen(&self) -> u32;
    fn data(&self) -> &[u8];
    fn timestamp(&self) -> TimestampNsec;
}

impl<'a> PacketMetadata for LegacyPcapBlock<'a> {
    #[inline]
    fn timestamp(&self) -> TimestampNsec {
        TimestampNsec((self.ts_sec as u64) * 1_000_000_000 + self.ts_usec as u64 * 1000)
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
    fn timestamp(&self) -> TimestampNsec {
        let raw_ts = ((self.ts_high as u64) << 32) | (self.ts_low as u64);
        let maybe_ns = raw_ts / 1_000_000_000;

        // Heuristic Thresholds:
        // Lower: 100_000_000 (Year 1973).
        //        Safe because modern microsecond timestamps / 10^9 result in ~1.7 million,
        //        which is well below this 100 million threshold.
        // Upper: 4_300_000_000 (Year 2106).
        //        Prevents u32 overflow.

        if (100_000_000..=4_000_000_000).contains(&maybe_ns) {
            TimestampNsec(raw_ts)
        } else {
            TimestampNsec(raw_ts * 1000)
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
    fn timestamp(&self) -> TimestampNsec {
        TimestampNsec(0)
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
