use crate::timestamp::Timestamp;
use pcap_parser::{EnhancedPacketBlock, LegacyPcapBlock, SimplePacketBlock};
use std::cmp::min;

pub trait PacketMetadata {
    fn caplen(&self) -> u32;
    fn origlen(&self) -> u32;
    fn data(&self) -> &[u8];
    fn timestamp(&self) -> Timestamp;
}

impl<'a> PacketMetadata for LegacyPcapBlock<'a> {
    #[inline]
    fn timestamp(&self) -> Timestamp {
        Timestamp((self.ts_sec as u64) * 1_000_000_000 + self.ts_usec as u64 * 1000)
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
        let maybe_ns = raw_ts / 1_000_000_000;

        // Heuristic Thresholds:
        // Lower: 100_000_000 (Year 1973).
        //        Safe because modern microsecond timestamps / 10^9 result in ~1.7 million,
        //        which is well below this 100 million threshold.
        // Upper: 4_300_000_000 (Year 2106).
        //        Prevents u32 overflow.

        if (100_000_000..=4_000_000_000).contains(&maybe_ns) {
            Timestamp(raw_ts)
        } else {
            Timestamp(raw_ts * 1000)
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
        Timestamp(0)
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
