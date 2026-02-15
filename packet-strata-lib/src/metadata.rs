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

        // Try to determine if timestamp is microseconds or nanoseconds.
        // Modern timestamps (e.g. 2024) in microseconds are ~1.7e15
        // In nanoseconds they are ~1.7e18
        // We use a threshold of 1e16 to distinguish.

        if raw_ts < 10_000_000_000_000_000 {
            // microseconds, convert to nanoseconds
            Timestamp(raw_ts * 1000)
        } else {
            // nanoseconds
            Timestamp(raw_ts)
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
