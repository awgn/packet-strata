use chrono::DateTime;
use pcap_parser::{EnhancedPacketBlock, LegacyPcapBlock};

pub trait PacketMetadata {
    fn ts_sec(&self) -> u32;
    fn ts_usec(&self) -> u32;
    fn caplen(&self) -> u32;
    fn origlen(&self) -> u32;
    fn payload(&self) -> &[u8];

    fn tstamp(&self) -> String {
        if let Some(date_time) = DateTime::from_timestamp(self.ts_sec() as i64, self.ts_usec() * 1000) {
            date_time.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string()
        } else {
            "".into()
        }
    }
}

impl<'a> PacketMetadata for LegacyPcapBlock<'a>  {
    #[inline]
    fn ts_sec(&self) -> u32 {
        self.ts_sec
    }

    #[inline]
    fn ts_usec(&self) -> u32 {
        self.ts_usec
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
    fn payload(&self) -> &[u8] {
        self.data
    }
}

impl<'a> PacketMetadata for  EnhancedPacketBlock<'a> {
    #[inline]
    fn ts_sec(&self) -> u32 {
        let timestamp = ((self.ts_high as u64) << 32) | (self.ts_low as u64);
        (timestamp / 1_000_000) as u32
    }

    #[inline]
    fn ts_usec(&self) -> u32 {
        let timestamp = ((self.ts_high as u64) << 32) | (self.ts_low as u64);
        (timestamp % 1_000_000) as u32
    }

    #[inline]
    fn caplen(&self) -> u32 {
        self.caplen
    }

    #[inline]
    fn origlen(&self) -> u32 {
        self.origlen
    }

    fn payload(&self) -> &[u8] {
        todo!()
    }
}
