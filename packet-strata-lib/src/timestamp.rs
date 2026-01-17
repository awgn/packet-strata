use std::fmt;
use chrono::DateTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timestamp(pub u64);

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(date_time) = DateTime::from_timestamp(
            self.0 as i64 / 1_000_000_000,
            (self.0 % 1_000_000_000) as u32,
        ) {
            if !f.alternate() {
                return write!(f, "{}", date_time.format("%Y-%m-%d %H:%M:%S%.6f UTC"));
            }
        }

        write!(
            f,
            "{}.{:09}",
            self.0 / 1_000_000_000,
            self.0 % 1_000_000_000
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nanoseconds(pub u64);

impl fmt::Display for Nanoseconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.0 / 1_000_000_000, self.0 % 1_000_000_000)
    }
}
