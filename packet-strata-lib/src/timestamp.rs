use chrono::{DateTime};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    ops::{Add, Div, Mul, Sub},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Timestamp(pub u64); // Nanoseconds since epoch

impl Timestamp {
    pub const ZERO: Self = Timestamp(0);

    #[inline]
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    #[inline]
    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    pub fn as_secs_f64(&self) -> f64 {
        self.0 as f64 / 1_000_000_000.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(date_time) = DateTime::from_timestamp(
            (self.0 / 1_000_000_000) as i64,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Interval(pub i64); // Signed nanoseconds

impl Interval {
    pub const ZERO: Self = Interval(0);

    #[inline]
    pub fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    #[inline]
    pub fn as_nanos(&self) -> i64 {
        self.0
    }

    pub fn as_secs_f64(&self) -> f64 {
        self.0 as f64 / 1_000_000_000.0
    }

    pub fn abs(&self) -> Self {
        Self(self.0.abs())
    }
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_nanos = self.0.abs();
        let secs = total_nanos / 1_000_000_000;
        let nanos = total_nanos % 1_000_000_000;
        let sign = if self.0 < 0 { "-" } else { "" };
        write!(f, "{}{}.{:09}", sign, secs, nanos)
    }
}

// --- Timestamp Operations ---

impl Add<Interval> for Timestamp {
    type Output = Timestamp;
    #[inline]
    fn add(self, rhs: Interval) -> Self::Output {
        Timestamp(self.0.saturating_add_signed(rhs.0))
    }
}

impl Sub<Interval> for Timestamp {
    type Output = Timestamp;
    #[inline]
    fn sub(self, rhs: Interval) -> Self::Output {
        Timestamp(self.0.saturating_sub_signed(rhs.0))
    }
}

impl Sub for Timestamp {
    type Output = Interval;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        if self.0 >= rhs.0 {
            Interval((self.0 - rhs.0) as i64)
        } else {
            Interval(-((rhs.0 - self.0) as i64))
        }
    }
}

// --- Interval Operations ---

impl Add for Interval {
    type Output = Interval;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Interval(self.0.saturating_add(rhs.0))
    }
}

impl Sub for Interval {
    type Output = Interval;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Interval(self.0.saturating_sub(rhs.0))
    }
}

impl Mul<f64> for Interval {
    type Output = Interval;
    #[inline]
    fn mul(self, rhs: f64) -> Self::Output {
        Interval((self.0 as f64 * rhs) as i64)
    }
}

impl Div<i64> for Interval {
    type Output = Interval;
    #[inline]
    fn div(self, rhs: i64) -> Self::Output {
        Interval(self.0 / rhs)
    }
}

impl Add<Timestamp> for Interval {
    type Output = Timestamp;
    #[inline]
    fn add(self, rhs: Timestamp) -> Self::Output {
        rhs + self
    }
}
