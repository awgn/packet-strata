use std::{fmt::Display, sync::atomic::AtomicU64};

/// Thread-local packet counters for high-performance counting
///
/// These counters avoid atomic operations on every packet by accumulating
/// counts locally and periodically flushing to the shared `Stats` struct.
///
/// # Usage
///
/// ```ignore
/// let stats = Arc::new(Stats::default());
/// let mut local = LocalStats::new();
///
/// for packet in packets {
///     local.total_packets += 1;
///     // ... classify and count ...
///     
///     // Flush every N packets
///     if local.total_packets % 1024 == 0 {
///         local.flush(&stats);
///     }
/// }
/// // Final flush
/// local.flush(&stats);
/// ```
#[derive(Default, Debug, Clone)]
pub struct LocalStats {
    // General statistics
    pub total_packets: u64,
    pub total_bytes: u64,

    // Error statistics
    pub too_small: u64,
    pub invalid: u64,
    pub insufficient_len: u64,
    pub other_errors: u64,

    // Link layer
    pub ethernet: u64,
    pub sll: u64,
    pub sllv2: u64,
    pub null: u64,
    pub vlan: u64,

    // Network layer
    pub ipv4: u64,
    pub ipv6: u64,
    pub arp: u64,

    // Transport layer
    pub tcp: u64,
    pub udp: u64,
    pub sctp: u64,
    pub icmp: u64,
    pub icmpv6: u64,

    // Tunnel protocols
    pub vxlan: u64,
    pub geneve: u64,
    pub gre: u64,
    pub nvgre: u64,
    pub mpls: u64,
    pub teredo: u64,
    pub gtpv1: u64,
    pub gtpv2: u64,
    pub l2tpv2: u64,
    pub l2tpv3: u64,
    pub pbb: u64,
    pub stt: u64,
    pub pptp: u64,
    // IP-in-IP tunnels
    pub ipip: u64,
    pub sit: u64,
    pub ip4in6: u64,
    pub ip6tnl: u64,

    // Unknown/unsupported protocols
    pub unknown_ether_proto: u64,
    pub unknown_ip_proto: u64,
    pub unknown_other: u64,
}

impl LocalStats {
    /// Create a new empty local stats instance
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Flush all local counters to the shared atomic stats
    ///
    /// This performs atomic additions for all non-zero counters and
    /// resets the local counters to zero.
    #[inline]
    pub fn flush(&mut self, stats: &Stats) {
        macro_rules! flush_counter {
            ($field:ident) => {
                if self.$field > 0 {
                    stats
                        .$field
                        .fetch_add(self.$field, std::sync::atomic::Ordering::Relaxed);
                    self.$field = 0;
                }
            };
        }

        flush_counter!(total_packets);
        flush_counter!(total_bytes);
        flush_counter!(too_small);
        flush_counter!(invalid);
        flush_counter!(insufficient_len);
        flush_counter!(other_errors);
        flush_counter!(ethernet);
        flush_counter!(sll);
        flush_counter!(sllv2);
        flush_counter!(null);
        flush_counter!(vlan);
        flush_counter!(ipv4);
        flush_counter!(ipv6);
        flush_counter!(arp);
        flush_counter!(tcp);
        flush_counter!(udp);
        flush_counter!(sctp);
        flush_counter!(icmp);
        flush_counter!(icmpv6);
        flush_counter!(vxlan);
        flush_counter!(geneve);
        flush_counter!(gre);
        flush_counter!(nvgre);
        flush_counter!(mpls);
        flush_counter!(teredo);
        flush_counter!(gtpv1);
        flush_counter!(gtpv2);
        flush_counter!(l2tpv2);
        flush_counter!(l2tpv3);
        flush_counter!(pbb);
        flush_counter!(stt);
        flush_counter!(pptp);
        flush_counter!(ipip);
        flush_counter!(sit);
        flush_counter!(ip4in6);
        flush_counter!(ip6tnl);
        flush_counter!(unknown_ether_proto);
        flush_counter!(unknown_ip_proto);
        flush_counter!(unknown_other);
    }

    /// Check if it's time to flush based on packet count
    ///
    /// Returns true every `interval` packets. Common values:
    /// - 1024: Good balance for high-throughput scenarios
    /// - 256: More frequent updates, slightly more overhead
    /// - 4096: Less overhead, but stats update less frequently
    #[inline]
    pub fn should_flush(&self, interval: u64) -> bool {
        self.total_packets & (interval - 1) == 0
    }
}

/// Flush interval for local stats (must be power of 2)
pub const FLUSH_INTERVAL: u64 = 1024;

#[derive(Default, Debug)]
pub struct Stats {
    // General statistics
    pub total_packets: AtomicU64,
    pub total_bytes: AtomicU64,

    // Error statistics
    pub too_small: AtomicU64,
    pub invalid: AtomicU64,
    pub insufficient_len: AtomicU64,
    pub other_errors: AtomicU64,

    // Link layer
    pub ethernet: AtomicU64,
    pub sll: AtomicU64,
    pub sllv2: AtomicU64,
    pub null: AtomicU64,
    pub vlan: AtomicU64,

    // Network layer
    pub ipv4: AtomicU64,
    pub ipv6: AtomicU64,
    pub arp: AtomicU64,

    // Transport layer
    pub tcp: AtomicU64,
    pub udp: AtomicU64,
    pub sctp: AtomicU64,
    pub icmp: AtomicU64,
    pub icmpv6: AtomicU64,

    // Tunnel protocols
    pub vxlan: AtomicU64,
    pub geneve: AtomicU64,
    pub gre: AtomicU64,
    pub nvgre: AtomicU64,
    pub mpls: AtomicU64,
    pub teredo: AtomicU64,
    pub gtpv1: AtomicU64,
    pub gtpv2: AtomicU64,
    pub l2tpv2: AtomicU64,
    pub l2tpv3: AtomicU64,
    pub pbb: AtomicU64,
    pub stt: AtomicU64,
    pub pptp: AtomicU64,
    // IP-in-IP tunnels
    pub ipip: AtomicU64,
    pub sit: AtomicU64,
    pub ip4in6: AtomicU64,
    pub ip6tnl: AtomicU64,

    // Unknown/unsupported protocols
    pub unknown_ether_proto: AtomicU64,
    pub unknown_ip_proto: AtomicU64,
    pub unknown_other: AtomicU64,
}

impl Stats {
    /// Increment a counter by 1 using relaxed ordering
    #[inline]
    #[allow(dead_code)]
    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Add a value to a counter using relaxed ordering
    #[inline]
    #[allow(dead_code)]
    pub fn add(&self, counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the value of a counter using relaxed ordering
    #[inline]
    fn get(&self, counter: &AtomicU64) -> u64 {
        counter.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total tunnel packets
    pub fn total_tunnels(&self) -> u64 {
        self.get(&self.vxlan)
            + self.get(&self.geneve)
            + self.get(&self.gre)
            + self.get(&self.nvgre)
            + self.get(&self.mpls)
            + self.get(&self.teredo)
            + self.get(&self.gtpv1)
            + self.get(&self.gtpv2)
            + self.get(&self.l2tpv2)
            + self.get(&self.l2tpv3)
            + self.get(&self.pbb)
            + self.get(&self.stt)
            + self.get(&self.pptp)
            + self.get(&self.ipip)
            + self.get(&self.sit)
            + self.get(&self.ip4in6)
            + self.get(&self.ip6tnl)
    }

    /// Get total unknown/unsupported protocol encounters
    pub fn total_unknown(&self) -> u64 {
        self.get(&self.unknown_ether_proto)
            + self.get(&self.unknown_ip_proto)
            + self.get(&self.unknown_other)
    }

    /// Get total errors
    pub fn total_errors(&self) -> u64 {
        self.get(&self.too_small)
            + self.get(&self.invalid)
            + self.get(&self.insufficient_len)
            + self.get(&self.other_errors)
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Packet Statistics ===")?;
        writeln!(f)?;

        // General
        writeln!(f, "--- General ---")?;
        writeln!(
            f,
            "Total packets processed: {}",
            self.get(&self.total_packets)
        )?;
        writeln!(f, "Total bytes processed: {}", self.get(&self.total_bytes))?;
        writeln!(f)?;

        // Errors
        writeln!(f, "--- Errors ---")?;
        writeln!(f, "Total errors: {}", self.total_errors())?;
        writeln!(f, "  Too small: {}", self.get(&self.too_small))?;
        writeln!(f, "  Invalid: {}", self.get(&self.invalid))?;
        writeln!(
            f,
            "  Insufficient length: {}",
            self.get(&self.insufficient_len)
        )?;
        writeln!(f, "  Other errors: {}", self.get(&self.other_errors))?;
        writeln!(f)?;

        // Link layer
        writeln!(f, "--- Link Layer ---")?;
        writeln!(f, "Ethernet: {}", self.get(&self.ethernet))?;
        writeln!(f, "SLL (Linux cooked): {}", self.get(&self.sll))?;
        writeln!(f, "SLLv2: {}", self.get(&self.sllv2))?;
        writeln!(f, "Null/Loopback: {}", self.get(&self.null))?;
        writeln!(f, "VLAN tagged: {}", self.get(&self.vlan))?;
        writeln!(f)?;

        // Network layer
        writeln!(f, "--- Network Layer ---")?;
        writeln!(f, "IPv4: {}", self.get(&self.ipv4))?;
        writeln!(f, "IPv6: {}", self.get(&self.ipv6))?;
        writeln!(f, "ARP: {}", self.get(&self.arp))?;
        writeln!(f)?;

        // Transport layer
        writeln!(f, "--- Transport Layer ---")?;
        writeln!(f, "TCP: {}", self.get(&self.tcp))?;
        writeln!(f, "UDP: {}", self.get(&self.udp))?;
        writeln!(f, "SCTP: {}", self.get(&self.sctp))?;
        writeln!(f, "ICMP: {}", self.get(&self.icmp))?;
        writeln!(f, "ICMPv6: {}", self.get(&self.icmpv6))?;
        writeln!(f)?;

        // Tunnels
        let total_tunnels = self.total_tunnels();
        if total_tunnels > 0 {
            writeln!(f, "--- Tunnel Protocols ---")?;
            writeln!(f, "Total tunneled packets: {}", total_tunnels)?;
            if self.get(&self.vxlan) > 0 {
                writeln!(f, "  VXLAN: {}", self.get(&self.vxlan))?;
            }
            if self.get(&self.geneve) > 0 {
                writeln!(f, "  Geneve: {}", self.get(&self.geneve))?;
            }
            if self.get(&self.gre) > 0 {
                writeln!(f, "  GRE: {}", self.get(&self.gre))?;
            }
            if self.get(&self.nvgre) > 0 {
                writeln!(f, "  NVGRE: {}", self.get(&self.nvgre))?;
            }
            if self.get(&self.mpls) > 0 {
                writeln!(f, "  MPLS: {}", self.get(&self.mpls))?;
            }
            if self.get(&self.teredo) > 0 {
                writeln!(f, "  Teredo: {}", self.get(&self.teredo))?;
            }
            if self.get(&self.gtpv1) > 0 {
                writeln!(f, "  GTPv1: {}", self.get(&self.gtpv1))?;
            }
            if self.get(&self.gtpv2) > 0 {
                writeln!(f, "  GTPv2: {}", self.get(&self.gtpv2))?;
            }
            if self.get(&self.l2tpv2) > 0 {
                writeln!(f, "  L2TPv2: {}", self.get(&self.l2tpv2))?;
            }
            if self.get(&self.l2tpv3) > 0 {
                writeln!(f, "  L2TPv3: {}", self.get(&self.l2tpv3))?;
            }
            if self.get(&self.pbb) > 0 {
                writeln!(f, "  PBB: {}", self.get(&self.pbb))?;
            }
            if self.get(&self.stt) > 0 {
                writeln!(f, "  STT: {}", self.get(&self.stt))?;
            }
            if self.get(&self.pptp) > 0 {
                writeln!(f, "  PPTP: {}", self.get(&self.pptp))?;
            }
            if self.get(&self.ipip) > 0 {
                writeln!(f, "  IPIP (IPv4-in-IPv4): {}", self.get(&self.ipip))?;
            }
            if self.get(&self.sit) > 0 {
                writeln!(f, "  SIT (IPv6-in-IPv4): {}", self.get(&self.sit))?;
            }
            if self.get(&self.ip4in6) > 0 {
                writeln!(f, "  IP4in6 (IPv4-in-IPv6): {}", self.get(&self.ip4in6))?;
            }
            if self.get(&self.ip6tnl) > 0 {
                writeln!(f, "  IP6Tnl (IPv6-in-IPv6): {}", self.get(&self.ip6tnl))?;
            }
            writeln!(f)?;
        }

        // Unknown/unsupported
        let total_unknown = self.total_unknown();
        if total_unknown > 0 {
            writeln!(f, "--- Unknown/Unsupported Protocols ---")?;
            writeln!(f, "Total unknown: {}", total_unknown)?;
            if self.get(&self.unknown_ether_proto) > 0 {
                writeln!(
                    f,
                    "  Unknown EtherType: {}",
                    self.get(&self.unknown_ether_proto)
                )?;
            }
            if self.get(&self.unknown_ip_proto) > 0 {
                writeln!(
                    f,
                    "  Unknown IP protocol: {}",
                    self.get(&self.unknown_ip_proto)
                )?;
            }
            if self.get(&self.unknown_other) > 0 {
                writeln!(f, "  Other unknown: {}", self.get(&self.unknown_other))?;
            }
        }

        Ok(())
    }
}
