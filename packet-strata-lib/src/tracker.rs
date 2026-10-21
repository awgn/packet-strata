use ahash::RandomState;
use hashlink::linked_hash_map::RawEntryMut;
use hashlink::LinkedHashMap;

use crate::{
    metadata::PacketMetadata,
    packet::Packet,
    tracker::{
        direction::PacketDirection,
        flow::{Flow, FlowEth, FlowIpV4, FlowIpV6},
        process::Process,
        tuple::{Symmetric, Tuple, TupleEth, TupleV4, TupleV6},
        vni::VniMapper,
    },
};

pub mod direction;
pub mod flow;
pub mod process;
pub mod tuple;
pub mod vni;

/// Type alias for a symmetric IPv4 flow tracker.
pub type FlowTrackerV4<D = ()> = Tracker<Symmetric<TupleV4>, FlowIpV4<D>>;

/// Type alias for a symmetric IPv6 flow tracker.
pub type FlowTrackerV6<D = ()> = Tracker<Symmetric<TupleV6>, FlowIpV6<D>>;

/// Type alias for a symmetric Ethernet (L2) flow tracker.
pub type FlowTrackerEth<D = ()> = Tracker<Symmetric<TupleEth>, FlowEth<D>>;

/// Trait for types that have intrinsic first-seen and last-seen timestamps
pub trait Trackable {
    type Timestamp: PartialOrd + Clone;
    fn first_seen(&self) -> Self::Timestamp;
    fn last_seen(&self) -> Self::Timestamp;
    fn set_last_seen(&mut self, ts: Self::Timestamp);
}

/// Flow tracker for types that have an intrinsic timestamp (via Trackable trait)
pub struct Tracker<K, V: Trackable> {
    lru: LinkedHashMap<K, V, RandomState>,
}

impl<K, V> Default for Tracker<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Trackable,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Tracker<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Trackable,
{
    #[inline]
    pub fn new() -> Self {
        Tracker {
            lru: LinkedHashMap::with_hasher(RandomState::new()),
        }
    }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Tracker {
            lru: LinkedHashMap::with_capacity_and_hasher(capacity, RandomState::new()),
        }
    }

    #[inline(always)]
    pub fn get_or_insert_with<F>(&mut self, key: &K, create: F) -> &mut V
    where
        F: FnOnce() -> V,
    {
        let hash = self.lru.hasher().hash_one(key);
        match self.lru.raw_entry_mut().from_key_hashed_nocheck(hash, key) {
            RawEntryMut::Occupied(mut occupied) => {
                occupied.to_back();
                occupied.into_mut()
            }
            RawEntryMut::Vacant(vacant) => {
                vacant.insert_hashed_nocheck(hash, key.clone(), create()).1
            }
        }
    }

    /// Evict entries based on a predicate function, in lru order
    pub fn process_and_evict<F>(&mut self, mut process: F) -> usize
    where
        F: FnMut(&K, &V) -> bool, // true: evict, false: keep and interrupt
    {
        let mut evicted = 0;
        loop {
            match self.lru.front() {
                Some((k, v)) if process(k, v) => {
                    self.lru.pop_front(); // evict and continue
                    evicted += 1;
                }
                _ => break,
            }
        }
        evicted
    }

    /// Evicts all entries from the front (oldest) whose `last_seen() <= max_last_seen`,
    /// passing ownership of each evicted `(K, V)` pair to `on_evict`.
    ///
    /// Stops at the first entry with `last_seen() > max_last_seen` since entries are
    /// ordered by last-seen timestamp in the LRU queue.
    pub fn evict_expired<F>(&mut self, max_last_seen: V::Timestamp, mut on_evict: F) -> usize
    where
        F: FnMut(K, V),
    {
        let mut evicted = 0;
        while let Some((_, v)) = self.lru.front() {
            if v.last_seen() <= max_last_seen {
                if let Some((k, v)) = self.lru.pop_front() {
                    on_evict(k, v);
                    evicted += 1;
                }
            } else {
                break;
            }
        }
        evicted
    }

    /// Drains and evicts all remaining entries in LRU order (from oldest to newest),
    /// passing ownership of each `(K, V)` pair to `on_evict`.
    pub fn drain_all<F>(&mut self, mut on_evict: F) -> usize
    where
        F: FnMut(K, V),
    {
        let mut evicted = 0;
        while let Some((k, v)) = self.lru.pop_front() {
            on_evict(k, v);
            evicted += 1;
        }
        evicted
    }

    /// Get the front (oldest) entry without removing it
    #[inline]
    pub fn front(&self) -> Option<(&K, &V)> {
        self.lru.front()
    }

    /// Get the back (newest) entry without removing it
    #[inline]
    pub fn back(&self) -> Option<(&K, &V)> {
        self.lru.back()
    }

    /// Remove and return the front (oldest) entry
    #[inline]
    pub fn pop_front(&mut self) -> Option<(K, V)> {
        self.lru.pop_front()
    }

    /// Remove and return the back (newest) entry
    #[inline]
    pub fn pop_back(&mut self) -> Option<(K, V)> {
        self.lru.pop_back()
    }

    /// Remove a specific entry by key
    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.lru.remove(key)
    }

    /// Get the first-seen timestamp of an entry
    #[inline]
    pub fn get_first_seen(&self, key: &K) -> Option<V::Timestamp> {
        self.lru.get(key).map(|v| v.first_seen())
    }

    /// Get the last-seen timestamp of an entry
    #[inline]
    pub fn get_last_seen(&self, key: &K) -> Option<V::Timestamp> {
        self.lru.get(key).map(|v| v.last_seen())
    }

    /// Get a reference to the value
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.lru.get(key)
    }

    /// Get a mutable reference to the value
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.lru.get_mut(key)
    }

    /// Iterator over entries (from oldest to newest)
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.lru.iter()
    }

    /// Mutable iterator over entries (from oldest to newest)
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.lru.iter_mut()
    }

    /// Iterator over keys (from oldest to newest)
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.lru.keys()
    }

    /// Iterator over values (from oldest to newest)
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.lru.values()
    }

    /// Mutable iterator over values (from oldest to newest)
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.lru.values_mut()
    }

    /// Number of entries
    #[inline]
    pub fn len(&self) -> usize {
        self.lru.len()
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.lru.is_empty()
    }
}

impl<T, D> Tracker<Symmetric<T>, Flow<T, D>>
where
    T: Tuple + Default + Clone + Sized,
    Symmetric<T>: Eq + std::hash::Hash + Clone,
    D: Default + Process,
{
    /// Extracts the tuple from `pkt`, looks up or creates the corresponding `Flow<T, D>`
    /// (Phase 1), updates its counters and invokes `D::process` (Phase 2), and returns
    /// a mutable reference to the flow along with the packet's `PacketDirection`.
    ///
    /// On the first packet of a flow, direction inference is computed only once and reused
    /// for both flow creation and metric updates.
    ///
    /// Returns `None` if `pkt` does not match the tuple's layer (e.g. non-IPv4 packet on `FlowTrackerV4`).
    #[inline(always)]
    pub fn track_packet<Meta: PacketMetadata>(
        &mut self,
        meta: &Meta,
        pkt: &Packet<'_>,
        vni_mapper: &mut VniMapper,
    ) -> Option<(&mut Flow<T, D>, PacketDirection)> {
        let tuple = T::from_packet(pkt, vni_mapper)?;
        let key = Symmetric(tuple.clone());
        let hash = self.lru.hasher().hash_one(&key);
        match self.lru.raw_entry_mut().from_key_hashed_nocheck(hash, &key) {
            RawEntryMut::Occupied(mut occupied) => {
                occupied.to_back();
                let flow = occupied.into_mut();
                let dir = flow.update(meta, pkt);
                Some((flow, dir))
            }
            RawEntryMut::Vacant(vacant) => {
                let (new_flow, initial_dir) = Flow::new_with_dir(meta.timestamp(), tuple, pkt);
                let flow = vacant.insert_hashed_nocheck(hash, key, new_flow).1;
                let dir = flow.update_with_dir(meta, pkt, initial_dir);
                Some((flow, dir))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct FlowData {
        timestamp: u64,
        bytes: u64,
        packets: u32,
    }

    impl Trackable for FlowData {
        type Timestamp = u64;

        fn first_seen(&self) -> u64 {
            self.timestamp
        }

        fn last_seen(&self) -> u64 {
            self.timestamp
        }

        fn set_last_seen(&mut self, ts: u64) {
            self.timestamp = ts;
        }
    }

    #[test]
    fn test_basic_insertion() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        // Insert items with data that already contains timestamp
        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        assert_eq!(tracker.len(), 3);

        // Verify we can access the data
        let flow1 = tracker.get(&1).unwrap();
        assert_eq!(flow1.timestamp, 100);
        assert_eq!(flow1.bytes, 1000);
    }

    #[test]
    fn test_lru_behavior() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        // Check initial order: front -> back (oldest -> newest)
        let keys: Vec<_> = tracker.lru.keys().copied().collect();
        println!("After inserts: {:?}", keys);
        assert_eq!(keys, vec![1, 2, 3]);

        // Access key 1 - moves it to back
        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 400,
            bytes: 1000,
            packets: 10,
        });

        // Verify item moved to back (timestamp unchanged since entry existed)
        let keys: Vec<_> = tracker.lru.keys().copied().collect();
        println!("After accessing 1: {:?}", keys);
        assert_eq!(keys, vec![2, 3, 1]); // 1 moved to back as most recent

        // Verify front is oldest (2) and back is newest (1)
        assert_eq!(tracker.lru.front().map(|(k, _)| *k), Some(2));
        assert_eq!(tracker.lru.back().map(|(k, _)| *k), Some(1));
    }

    #[test]
    fn test_iteration_order() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        // Iterator goes from front (oldest) to back (newest)
        let keys: Vec<_> = tracker.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![1, 2, 3]);

        // Verify timestamps are in order
        let timestamps: Vec<_> = tracker.iter().map(|(_, v)| v.timestamp).collect();
        assert_eq!(timestamps, vec![100, 200, 300]);
    }

    #[test]
    fn test_get_or_insert_with() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        // Insert with closure
        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });

        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.get(&1).unwrap().bytes, 1000);

        // Access existing entry (closure should not be called)
        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 200,
            bytes: 9999,
            packets: 99,
        });

        // Value should not change, but entry moves to back
        assert_eq!(tracker.get(&1).unwrap().bytes, 1000);
    }

    #[test]
    fn test_empty_tracker() {
        let tracker = Tracker::<i32, FlowData>::new();

        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
        assert!(tracker.get(&1).is_none());
        assert!(tracker.get_first_seen(&1).is_none());
        assert!(tracker.get_last_seen(&1).is_none());
    }

    #[test]
    fn test_process_and_evict_basic() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });
        tracker.get_or_insert_with(&4, || FlowData {
            timestamp: 400,
            bytes: 4000,
            packets: 40,
        });

        // Evict entries with timestamp < 250
        let threshold = 250;
        let evicted = tracker.process_and_evict(|_key, value| {
            value.timestamp < threshold // true = evict, false = keep + stop
        });

        assert_eq!(evicted, 2); // Evicted entries 1 and 2
        assert_eq!(tracker.len(), 2); // Entries 3 and 4 remain

        assert!(tracker.get(&1).is_none());
        assert!(tracker.get(&2).is_none());
        assert!(tracker.get(&3).is_some());
        assert!(tracker.get(&4).is_some());
    }

    #[test]
    fn test_process_and_evict_with_keep() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });
        tracker.get_or_insert_with(&4, || FlowData {
            timestamp: 400,
            bytes: 4000,
            packets: 40,
        });

        // With new API: false = keep + stop, so we stop at entry 1 if we want to keep it
        // This test now verifies that returning false stops iteration immediately
        let threshold = 250;
        let evicted = tracker.process_and_evict(|_key, value| {
            value.timestamp < threshold // true = evict, false = keep + stop
        });

        assert_eq!(evicted, 2); // Entries 1 and 2 evicted (both < 250)
        assert_eq!(tracker.len(), 2); // Entries 3 and 4 remain

        assert!(tracker.get(&1).is_none());
        assert!(tracker.get(&2).is_none());
        assert!(tracker.get(&3).is_some());
        assert!(tracker.get(&4).is_some());
    }

    #[test]
    fn test_process_and_evict_stop_early() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });
        tracker.get_or_insert_with(&4, || FlowData {
            timestamp: 400,
            bytes: 4000,
            packets: 40,
        });

        // Process and evict, stop at first entry >= threshold
        let mut inspected = Vec::new();
        let threshold = 250;
        let evicted = tracker.process_and_evict(|key, value| {
            inspected.push(*key);
            value.timestamp < threshold // true = evict, false = keep + stop
        });

        assert_eq!(evicted, 2); // Evicted entries 1 and 2
        assert_eq!(inspected, vec![1, 2, 3]); // Inspected 1, 2, and 3 (stopped at 3)
        assert_eq!(tracker.len(), 2); // Entries 3 and 4 remain (3 was not consumed)

        assert!(tracker.get(&1).is_none());
        assert!(tracker.get(&2).is_none());
        assert!(tracker.get(&3).is_some()); // Entry 3 remains (not consumed)
        assert!(tracker.get(&4).is_some());
    }

    #[test]
    fn test_process_and_evict_with_accumulation() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });
        tracker.get_or_insert_with(&4, || FlowData {
            timestamp: 400,
            bytes: 4000,
            packets: 40,
        });

        // Accumulate stats from entries before eviction
        let mut total_bytes_evicted = 0u64;
        let threshold = 250;

        let evicted = tracker.process_and_evict(|_key, value| {
            if value.timestamp < threshold {
                total_bytes_evicted += value.bytes;
                true // evict
            } else {
                false // keep + stop
            }
        });

        assert_eq!(evicted, 2);
        assert_eq!(total_bytes_evicted, 3000); // 1000 + 2000
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn test_front_back_access() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        // Empty tracker
        assert!(tracker.front().is_none());
        assert!(tracker.back().is_none());

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        // Front is oldest
        assert_eq!(tracker.front().map(|(k, _)| *k), Some(1));
        assert_eq!(tracker.front().map(|(_, v)| v.timestamp), Some(100));

        // Back is newest
        assert_eq!(tracker.back().map(|(k, _)| *k), Some(3));
        assert_eq!(tracker.back().map(|(_, v)| v.timestamp), Some(300));
    }

    #[test]
    fn test_pop_operations() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        // Pop front (oldest)
        let (k, v) = tracker.pop_front().unwrap();
        assert_eq!(k, 1);
        assert_eq!(v.timestamp, 100);
        assert_eq!(tracker.len(), 2);

        // Pop back (newest)
        let (k, v) = tracker.pop_back().unwrap();
        assert_eq!(k, 3);
        assert_eq!(v.timestamp, 300);
        assert_eq!(tracker.len(), 1);

        // Only item 2 remains
        assert_eq!(tracker.front().map(|(k, _)| *k), Some(2));
    }

    #[test]
    fn test_iterator_methods() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        // Keys iterator
        let keys: Vec<_> = tracker.keys().copied().collect();
        assert_eq!(keys, vec![1, 2, 3]);

        // Values iterator
        let bytes: Vec<_> = tracker.values().map(|v| v.bytes).collect();
        assert_eq!(bytes, vec![1000, 2000, 3000]);

        // Mutable values iterator
        for value in tracker.values_mut() {
            value.bytes *= 2;
        }
        let bytes: Vec<_> = tracker.values().map(|v| v.bytes).collect();
        assert_eq!(bytes, vec![2000, 4000, 6000]);
    }

    #[test]
    fn test_remove() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        // Remove middle entry
        let removed = tracker.remove(&2).unwrap();
        assert_eq!(removed.bytes, 2000);
        assert_eq!(tracker.len(), 2);

        // Verify order preserved
        let keys: Vec<_> = tracker.keys().copied().collect();
        assert_eq!(keys, vec![1, 3]);

        // Remove non-existent
        assert!(tracker.remove(&99).is_none());
    }

    #[test]
    fn test_manual_eviction_pattern() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });
        tracker.get_or_insert_with(&4, || FlowData {
            timestamp: 400,
            bytes: 4000,
            packets: 40,
        });

        // Manual eviction: iterate and pop old entries
        let threshold = 250u64;
        let mut evicted = Vec::new();

        while let Some((_, v)) = tracker.front() {
            if v.timestamp < threshold {
                let (k, v) = tracker.pop_front().unwrap();
                evicted.push((k, v));
            } else {
                break;
            }
        }

        assert_eq!(evicted.len(), 2);
        assert_eq!(evicted[0].0, 1);
        assert_eq!(evicted[1].0, 2);
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn test_evict_expired_and_drain_all() {
        let mut tracker = Tracker::<i32, FlowData>::with_capacity(10);

        tracker.get_or_insert_with(&1, || FlowData {
            timestamp: 100,
            bytes: 1000,
            packets: 10,
        });
        tracker.get_or_insert_with(&2, || FlowData {
            timestamp: 200,
            bytes: 2000,
            packets: 20,
        });
        tracker.get_or_insert_with(&3, || FlowData {
            timestamp: 300,
            bytes: 3000,
            packets: 30,
        });

        let mut expired = Vec::new();
        let count = tracker.evict_expired(200, |k, v| {
            expired.push((k, v.bytes));
        });
        assert_eq!(count, 2);
        assert_eq!(expired, vec![(1, 1000), (2, 2000)]);
        assert_eq!(tracker.len(), 1);

        let mut remaining = Vec::new();
        let drained = tracker.drain_all(|k, v| {
            remaining.push((k, v.bytes));
        });
        assert_eq!(drained, 1);
        assert_eq!(remaining, vec![(3, 3000)]);
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_flow_tracker_v4_track_packet() {
        use crate::packet::{iter::LinkType, Packet, ParseMode};
        use crate::timestamp::Timestamp;

        struct DummyMeta<'a> {
            ts: Timestamp,
            raw: &'a [u8],
        }
        impl PacketMetadata for DummyMeta<'_> {
            fn timestamp(&self) -> Timestamp {
                self.ts
            }
            fn caplen(&self) -> u32 {
                self.raw.len() as u32
            }
            fn origlen(&self) -> u32 {
                self.raw.len() as u32
            }
            fn data(&self) -> &[u8] {
                self.raw
            }
        }

        // Build minimal Ethernet + IPv4 + UDP packet (10.0.0.1:50000 -> 1.1.1.1:53)
        let mut buf = Vec::with_capacity(14 + 20 + 8 + 4);
        buf.extend_from_slice(&[0x00, 0x00, 0x0C, 0x11, 0x22, 0x33]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x44, 0x55, 0x66]);
        buf.extend_from_slice(&[0x08, 0x00]);
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&32u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.push(64);
        buf.push(17); // UDP
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&[1, 1, 1, 1]);
        buf.extend_from_slice(&50000u16.to_be_bytes());
        buf.extend_from_slice(&53u16.to_be_bytes());
        buf.extend_from_slice(&12u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(b"ping");

        let pkt = Packet::from_bytes(&buf, LinkType::Ethernet, ParseMode::Innermost).unwrap();
        let meta = DummyMeta {
            ts: Timestamp::from_nanos(1_000),
            raw: &buf,
        };

        let mut tracker: FlowTrackerV4 = FlowTrackerV4::with_capacity(16);
        let mut vni_mapper = VniMapper::new();

        let (flow, dir) = tracker.track_packet(&meta, &pkt, &mut vni_mapper).unwrap();
        assert_eq!(dir, PacketDirection::Upwards);
        assert_eq!(flow.base.metrics.u_pkts, 1);
        assert_eq!(flow.base.metrics.d_pkts, 0);
        assert_eq!(flow.base.id.tuple.src_port, 50000);
        assert_eq!(flow.base.id.tuple.dst_port, 53);
    }
}
