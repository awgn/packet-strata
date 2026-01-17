use ahash::RandomState;
use hashlink::LinkedHashMap;

pub mod direction;
pub mod process;
pub mod flow;
pub mod tuple;
pub mod vni;

/// Trait for types that have an intrinsic timestamp
pub trait Trackable {
    type Timestamp: PartialOrd + Clone;

    fn timestamp(&self) -> Self::Timestamp;
    fn set_timestamp(&mut self, ts: Self::Timestamp);
}

/// Flow tracker for types that have an intrinsic timestamp (via Timestamped trait)
/// This avoids timestamp duplication in memory.
pub struct Tracker<K, V: Trackable> {
    lru: LinkedHashMap<K, V, RandomState>,
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

    #[inline]
    pub fn get_or_insert_with<F>(&mut self, key: &K, create: F) -> &mut V
    where
        F: FnOnce() -> V,
    {
        if self.lru.contains_key(key) {
            self.lru.to_back(key).unwrap()
        } else {
            self.lru.entry(key.clone()).or_insert_with(create)
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

    /// Get the timestamp of an entry
    #[inline]
    pub fn get_timestamp(&self, key: &K) -> Option<V::Timestamp> {
        self.lru.get(key).map(|v| v.timestamp())
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

        fn timestamp(&self) -> u64 {
            self.timestamp
        }

        fn set_timestamp(&mut self, ts: u64) {
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
        assert!(tracker.get_timestamp(&1).is_none());
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
}
