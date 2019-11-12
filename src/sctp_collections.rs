use std::borrow::Borrow;
use std::collections::{BTreeMap, VecDeque};
use std::ops::Bound::{Excluded, Included, Unbounded};

use sna::SerialNumber;

#[derive(Clone, Debug)]
pub struct SctpTsnQueue<V> {
    pub smallest_tsn: SerialNumber<u32>,
    array: VecDeque<V>,
}

impl<V> SctpTsnQueue<V> {
    pub fn new(sna: SerialNumber<u32>) -> Self {
        Self {
            smallest_tsn: sna,
            array: VecDeque::new(),
        }
    }

    pub fn append(&mut self, values: &mut VecDeque<V>) {
        self.array.append(values);
    }

    pub fn clear(&mut self) {
        self.array.clear();
    }

    pub fn drain(&mut self, start: u32, end: u32) -> std::collections::vec_deque::Drain<'_, V> {
        let start_index = if self.smallest_tsn.0 <= start {
            (start - self.smallest_tsn.0) as usize
        } else {
            (u32::max_value() - self.smallest_tsn.0 + 1 + start) as usize
        };
        let end_index = if self.smallest_tsn.0 <= end {
            (end - self.smallest_tsn.0) as usize
        } else {
            (u32::max_value() - self.smallest_tsn.0 + 1 + end) as usize
        };
        let drained = self
            .array
            .drain((Included(&start_index), Excluded(&end_index)));
        self.smallest_tsn = SerialNumber(end);
        drained
    }

    pub fn get(&self, tsn: u32) -> Option<&V> {
        let index = if self.smallest_tsn.0 <= tsn {
            (tsn - self.smallest_tsn.0) as usize
        } else {
            (u32::max_value() - self.smallest_tsn.0 + 1 + tsn) as usize
        };
        self.array.get(index)
    }

    pub fn get_mut(&mut self, tsn: u32) -> Option<&mut V> {
        let index = if self.smallest_tsn.0 <= tsn {
            (tsn - self.smallest_tsn.0) as usize
        } else {
            (u32::max_value() - self.smallest_tsn.0 + 1 + tsn) as usize
        };
        self.array.get_mut(index)
    }

    pub fn is_empty(&self) -> bool {
        self.array.is_empty()
    }

    pub fn iter(&self) -> SctpTsnQueueIter<'_, V> {
        SctpTsnQueueIter {
            array: self.array.iter().collect::<VecDeque<&'_ V>>(),
            index: self.smallest_tsn,
        }
    }

    pub fn iter_mut(&mut self) -> SctpTsnQueueIterMut<'_, V> {
        SctpTsnQueueIterMut {
            array: self.array.iter_mut().collect::<VecDeque<&'_ mut V>>(),
            index: self.smallest_tsn,
        }
    }

    pub fn pop(&mut self) -> Option<V> {
        let ret = self.array.pop_front();
        if ret.is_some() {
            self.smallest_tsn += 1;
        }
        ret
    }

    pub fn push(&mut self, value: V) {
        self.array.push_back(value);
    }
}

pub struct SctpTsnQueueIter<'a, V> {
    array: VecDeque<&'a V>,
    index: SerialNumber<u32>,
}

impl<'a, V> SctpTsnQueueIter<'a, V> {
    pub fn new(array: VecDeque<&'a V>, sna: SerialNumber<u32>) -> Self {
        Self {
            array: array,
            index: sna,
        }
    }

    pub fn append(&mut self, other: &mut VecDeque<&'a V>) {
        self.array.append(other);
    }
}

impl<'a, V> Iterator for SctpTsnQueueIter<'a, V> {
    type Item = (SerialNumber<u32>, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.array.pop_front();
        if ret.is_some() {
            let item = (self.index, ret.unwrap());
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

pub struct SctpTsnQueueIterMut<'a, V> {
    array: VecDeque<&'a mut V>,
    index: SerialNumber<u32>,
}

impl<'a, V> SctpTsnQueueIterMut<'a, V> {
    pub fn new(array: VecDeque<&'a mut V>, sna: SerialNumber<u32>) -> Self {
        Self {
            array: array,
            index: sna,
        }
    }

    pub fn append(&mut self, other: &mut VecDeque<&'a mut V>) {
        self.array.append(other);
    }
}

impl<'a, V> Iterator for SctpTsnQueueIterMut<'a, V> {
    type Item = (SerialNumber<u32>, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.array.pop_front();
        if ret.is_some() {
            let item = (self.index, ret.unwrap());
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

pub struct SctpTsnQueueIntoIter<V> {
    inner: SctpTsnQueue<V>,
    index: SerialNumber<u32>,
}

impl<V> IntoIterator for SctpTsnQueue<V> {
    type Item = (SerialNumber<u32>, V);
    type IntoIter = SctpTsnQueueIntoIter<V>;

    fn into_iter(self) -> SctpTsnQueueIntoIter<V> {
        let smallest_tsn = self.smallest_tsn;
        SctpTsnQueueIntoIter {
            inner: self,
            index: smallest_tsn,
        }
    }
}

impl<V> Iterator for SctpTsnQueueIntoIter<V> {
    type Item = (SerialNumber<u32>, V);

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.inner.pop();
        if ret.is_some() {
            let item = (self.index, ret.unwrap());
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

impl<'a, V> IntoIterator for &'a SctpTsnQueue<V> {
    type Item = (SerialNumber<u32>, &'a V);
    type IntoIter = SctpTsnQueueIter<'a, V>;

    fn into_iter(self) -> SctpTsnQueueIter<'a, V> {
        self.iter()
    }
}

impl<'a, V> IntoIterator for &'a mut SctpTsnQueue<V> {
    type Item = (SerialNumber<u32>, &'a mut V);
    type IntoIter = SctpTsnQueueIterMut<'a, V>;

    fn into_iter(self) -> SctpTsnQueueIterMut<'a, V> {
        self.iter_mut()
    }
}

#[derive(Clone, Debug)]
pub struct SctpBTreeMap<K, V> {
    lowest_sn: Option<SerialNumber<K>>,
    highest_sn: Option<SerialNumber<K>>,
    tree_map: BTreeMap<K, V>,
}

impl<K: Copy + Ord + PartialOrd<SerialNumber<K>>, V> SctpBTreeMap<K, V> {
    pub fn new() -> SctpBTreeMap<K, V> {
        SctpBTreeMap {
            lowest_sn: None,
            highest_sn: None,
            tree_map: BTreeMap::new(),
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.tree_map.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.tree_map.get_mut(key)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.lowest_sn.is_none() || key < self.lowest_sn.unwrap() {
            self.lowest_sn = Some(SerialNumber(key));
        }
        if self.highest_sn.is_none() || key > self.highest_sn.unwrap() {
            self.highest_sn = Some(SerialNumber(key));
        }
        self.tree_map.insert(key, value)
    }

    pub fn is_empty(&self) -> bool {
        self.tree_map.is_empty()
    }

    pub fn keys(&self) -> SctpBTreeMapKeys<'_, K> {
        let mut sctp_keyes = SctpBTreeMapKeys {
            array: VecDeque::new(),
        };
        if self.highest_sn.is_none() || self.lowest_sn.is_none() {
            return sctp_keyes;
        }
        let lowest_sn = self.lowest_sn.unwrap();
        let highest_sn = self.highest_sn.unwrap();
        if highest_sn.0 >= lowest_sn.0 {
            let range = self
                .tree_map
                .range((Included(&lowest_sn.0), Included(&highest_sn.0)));
            sctp_keyes.append(&mut range.map(|(k, _)| k).collect::<VecDeque<(&'_ K)>>());
        } else {
            let range = self.tree_map.range((Included(&lowest_sn.0), Unbounded));
            sctp_keyes.append(&mut range.map(|(k, _)| k).collect::<VecDeque<(&'_ K)>>());
            let range = self.tree_map.range((Unbounded, Included(&highest_sn.0)));
            sctp_keyes.append(&mut range.map(|(k, _)| k).collect::<VecDeque<(&'_ K)>>());
        }
        sctp_keyes
    }

    pub fn len(&self) -> usize {
        self.tree_map.len()
    }

    pub fn range(&self, start: Option<K>, end: Option<K>) -> SctpBTreeMapRange<'_, K, V> {
        let mut sctp_range = SctpBTreeMapRange {
            array: VecDeque::new(),
        };
        if self.lowest_sn.is_none()
            || self.highest_sn.is_none()
            || (start.is_some() && start.unwrap() < self.lowest_sn.unwrap())
            || (end.is_some() && end.unwrap() < self.lowest_sn.unwrap())
            || (start.is_some() && end.is_some() && start.unwrap() > SerialNumber(end.unwrap()))
        {
            return sctp_range;
        }
        let lowest_sn = self.lowest_sn.unwrap();
        let highest_sn = self.highest_sn.unwrap();
        let start = if start.is_some() {
            start.unwrap()
        } else {
            lowest_sn.0
        };
        let end = if end.is_some() {
            end.unwrap()
        } else {
            highest_sn.0
        };
        if end >= start {
            let range = self.tree_map.range((Included(&start), Included(&end)));
            sctp_range.append(&mut range.collect::<VecDeque<(&'_ K, &'_ V)>>());
        } else {
            let range = self.tree_map.range((Included(&start), Unbounded));
            sctp_range.append(&mut range.collect::<VecDeque<(&K, &'_ V)>>());
            let range = self.tree_map.range((Unbounded, Included(&end)));
            sctp_range.append(&mut range.collect::<VecDeque<(&K, &'_ V)>>());
        }
        sctp_range
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.tree_map.remove(key)
    }
}

#[derive(Clone, Debug)]
pub struct SctpBTreeMapKeys<'a, K> {
    array: VecDeque<&'a K>,
}

impl<'a, K> SctpBTreeMapKeys<'a, K> {
    pub fn append(&mut self, other: &mut VecDeque<&'a K>) {
        self.array.append(other);
    }
}

impl<'a, K> Iterator for SctpBTreeMapKeys<'a, K> {
    type Item = &'a K;

    fn next(&mut self) -> Option<Self::Item> {
        self.array.pop_front()
    }
}

impl<'a, K> DoubleEndedIterator for SctpBTreeMapKeys<'a, K> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.array.pop_back()
    }
}

#[derive(Clone, Debug)]
pub struct SctpBTreeMapRange<'a, K, V> {
    array: VecDeque<(&'a K, &'a V)>,
}

impl<'a, K, V> SctpBTreeMapRange<'a, K, V> {
    pub fn append(&mut self, other: &mut VecDeque<(&'a K, &'a V)>) {
        self.array.append(other);
    }
}

impl<'a, K, V> Iterator for SctpBTreeMapRange<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.array.pop_front()
    }
}

impl<'a, K, V> DoubleEndedIterator for SctpBTreeMapRange<'a, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.array.pop_back()
    }
}

#[test]
fn test_collections_tsn_queue() {
    let mut queue: SctpTsnQueue<(u32, bool)> = SctpTsnQueue::new(SerialNumber(0xffffffff));
    queue.push((0xffffffff, false)); // TSN: 0xffffffff
    queue.push((0x0, true)); // TSN: 0
    queue.push((0x1, false)); // TSN: 1
    queue.push((0x2, false)); // TSN: 2

    assert_eq!(queue.get(0x00), Some(&(0x00, true)));
    assert_eq!(queue.pop(), Some((0xffffffff, false)));
    assert_eq!(queue.get(0x00), Some(&(0x00, true)));
    let drained = queue.drain(0x00, 0x02).collect::<VecDeque<(u32, bool)>>();
    assert_eq!(drained, [(0x00, true), (0x01, false)]);
    assert_eq!(queue.get(0x02), Some(&(0x02, false)));
    assert_eq!(queue.pop(), Some((0x02, false)));
    assert_eq!(queue.is_empty(), true);
}

#[test]
fn test_collections_tsn_queue_iter() {
    let mut queue: SctpTsnQueue<(u32, bool)> = SctpTsnQueue::new(SerialNumber(0xffffffff));
    queue.push((0xffffffff, true)); // TSN: 0xffffffff
    queue.push((0x00, true)); // TSN: 1
    queue.push((0x01, true)); // TSN: 2

    let oks = queue
        .iter()
        .map(|(_, (_, ok))| *ok)
        .collect::<VecDeque<bool>>();
    assert_eq!(oks, [true, true, true]);

    for (sna, (_, ok)) in queue.iter_mut() {
        if sna.0 % 2 == 0 {
            *ok = false;
        }
    }
    let mut oks = queue
        .iter()
        .map(|(_, (_, ok))| *ok)
        .collect::<VecDeque<bool>>();
    assert_eq!(oks, [true, false, true]);

    let mut new_queue: SctpTsnQueue<bool> = SctpTsnQueue::new(SerialNumber(0xffffffff));
    new_queue.append(&mut oks);
    assert_eq!(new_queue.get(0xffffffff), Some(&true));
    assert_eq!(new_queue.get(0x00), Some(&false));
    assert_eq!(new_queue.get(0x01), Some(&true));

    for (sna, ok) in &new_queue {
        assert_eq!(*ok, if sna.0 % 2 == 0 { false } else { true });
    }

    for (_, ok) in &mut new_queue {
        *ok = false;
    }

    for (_, ok) in new_queue {
        assert_eq!(ok, false);
    }
}

#[test]
fn test_collections_btreemap() {
    let mut btree: SctpBTreeMap<u32, u32> = SctpBTreeMap::new();
    assert_eq!(btree.insert(0xffffffff, 0x31), None);
    let range = btree.range(None, None).collect::<Vec<(&u32, &u32)>>();
    assert_eq!(range, [(&0xffffffff, &0x31)]);
    let mut keys = btree.keys();
    assert_eq!(keys.next(), Some(&0xffffffff));
    assert_eq!(keys.next(), None);

    assert_eq!(btree.insert(0xffffffff, 0x31), Some(0x31));
    assert_eq!(btree.get(&0xffffffff), Some(&0x31));
    assert_eq!(btree.insert(0x00, 0x32), None);
    assert_eq!(btree.insert(0x01, 0x33), None);
    let mut keys = btree.keys();
    assert_eq!(keys.next(), Some(&0xffffffff));
    assert_eq!(keys.next(), Some(&0x00));
    assert_eq!(keys.next(), Some(&0x01));

    let range = btree
        .range(Some(0xffffffff), Some(0x02))
        .collect::<Vec<(&u32, &u32)>>();
    assert_eq!(
        range,
        [(&0xffffffff, &0x31), (&0x00, &0x32), (&0x01, &0x33)]
    );
    let range = btree
        .range(Some(0xffffffff), Some(0x00))
        .collect::<Vec<(&u32, &u32)>>();
    assert_eq!(range, [(&0xffffffff, &0x31), (&0x00, &0x32)]);
    let range = btree.range(Some(0x00), None).collect::<Vec<(&u32, &u32)>>();
    assert_eq!(range, [(&0x00, &0x32), (&0x01, &0x33)]);
    let range = btree
        .range(None, Some(0xffffffff))
        .collect::<Vec<(&u32, &u32)>>();
    assert_eq!(range, [(&0xffffffff, &0x31)]);
    let range = btree.range(None, None).collect::<Vec<(&u32, &u32)>>();
    assert_eq!(
        range,
        [(&0xffffffff, &0x31), (&0x00, &0x32), (&0x01, &0x33)]
    );
    assert_eq!(btree.len(), 3);
    assert_eq!(btree.remove(&0xffffffff), Some(0x31));
    assert_eq!(btree.len(), 2);
    let range = btree.range(None, None).collect::<Vec<(&u32, &u32)>>();
    assert_eq!(range, [(&0x00, &0x32), (&0x01, &0x33)]);
}
