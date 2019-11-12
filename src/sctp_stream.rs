use std::collections::VecDeque;

use sna::SerialNumber;

pub use crate::sctp_pkt::*;
use crate::Result;
use crate::SctpError;

#[derive(Debug, PartialEq)]
pub struct SctpStreamIn {
    pub stream_id: u16,
    next_seq: SerialNumber<u16>,
    waiting_ordered_queue: VecDeque<SctpDataMessage>,
    waiting_unordered_queue: VecDeque<SctpDataMessage>,
    readable_ordered_queue: VecDeque<SctpDataMessage>,
    readable_unordered_queue: VecDeque<SctpDataMessage>,
}

impl SctpStreamIn {
    pub fn new(strmid: u16) -> Self {
        SctpStreamIn {
            stream_id: strmid,
            next_seq: SerialNumber(0),
            waiting_ordered_queue: VecDeque::new(),
            waiting_unordered_queue: VecDeque::new(),
            readable_ordered_queue: VecDeque::new(),
            readable_unordered_queue: VecDeque::new(),
        }
    }

    pub fn recv(&mut self, chunk: SctpDataChunk) -> Result<usize> {
        assert_eq!(self.stream_id, chunk.stream_id);
        if SerialNumber(chunk.stream_seq) < self.next_seq {
            return Err(SctpError::ProtocolViolation);
        }
        let mut len = 0;

        if chunk.b_bit && chunk.e_bit {
            let msg = SctpDataMessage::new(chunk).unwrap();
            if msg.stream_seq == None || Some(self.next_seq) == msg.stream_seq {
                len += msg.len;
                if msg.stream_seq != None {
                    self.readable_ordered_queue.push_back(msg);
                    self.next_seq += 1;
                } else {
                    self.readable_unordered_queue.push_back(msg);
                }
            } else {
                if let Err(v) = self.insert_into_waiting(msg) {
                    return Err(v);
                }
                return Ok(len);
            }
        } else {
            match self.find_msg_from_waiting(&chunk) {
                Ok(Some(msg)) => {
                    msg.insert(chunk);
                }
                Ok(None) => {
                    if chunk.u_bit {
                        match self.find_splittable_msg_from_waiting(&chunk) {
                            Ok(Some(msg)) => {
                                let mut msg1 = msg.split(&chunk).unwrap();
                                msg1.insert(chunk);
                                if let Err(v) = self.insert_into_waiting(msg1) {
                                    return Err(v);
                                }
                            }
                            Ok(None) => {
                                let msg1 = SctpDataMessage::new(chunk).unwrap();
                                if let Err(v) = self.insert_into_waiting(msg1) {
                                    return Err(v);
                                }
                            }
                            Err(v) => {
                                return Err(v);
                            }
                        }
                    } else {
                        let msg = SctpDataMessage::new(chunk).unwrap();
                        if let Err(v) = self.insert_into_waiting(msg) {
                            return Err(v);
                        }
                    }
                }
                Err(v) => {
                    return Err(v);
                }
            }
        }
        while !self.waiting_ordered_queue.is_empty()
            && self.waiting_ordered_queue[0].stream_seq == Some(self.next_seq)
            && self.waiting_ordered_queue[0].complete
        {
            let msg = self.waiting_ordered_queue.pop_front().unwrap();
            len += msg.len;
            self.readable_ordered_queue.push_back(msg);
            self.next_seq += 1;
        }
        let mut i = self.waiting_unordered_queue.len();
        while i > 0 {
            if self.waiting_unordered_queue[i - 1].complete {
                let msg = self.waiting_unordered_queue.remove(i - 1).unwrap();
                len += msg.len;
                self.readable_unordered_queue.push_back(msg);
            }
            i -= 1;
        }
        Ok(len)
    }

    fn insert_into_waiting(&mut self, msg: SctpDataMessage) -> Result<bool> {
        if msg.stream_seq != None {
            if self.waiting_ordered_queue.is_empty() {
                self.waiting_ordered_queue.push_front(msg);
            } else {
                for (i, item) in self.waiting_ordered_queue.iter().enumerate() {
                    if msg.stream_seq > item.stream_seq {
                        continue;
                    }
                    if msg.stream_seq == item.stream_seq {
                        return Err(SctpError::ProtocolViolation);
                    }
                    self.waiting_ordered_queue.insert(i, msg);
                    return Ok(true);
                }
                self.waiting_ordered_queue.push_back(msg);
            }
        } else {
            if self.waiting_unordered_queue.is_empty() {
                self.waiting_unordered_queue.push_front(msg);
            } else {
                for (i, item) in self.waiting_unordered_queue.iter().enumerate() {
                    if msg.smallest_tsn > item.largest_tsn {
                        continue;
                    }
                    if msg.smallest_tsn == item.largest_tsn {
                        return Err(SctpError::ProtocolViolation);
                    }
                    self.waiting_unordered_queue.insert(i, msg);
                    return Ok(true);
                }
                self.waiting_unordered_queue.push_back(msg);
            }
        }
        return Ok(true);
    }

    fn find_msg_from_waiting(
        &mut self,
        chunk: &SctpDataChunk,
    ) -> Result<Option<&mut SctpDataMessage>> {
        if !chunk.u_bit {
            for item in self.waiting_ordered_queue.iter_mut() {
                match item.is_include(chunk) {
                    Ok(v) => {
                        if v {
                            return Ok(Some(item));
                        }
                    }
                    Err(v) => {
                        return Err(v);
                    }
                };
            }
            return Ok(None);
        } else {
            for item in self.waiting_unordered_queue.iter_mut() {
                match item.is_include(chunk) {
                    Ok(v) => {
                        if v {
                            return Ok(Some(item));
                        }
                    }
                    Err(v) => {
                        return Err(v);
                    }
                };
            }
            return Ok(None);
        }
    }

    fn find_splittable_msg_from_waiting(
        &mut self,
        chunk: &SctpDataChunk,
    ) -> Result<Option<&mut SctpDataMessage>> {
        if !chunk.u_bit {
            return Ok(None);
        }
        for item in self.waiting_unordered_queue.iter_mut() {
            match item.is_splittable(chunk) {
                Ok(v) => {
                    if v {
                        return Ok(Some(item));
                    }
                }
                Err(v) => {
                    return Err(v);
                }
            };
        }
        return Ok(None);
    }

    pub fn get_waiting_num(&self, is_unordered: bool) -> usize {
        if !is_unordered {
            self.waiting_ordered_queue.len()
        } else {
            self.waiting_unordered_queue.len()
        }
    }

    pub fn get_readable_num(&self, is_unordered: bool) -> usize {
        if !is_unordered {
            self.readable_ordered_queue.len()
        } else {
            self.readable_unordered_queue.len()
        }
    }

    pub fn len(&self) -> usize {
        let len1: usize = self.waiting_unordered_queue.iter().map(|v| v.len).sum();
        let len2: usize = self.waiting_ordered_queue.iter().map(|v| v.len).sum();
        let len3: usize = self.readable_unordered_queue.iter().map(|v| v.len).sum();
        let len4: usize = self.readable_ordered_queue.iter().map(|v| v.len).sum();
        return len1 + len2 + len3 + len4;
    }

    pub fn read(&mut self, wbuf: &mut Vec<u8>) -> Result<usize> {
        let prev_len = wbuf.len();
        if !self.readable_unordered_queue.is_empty() {
            let mut msg = self.readable_unordered_queue.pop_front().unwrap();
            for chunk in msg.chunks.iter_mut() {
                wbuf.append(&mut chunk.data);
            }
            return Ok(wbuf.len() - prev_len);
        }
        if !self.readable_ordered_queue.is_empty() {
            let mut msg = self.readable_ordered_queue.pop_front().unwrap();
            for chunk in msg.chunks.iter_mut() {
                wbuf.append(&mut chunk.data);
            }
            return Ok(wbuf.len() - prev_len);
        }
        return Ok(0);
    }

    pub fn is_readable(&self) -> bool {
        return !self.readable_unordered_queue.is_empty()
            || !self.readable_ordered_queue.is_empty();
    }
}

#[derive(Debug, PartialEq)]
pub struct SctpStreamOut {
    pub stream_id: u16,
    next_seq: SerialNumber<u16>,
    pending_queue: VecDeque<SctpDataPending>,
}

impl SctpStreamOut {
    pub fn new(strmid: u16) -> Self {
        SctpStreamOut {
            stream_id: strmid,
            next_seq: SerialNumber(0),
            pending_queue: VecDeque::new(),
        }
    }

    pub fn is_pending(&self) -> bool {
        return !self.pending_queue.is_empty();
    }

    pub fn write(&mut self, rbuf: &[u8], is_unordered: bool, is_complete: bool) -> Result<usize> {
        if let Some(last_pending) = self.pending_queue.back_mut() {
            if !last_pending.complete {
                last_pending.data.append(&mut Vec::from(rbuf));
                if is_complete {
                    last_pending.complete = true;
                }
                return Ok(rbuf.len());
            }
        }

        let pending = SctpDataPending {
            stream_id: self.stream_id,
            unordeded: is_unordered,
            complete: is_complete,
            flight: false,
            data: Vec::from(rbuf),
        };
        self.pending_queue.push_back(pending);
        return Ok(rbuf.len());
    }

    pub fn generate_data(
        &mut self,
        tsn: u32,
        fragment_point: usize,
    ) -> Result<Option<SctpDataChunk>> {
        if let Some(first_pending) = self.pending_queue.front_mut() {
            if first_pending.complete && first_pending.data.len() <= fragment_point {
                let first_pending = self.pending_queue.pop_front().unwrap();
                let data_chunk = SctpDataChunk {
                    u_bit: first_pending.unordeded,
                    b_bit: !first_pending.flight,
                    e_bit: true,
                    tsn: tsn,
                    stream_id: self.stream_id,
                    stream_seq: self.next_seq.0,
                    proto_id: 0,
                    data: first_pending.data,
                };
                if !first_pending.unordeded {
                    self.next_seq += 1;
                }
                return Ok(Some(data_chunk));
            } else {
                let data_len = first_pending.data.len();
                let data = if data_len > fragment_point {
                    first_pending.data.drain(0..fragment_point)
                } else {
                    first_pending.data.drain(0..data_len)
                }
                .collect::<Vec<u8>>();
                let data_chunk = SctpDataChunk {
                    u_bit: first_pending.unordeded,
                    b_bit: !first_pending.flight,
                    e_bit: false,
                    tsn: tsn,
                    stream_id: self.stream_id,
                    stream_seq: self.next_seq.0,
                    proto_id: 0,
                    data: data,
                };
                if !first_pending.flight {
                    first_pending.flight = true;
                }
                return Ok(Some(data_chunk));
            }
        }
        return Ok(None);
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SctpDataPending {
    stream_id: u16,
    unordeded: bool,
    complete: bool,
    flight: bool,
    data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
struct SctpDataMessage {
    pub stream_id: u16,
    pub stream_seq: Option<SerialNumber<u16>>,
    pub complete: bool,
    pub start_tsn: Option<SerialNumber<u32>>,
    pub end_tsn: Option<SerialNumber<u32>>,
    pub smallest_tsn: SerialNumber<u32>,
    pub largest_tsn: SerialNumber<u32>,
    pub max_tsn: Option<SerialNumber<u32>>,
    pub len: usize,
    pub chunks: VecDeque<SctpDataChunk>,
}

impl SctpDataMessage {
    fn new(chunk: SctpDataChunk) -> Result<SctpDataMessage> {
        let mut msg = SctpDataMessage {
            stream_id: chunk.stream_id,
            stream_seq: if !chunk.u_bit {
                Some(SerialNumber(chunk.stream_seq))
            } else {
                None
            },
            start_tsn: if chunk.b_bit {
                Some(SerialNumber(chunk.tsn))
            } else {
                None
            },
            end_tsn: if chunk.e_bit {
                Some(SerialNumber(chunk.tsn))
            } else {
                None
            },
            smallest_tsn: SerialNumber(chunk.tsn),
            largest_tsn: SerialNumber(chunk.tsn),
            max_tsn: None,
            complete: if chunk.b_bit & chunk.e_bit {
                true
            } else {
                false
            },
            len: chunk.data.len(),
            chunks: VecDeque::new(),
        };
        msg.chunks.push_back(chunk);
        Ok(msg)
    }

    fn is_include(&self, chunk: &SctpDataChunk) -> Result<bool> {
        if (!chunk.u_bit && self.stream_seq != Some(SerialNumber(chunk.stream_seq)))
            || (chunk.u_bit && self.stream_seq != None)
        {
            return Ok(false);
        }
        if let Some(v) = self.start_tsn {
            if chunk.b_bit && v != SerialNumber(chunk.tsn) {
                if !chunk.u_bit {
                    return Err(SctpError::ProtocolViolation);
                } else {
                    return Ok(false);
                }
            } else {
                if SerialNumber(chunk.tsn) < v {
                    return Err(SctpError::ProtocolViolation);
                }
            }
        }
        if let Some(v) = self.end_tsn {
            if chunk.e_bit && v != SerialNumber(chunk.tsn) {
                if !chunk.u_bit {
                    return Err(SctpError::ProtocolViolation);
                } else {
                    return Ok(false);
                }
            } else {
                if SerialNumber(chunk.tsn) > v {
                    return Err(SctpError::ProtocolViolation);
                }
            }
        }
        if chunk.b_bit && self.smallest_tsn <= SerialNumber(chunk.tsn) {
            if !chunk.u_bit {
                return Err(SctpError::ProtocolViolation);
            } else {
                return Ok(false);
            }
        }
        if chunk.e_bit && self.largest_tsn >= SerialNumber(chunk.tsn) {
            if !chunk.u_bit {
                return Err(SctpError::ProtocolViolation);
            } else {
                return Ok(false);
            }
        }
        if let Some(v) = self.max_tsn {
            if SerialNumber(chunk.tsn) > v {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    fn is_splittable(&self, chunk: &SctpDataChunk) -> Result<bool> {
        if !chunk.u_bit || self.stream_seq != None {
            return Ok(false);
        }

        if (!chunk.b_bit && !chunk.e_bit) || (chunk.b_bit && chunk.e_bit) {
            return Ok(false);
        }
        if SerialNumber(chunk.tsn) > self.smallest_tsn && SerialNumber(chunk.tsn) < self.largest_tsn
        {
            if chunk.b_bit {
                if let Some(v) = self.start_tsn {
                    if v + 1 >= SerialNumber(chunk.tsn) {
                        return Err(SctpError::ProtocolViolation);
                    }
                }
                return Ok(true);
            }
            if chunk.e_bit {
                if let Some(v) = self.end_tsn {
                    if v <= SerialNumber(chunk.tsn) + 1 {
                        return Err(SctpError::ProtocolViolation);
                    }
                }
                return Ok(true);
            }
        }
        return Ok(false);
    }

    fn split(&mut self, chunk: &SctpDataChunk) -> Result<SctpDataMessage> {
        assert_eq!(!chunk.b_bit && !chunk.e_bit, false);
        assert_eq!(chunk.b_bit && chunk.e_bit, false);

        let mut msg = SctpDataMessage {
            stream_id: chunk.stream_id,
            stream_seq: None,
            start_tsn: None,
            end_tsn: None,
            smallest_tsn: SerialNumber(0),
            largest_tsn: SerialNumber(0),
            max_tsn: None,
            complete: false,
            len: 0,
            chunks: VecDeque::new(),
        };

        let mut at = self.chunks.len();
        for (i, item) in self.chunks.iter().enumerate() {
            if SerialNumber(item.tsn) < SerialNumber(chunk.tsn) {
                continue;
            }
            if SerialNumber(item.tsn) == SerialNumber(chunk.tsn) {
                return Err(SctpError::ProtocolViolation);
            }
            at = i;
            break;
        }
        assert!(at > 0);
        assert!(at < self.chunks.len());

        let mut latter = self.chunks.split_off(at);
        if chunk.b_bit {
            msg.chunks.append(&mut latter);

            msg.end_tsn = self.end_tsn;
            msg.smallest_tsn = SerialNumber(msg.chunks.front().unwrap().tsn);
            msg.largest_tsn = SerialNumber(msg.chunks.back().unwrap().tsn);
            msg.len = msg.chunks.iter().map(|v| v.data.len()).sum();

            self.largest_tsn = SerialNumber(self.chunks.back().unwrap().tsn);
            self.end_tsn = None;
            self.max_tsn = if msg.smallest_tsn.0 == 0 {
                Some(SerialNumber(0xffffffff))
            } else {
                Some(SerialNumber(msg.smallest_tsn.0 - 1))
            };
            self.len = self.chunks.iter().map(|v| v.data.len()).sum();
            return Ok(msg);
        } else {
            msg.chunks.append(&mut self.chunks);
            self.chunks.append(&mut latter);

            msg.start_tsn = self.start_tsn;
            msg.smallest_tsn = SerialNumber(msg.chunks.front().unwrap().tsn);
            msg.largest_tsn = SerialNumber(msg.chunks.back().unwrap().tsn);
            msg.max_tsn = if self.smallest_tsn.0 == 0 {
                Some(SerialNumber(0xffffffff))
            } else {
                Some(SerialNumber(self.smallest_tsn.0 - 1))
            };
            msg.len = msg.chunks.iter().map(|v| v.data.len()).sum();

            self.smallest_tsn = SerialNumber(self.chunks.front().unwrap().tsn);
            self.start_tsn = None;
            self.len = self.chunks.iter().map(|v| v.data.len()).sum();
            return Ok(msg);
        }
    }

    fn insert(&mut self, chunk: SctpDataChunk) -> bool {
        if self.complete || (chunk.b_bit && chunk.e_bit) {
            return false;
        }
        if !chunk.u_bit && self.stream_seq != Some(SerialNumber(chunk.stream_seq)) {
            return false;
        }
        if chunk.u_bit && self.stream_seq != None {
            return false;
        }
        if chunk.b_bit {
            if self.start_tsn != None {
                return false;
            }
            if self.smallest_tsn <= SerialNumber(chunk.tsn) {
                return false;
            }
            self.start_tsn = Some(SerialNumber(chunk.tsn));
            self.smallest_tsn = SerialNumber(chunk.tsn);
            self.len += chunk.data.len();
            self.chunks.push_front(chunk);
        } else if chunk.e_bit {
            if self.end_tsn != None {
                return false;
            }
            if self.largest_tsn >= SerialNumber(chunk.tsn) {
                return false;
            }
            self.end_tsn = Some(SerialNumber(chunk.tsn));
            self.largest_tsn = SerialNumber(chunk.tsn);
            self.len += chunk.data.len();
            self.chunks.push_back(chunk);
        } else {
            for (i, item) in self.chunks.iter().enumerate() {
                if SerialNumber(item.tsn) < SerialNumber(chunk.tsn) {
                    if i < self.chunks.len() - 1 {
                        continue;
                    } else {
                        if SerialNumber(chunk.tsn) < self.smallest_tsn {
                            self.smallest_tsn = SerialNumber(chunk.tsn);
                        }
                        if SerialNumber(chunk.tsn) > self.largest_tsn {
                            self.largest_tsn = SerialNumber(chunk.tsn);
                        }
                        self.len += chunk.data.len();
                        self.chunks.push_back(chunk);
                        break;
                    }
                }
                if SerialNumber(item.tsn) == SerialNumber(chunk.tsn) {
                    return false;
                }

                if SerialNumber(chunk.tsn) < self.smallest_tsn {
                    self.smallest_tsn = SerialNumber(chunk.tsn);
                }
                if SerialNumber(chunk.tsn) > self.largest_tsn {
                    self.largest_tsn = SerialNumber(chunk.tsn);
                }
                self.len += chunk.data.len();
                self.chunks.insert(i, chunk);
                break;
            }
        }
        if self.start_tsn != None && self.end_tsn != None {
            assert!(self.start_tsn == Some(self.smallest_tsn));
            assert!(self.end_tsn == Some(self.largest_tsn));
            for (i, item) in self.chunks.iter().enumerate() {
                if let Some(v) = self.start_tsn {
                    if SerialNumber(item.tsn) != v + i as u32 {
                        break;
                    }
                }
                if i == self.chunks.len() - 1 {
                    self.complete = true;
                }
            }
        }
        return true;
    }
}

#[derive(Default)]
pub struct SctpStreamIter {
    streams: Vec<u16>,
}

impl SctpStreamIter {
    pub fn new(streams: Vec<u16>) -> Self {
        SctpStreamIter { streams: streams }
    }
}

impl Iterator for SctpStreamIter {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        self.streams.pop()
    }
}

impl ExactSizeIterator for SctpStreamIter {
    fn len(&self) -> usize {
        self.streams.len()
    }
}

#[test]
fn test_stream_in_recv_nonfragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 1,
        proto_id: 0,
        data: vec![1u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 0);
    assert_eq!(stream_in.get_waiting_num(false), 1);
    assert_eq!(stream_in.get_waiting_num(true), 0);
    assert_eq!(stream_in.get_readable_num(false), 0);
    assert_eq!(stream_in.get_readable_num(true), 0);

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: true,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec![2u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 1);
    assert_eq!(stream_in.get_waiting_num(false), 1);
    assert_eq!(stream_in.get_waiting_num(true), 0);
    assert_eq!(stream_in.get_readable_num(false), 0);
    assert_eq!(stream_in.get_readable_num(true), 1);

    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 591162750,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec![0u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 2);
    assert_eq!(stream_in.get_waiting_num(false), 0);
    assert_eq!(stream_in.get_waiting_num(true), 0);
    assert_eq!(stream_in.get_readable_num(false), 2);
    assert_eq!(stream_in.get_readable_num(true), 1);
}

#[test]
fn test_stream_in_recv_fragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['a' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 0);

    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: false,
        e_bit: false,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['b' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 0);

    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: false,
        e_bit: false,
        tsn: 591162753,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['c' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 0);

    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: false,
        e_bit: true,
        tsn: 591162754,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['d' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    trace!("{:?}", stream_in);
    assert_eq!(ret, 4);
}

#[test]
fn test_stream_in_recv_reordered_fragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['a' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 0);

    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: false,
        e_bit: true,
        tsn: 591162754,
        stream_id: 0,
        stream_seq: 1,
        proto_id: 0,
        data: vec!['B' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 0);

    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: false,
        tsn: 591162753,
        stream_id: 0,
        stream_seq: 1,
        proto_id: 0,
        data: vec!['A' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 0);

    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: false,
        e_bit: true,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['b' as u8],
    };
    let ret = stream_in.recv(datachunk).unwrap();
    assert_eq!(ret, 4);
}

#[test]
fn test_stream_in_recv_invalid_nonfragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec![1u8],
    };

    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(1));
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec![1u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Err(SctpError::ProtocolViolation));
}

#[test]
fn test_stream_in_recv_invalid_fragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: false,
        e_bit: true,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec![1u8],
    };

    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec![1u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Err(SctpError::ProtocolViolation));
}

#[test]
fn test_stream_in_recv_ufragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['a' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['b' as u8],
    };
    let ret = stream_in.recv(datachunk);
    trace!("{:?}", stream_in);
    assert_eq!(ret, Ok(2));
}

#[test]
fn test_stream_in_recv_reordered_ufragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162753,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['A' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['a' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['b' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(2));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162754,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['B' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(2));
}

#[test]
fn test_stream_in_recv_splittable_reordered_ufragment() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['a' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162754,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['B' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['b' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(2));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162753,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['A' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(2));
}

#[test]
fn test_stream_in_recv_splittable_reordered_ufragment2() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['a' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162754,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['B' as u8],
    };
    let ret = stream_in.recv(datachunk);
    trace!("{:?}", stream_in);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['b' as u8],
    };
    let ret = stream_in.recv(datachunk);
    trace!("{:?}", stream_in);
    assert_eq!(ret, Ok(2));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162753,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['A' as u8],
    };
    let ret = stream_in.recv(datachunk);
    trace!("{:?}", stream_in);
    assert_eq!(ret, Ok(2));
}

#[test]
fn test_stream_in_recv_splittable_reordered_ufragment3() {
    let mut stream_in = SctpStreamIn {
        stream_id: 0,
        next_seq: SerialNumber(0),
        waiting_ordered_queue: VecDeque::new(),
        waiting_unordered_queue: VecDeque::new(),
        readable_ordered_queue: VecDeque::new(),
        readable_unordered_queue: VecDeque::new(),
    };
    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: false,
        tsn: 591162752,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['b' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: false,
        tsn: 591162755,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['B' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162751,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['a' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: true,
        e_bit: false,
        tsn: 591162754,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['A' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(0));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162756,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['C' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(3));

    let datachunk = SctpDataChunk {
        u_bit: true,
        b_bit: false,
        e_bit: true,
        tsn: 591162753,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: vec!['c' as u8],
    };
    let ret = stream_in.recv(datachunk);
    assert_eq!(ret, Ok(3));
}
