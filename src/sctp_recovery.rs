use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use sna::SerialNumber;

use crate::Result;
use crate::SctpError;

use crate::sctp_collections::{SctpBTreeMap, SctpTsnQueue};
pub use crate::sctp_pkt::*;

const RTO_INITIAL: Duration = Duration::from_secs(3);
const RTO_MIN: Duration = Duration::from_secs(1);
const RTO_MAX: Duration = Duration::from_secs(60);
const RTO_ALPHA: f64 = 1.0 / 8.0;
const RTO_BETA: f64 = 1.0 / 4.0;

const DUP_THRESH: usize = 3;

const MAX_PATH_RETRANS: u32 = 5;
const _MAX_INIT_RETRANS: u32 = 8;

const HB_INTERVAL: Duration = Duration::from_secs(30);
const _HB_MAX_BURST: u32 = 1;

#[derive(Debug)]
pub struct SctpRecovery {
    established: bool,
    shutdown_pending: bool,
    shutdown_received: bool,
    closing: bool,

    rwnd: usize,
    fast_recovery: bool,
    recovery_point: Option<u32>,

    path_list: Vec<Option<SctpPath>>,
    primary_path: Option<usize>,

    largest_tsn: SerialNumber<u32>,

    cum_ack: SerialNumber<u32>,
    highest_ack: SerialNumber<u32>,
    highest_newly_ack: Option<SerialNumber<u32>>,

    peer_cumulative_tsn_ack: Option<u32>,

    total_flight: usize,
    total_flight_count: usize,
    t2_shutdown_timeout: Option<Instant>,

    data_sent: SctpTsnQueue<SctpTransmitData>,
    pub control_waiting_trans: SctpBTreeMap<u64, (SctpChunk, usize)>,
    next_control_sequence: SerialNumber<u64>,
    pub tsn_waiting_t3_retrans: SctpBTreeMap<u32, (usize, usize, bool)>,
    pub tsn_waiting_fast_retrans: SctpBTreeMap<u32, (usize, usize, bool)>,

    trace_id: String,
}

#[derive(Debug)]
struct SctpPath {
    id: usize,
    random_value: u64,
    confirmed: bool,

    state: SctpPathState,

    last_time: Option<Instant>,

    needs_new_rtt: bool,
    latest_rtt: Duration,
    srtt: Option<Duration>,
    rttvar: Duration,

    mtu: usize,
    flight: usize,
    flight_count: usize,
    ack: usize,
    cwnd: usize,
    ssthresh: usize,
    partial_bytes_acked: usize,
    recovery_point: Option<SerialNumber<u64>>,

    next_hb_sequence: u64,
    next_sequence: SerialNumber<u64>,
    lowest_sequence: Option<SerialNumber<u64>>,

    t1_timeout: Option<Instant>,
    heartbeat_timeout: Option<Instant>,
    t3_retrans_timeout: Option<Instant>,

    retrans_count: u32,
    retrans_threshold: u32,

    control_sent: VecDeque<SctpTransmitControlChunk>,
    heartbeat_sent: SctpBTreeMap<u64, SctpTransmitHeartbeatChunk>,
    data_sent: SctpBTreeMap<u64, SctpTransmitDataInfo>,

    wait_hb_trans: bool,
    wait_t3_retrans: bool,
    wait_fast_retrans: bool,

    fast_recovery: bool,

    trace_id: String,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SctpPathState {
    Active,
    InActive,
}

#[derive(Debug)]
struct SctpTransmitControlChunk {
    chunk: SctpChunk,
    pub pathid: usize,
    time: Instant,
}

#[derive(Debug)]
struct SctpTransmitHeartbeatChunk {
    pub hbinfo: SctpHeartbeatInfo,
    pub pathid: usize,
    time: Instant,
}

#[derive(Debug)]
struct SctpTransmitData {
    chunk: Vec<SctpChunk>,
    pathid: usize,
    tsn: u32,
    state: SctpTransmitDataState,
    bytes_len: usize,
    in_flight: bool,
    retrans: bool,
    fast_retrans: bool,
    miss_indications: usize,
    gapacked: bool,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SctpTransmitDataState {
    Sent,
    GapAcked,
    CumAcked,
    Lost,
}

#[derive(Debug)]
struct SctpTransmitDataInfo {
    pathid: usize,
    sequence: SerialNumber<u64>,
    tsn: SerialNumber<u32>,
    bytes_len: usize,
    state: SctpTransmitDataState,
    time: Instant,
    do_rtt: bool,
}

impl SctpRecovery {
    pub fn new(init_tsn: u32, trace_id: String) -> Result<SctpRecovery> {
        let initial_tsn_minus1 = if init_tsn == 0 {
            SerialNumber(0xffffffff)
        } else {
            SerialNumber(init_tsn - 1)
        };
        let recovery = SctpRecovery {
            established: false,
            shutdown_pending: false,
            shutdown_received: false,
            closing: false,
            peer_cumulative_tsn_ack: None,
            rwnd: 0,
            largest_tsn: initial_tsn_minus1,
            cum_ack: initial_tsn_minus1,
            highest_ack: initial_tsn_minus1,
            highest_newly_ack: None,
            total_flight: 0,
            total_flight_count: 0,
            path_list: Vec::new(),
            primary_path: None,
            data_sent: SctpTsnQueue::new(SerialNumber(init_tsn)),
            control_waiting_trans: SctpBTreeMap::new(),
            next_control_sequence: SerialNumber(0),
            tsn_waiting_t3_retrans: SctpBTreeMap::new(),
            tsn_waiting_fast_retrans: SctpBTreeMap::new(),
            fast_recovery: false,
            recovery_point: None,
            t2_shutdown_timeout: None,
            trace_id: trace_id,
        };
        Ok(recovery)
    }

    pub fn initialize(&mut self, rwnd: usize) {
        self.rwnd = rwnd;
    }

    pub fn establish(&mut self) {
        self.established = true;
    }

    pub fn add_path(&mut self, mtu: usize) -> usize {
        let pathid = self.path_list.len();
        self.path_list.push(Some(SctpPath {
            id: pathid,
            confirmed: false,
            random_value: rand::random::<u64>(),
            state: SctpPathState::Active,
            needs_new_rtt: true,
            latest_rtt: Duration::new(0, 0),
            srtt: None,
            rttvar: Duration::new(0, 0),
            mtu: mtu,
            cwnd: mtu * 4,
            ssthresh: std::usize::MAX,
            recovery_point: None,
            last_time: None,
            next_hb_sequence: 0,
            next_sequence: SerialNumber(0),
            lowest_sequence: None,
            retrans_count: 0,
            retrans_threshold: MAX_PATH_RETRANS,
            flight: 0,
            flight_count: 0,
            ack: 0,
            partial_bytes_acked: 0,
            t1_timeout: None,
            t3_retrans_timeout: None,
            heartbeat_timeout: None,
            control_sent: VecDeque::new(),
            heartbeat_sent: SctpBTreeMap::new(),
            data_sent: SctpBTreeMap::new(),
            wait_hb_trans: false,
            wait_t3_retrans: false,
            wait_fast_retrans: false,
            fast_recovery: false,
            trace_id: self.trace_id.clone(),
        }));
        pathid
    }

    pub fn get_next_tsn(&mut self) -> u32 {
        self.largest_tsn += 1;
        self.largest_tsn.0
    }

    fn get_path(&self, pathid: usize) -> Option<&SctpPath> {
        if let Some(opt) = self.path_list.get(pathid) {
            if let Some(path) = opt {
                return Some(path);
            }
        }
        return None;
    }

    fn get_path_mut(&mut self, pathid: usize) -> Option<&mut SctpPath> {
        if let Some(opt) = self.path_list.get_mut(pathid) {
            if let Some(path) = opt {
                return Some(path);
            }
        }
        return None;
    }

    pub fn confirm_path(&mut self, pathid: usize) -> Result<()> {
        if let Some(path) = self.get_path_mut(pathid) {
            path.confirmed = true;
            path.last_time = Some(Instant::now());
            path.random_value = 0;
            Ok(())
        } else {
            Err(SctpError::InvalidPathId)
        }
    }

    pub fn get_path_state(&self, pathid: usize) -> Result<(bool, SctpPathState)> {
        if let Some(path) = self.get_path(pathid) {
            if let Some((confirmed, state)) = path.get_state() {
                return Ok((confirmed, state));
            }
        }
        Err(SctpError::InvalidPathId)
    }

    pub fn get_primary_path(&self) -> Option<usize> {
        self.primary_path
    }

    pub fn set_primary_path(&mut self, pathid: usize) -> Result<()> {
        if let Some(path) = self.get_path(pathid) {
            if let Some((confirmed, state)) = path.get_state() {
                if confirmed && state == SctpPathState::Active {
                    self.primary_path = Some(pathid);
                    return Ok(());
                }
            }
        }
        Err(SctpError::InvalidPathId)
    }

    pub fn get_path_mtu(&self, pathid: usize) -> Result<usize> {
        if let Some(path) = self.get_path(pathid) {
            Ok(path.mtu)
        } else {
            Err(SctpError::InvalidPathId)
        }
    }

    pub fn get_available_cwnd(&self, pathid: usize) -> Result<usize> {
        if let Some(path) = self.get_path(pathid) {
            Ok(path.cwnd.checked_sub(path.flight).unwrap_or(0))
        } else {
            Err(SctpError::InvalidPathId)
        }
    }

    pub fn get_available_window(&self, pathid: usize) -> Result<usize> {
        if let Some(path) = self.get_path(pathid) {
            let window = std::cmp::min(
                self.rwnd.checked_sub(path.flight).unwrap_or(0),
                path.cwnd.checked_sub(path.flight).unwrap_or(0),
            );
            Ok(window)
        } else {
            Err(SctpError::InvalidPathId)
        }
    }

    pub fn pop_retrans_chunk(&mut self, tsn: u32) -> Option<SctpChunk> {
        if let Some(tmit_data) = self.data_sent.get_mut(tsn) {
            if tmit_data.state == SctpTransmitDataState::Lost {
                return tmit_data.chunk.pop();
            }
        }
        return None;
    }

    pub fn enter_t3_retrans(&mut self, pathid: usize) -> bool {
        if let Some(path) = self.get_path_mut(pathid) {
            if path.wait_t3_retrans {
                path.wait_t3_retrans = false;
                return true;
            }
        }
        return false;
    }
    pub fn enter_fast_retrans(&mut self, pathid: usize) -> bool {
        if let Some(path) = self.get_path_mut(pathid) {
            if path.wait_fast_retrans {
                path.wait_fast_retrans = false;
                return true;
            }
        }
        return false;
    }

    pub fn get_timeout(&self) -> Option<Instant> {
        let now = Instant::now();
        vec![
            self.get_t1_timeout(now),
            self.get_idle_timeout(now),
            self.get_heartbeats_timeout(now),
            self.get_t3_retrans_timeout(now),
            self.get_t2_shutdown_timeout(now),
        ]
        .into_iter()
        .filter_map(|x| x)
        .min()
    }

    fn get_t1_timeout(&self, now: Instant) -> Option<Instant> {
        if self.established {
            return None;
        }
        self.path_list
            .iter()
            .filter_map(|opt| {
                if let Some(path) = opt {
                    return path.get_t1_timeout(now);
                } else {
                    return None;
                }
            })
            .min()
    }

    fn get_idle_timeout(&self, now: Instant) -> Option<Instant> {
        if !self.established {
            return None;
        }
        self.path_list
            .iter()
            .filter_map(|opt| {
                if let Some(path) = opt {
                    return path.get_idle_timeout(now);
                } else {
                    return None;
                }
            })
            .min()
    }

    fn get_heartbeats_timeout(&self, now: Instant) -> Option<Instant> {
        if !self.established {
            return None;
        }
        self.path_list
            .iter()
            .filter_map(|opt| {
                if let Some(path) = opt {
                    return path.get_heartbeats_timeout(now);
                } else {
                    return None;
                }
            })
            .min()
    }

    fn get_t3_retrans_timeout(&self, now: Instant) -> Option<Instant> {
        if !self.established && !self.shutdown_pending {
            return None;
        }
        self.path_list
            .iter()
            .filter_map(|opt| {
                if let Some(path) = opt {
                    return path.get_t3_retrans_timeout(now);
                } else {
                    return None;
                }
            })
            .min()
    }

    fn get_t2_shutdown_timeout(&self, now: Instant) -> Option<Instant> {
        if !self.shutdown_pending && !self.shutdown_received {
            return None;
        }
        if let Some(t2_timeout) = self.t2_shutdown_timeout {
            if t2_timeout <= now {
                return Some(now);
            } else {
                return Some(t2_timeout);
            }
        }
        return None;
    }

    pub fn on_timeout(&mut self, now: Instant) {
        if let Some(timeout) = self.get_t1_timeout(now) {
            if timeout == now {
                self.on_t1_timeout(now);
            }
        }

        if let Some(timeout) = self.get_heartbeats_timeout(now) {
            if timeout == now {
                self.on_heartbeats_timeout(now);
            }
        }

        if let Some(timeout) = self.get_t3_retrans_timeout(now) {
            if timeout == now {
                self.on_t3_retrans_timeout(now);
            }
        }

        if let Some(timeout) = self.get_t2_shutdown_timeout(now) {
            if timeout == now {
                self.on_t2_shutdown_timeout();
            }
        }

        if let Some(timeout) = self.get_idle_timeout(now) {
            if timeout == now {
                self.on_idle_timeout(now);
            }
        }
    }

    fn on_t1_timeout(&mut self, now: Instant) {
        trace!("{} t1 INIT timeout fired", self.trace_id);

        for opt in self.path_list.iter_mut() {
            if let Some(path) = opt {
                if let Some(v) = path.on_t1_timeout(now) {
                    self.control_waiting_trans
                        .insert(self.next_control_sequence.0, v);
                    self.next_control_sequence += 1;
                }
            }
        }
    }

    fn on_idle_timeout(&mut self, now: Instant) {
        trace!("{} idle timeout fired", self.trace_id);

        for opt in self.path_list.iter_mut() {
            if let Some(path) = opt {
                if let Some(v) = path.on_idle_timeout(now) {
                    self.control_waiting_trans
                        .insert(self.next_control_sequence.0, v);
                    self.next_control_sequence += 1;
                }
            }
        }
    }

    fn on_heartbeats_timeout(&mut self, now: Instant) {
        trace!("{} heartbeat timeout fired", self.trace_id);

        for opt in self.path_list.iter_mut() {
            if let Some(path) = opt {
                path.on_heartbeats_timeout(now);
            }
        }
    }

    fn on_t3_retrans_timeout(&mut self, now: Instant) {
        trace!("{} T3 retransmission timeout fired", self.trace_id);

        let mut timeout_pathid = BTreeMap::new();
        for opt in self.path_list.iter_mut() {
            if let Some(path) = opt {
                if path.on_t3_retrans_timeout(now) {
                    timeout_pathid.insert(path.id, false);
                }
            }
        }

        for (tsn, tmit_data) in &mut self.data_sent {
            if let Some(second) = timeout_pathid.get_mut(&tmit_data.pathid) {
                trace!(
                    "{} try to retransmit tsn={}, pathid={}",
                    self.trace_id,
                    tsn,
                    tmit_data.pathid
                );

                self.tsn_waiting_t3_retrans.insert(
                    tsn.0,
                    (tmit_data.pathid, tmit_data.bytes_len, *second == false),
                );
                *second = true;

                if tmit_data.state == SctpTransmitDataState::Sent {
                    self.total_flight -= tmit_data.bytes_len;
                    self.total_flight_count -= 1;
                }
                tmit_data.state = SctpTransmitDataState::Lost;
            }
        }
    }

    fn on_t2_shutdown_timeout(&mut self) {
        trace!("{} T2 shutdown timeout fired", self.trace_id);

        if self.shutdown_pending {
            // Send Shutdown
            assert!(!self.shutdown_received);
            let shutdown = SctpChunk::Shutdown(self.peer_cumulative_tsn_ack.unwrap());
            trace!(
                "{} send SHUTDOWN cumulative_tsn_ack={}, pathid={})",
                self.trace_id,
                self.peer_cumulative_tsn_ack.unwrap(),
                self.primary_path.unwrap_or(0)
            );
            self.control_waiting_trans.insert(
                self.next_control_sequence.0,
                (shutdown, self.primary_path.unwrap_or(0)),
            );
            self.next_control_sequence += 1;
        }

        if self.shutdown_received {
            // Send Shutdown-ACK
            assert!(!self.shutdown_pending);
            let shutdown_ack = SctpChunk::ShutdownAck;
            trace!(
                "{} send SHUTDOWN-ACK pathid={})",
                self.trace_id,
                self.primary_path.unwrap_or(0)
            );
            self.control_waiting_trans.insert(
                self.next_control_sequence.0,
                (shutdown_ack, self.primary_path.unwrap_or(0)),
            );
            self.next_control_sequence += 1;
        }
    }

    pub fn on_control_sent(&mut self, chunk: SctpChunk, pathid: usize, now: Instant) {
        match &chunk {
            SctpChunk::Shutdown(..) | SctpChunk::ShutdownAck => {
                let path = self.get_path_mut(pathid).unwrap();
                self.t2_shutdown_timeout = Some(now + path.get_rto());
            }
            _ => {
                let path = self.get_path_mut(pathid).unwrap();
                path.on_control_sent(chunk, now);
            }
        }
    }

    pub fn on_t1_chunk_received(&mut self, now: Instant) -> Option<SctpChunk> {
        for opt in self.path_list.iter_mut() {
            if let Some(path) = opt {
                let ret = path.on_t1_chunk_received(now);
                if ret.is_some() {
                    return ret;
                }
            }
        }
        return None;
    }

    pub fn on_heartbeatack_received(&mut self, chunk: SctpChunk, now: Instant) {
        if let SctpChunk::HeartbeatAckWithInfo(hbinfo) = &chunk {
            let path = self.get_path_mut(hbinfo.pathid).unwrap();
            path.on_heartbeatack_received(chunk, now);
        }
    }

    pub fn on_data_sent(&mut self, chunk: SctpChunk, pathid: usize, now: Instant, retrans: bool) {
        if !self.established {
            return;
        }
        match &chunk {
            SctpChunk::Data(data_chunk) => {
                let tsn = data_chunk.tsn;
                let bytes_len = chunk.bytes_len();
                let earliest_retrans = tsn == self.data_sent.smallest_tsn && retrans;

                assert!(tsn > self.cum_ack);

                let path = self.get_path_mut(pathid).unwrap();
                path.on_data_sent(SerialNumber(tsn), bytes_len, retrans, earliest_retrans, now);

                let tmit_data = match self.data_sent.get_mut(tsn) {
                    Some(tmit_data1) => {
                        assert!(tmit_data1.chunk.is_empty());
                        tmit_data1.state = SctpTransmitDataState::Sent;
                        tmit_data1.chunk.push(chunk);
                        tmit_data1
                    }
                    None => {
                        assert!(!retrans);
                        self.data_sent
                            .push(SctpTransmitData::new(chunk, bytes_len, tsn, pathid));
                        self.data_sent.get_mut(tsn).unwrap()
                    }
                };

                tmit_data.retrans = retrans;
                tmit_data.in_flight = true;

                self.total_flight += bytes_len;
                self.total_flight_count += 1;

                trace!(
                    "{} total_flight={}, total_flight_count={}",
                    self.trace_id,
                    self.total_flight,
                    self.total_flight_count
                );
            }
            _ => {}
        };
    }

    fn check_datas_lost(&mut self) {
        let mut lost_tsn = Vec::new();

        for (tsn, tmit_data) in &mut self.data_sent {
            if tmit_data.state != SctpTransmitDataState::Sent {
                continue;
            }

            if self.highest_newly_ack.is_some() && tsn < self.highest_newly_ack.unwrap() {
                tmit_data.miss_indications += 1;
            }
            if tmit_data.miss_indications >= DUP_THRESH {
                tmit_data.miss_indications = 0;
                tmit_data.state = SctpTransmitDataState::Lost;
                lost_tsn.push(tsn.0);
            }
        }

        let mut data_sent_state: SctpTsnQueue<SctpTransmitDataState> =
            SctpTsnQueue::new(self.data_sent.smallest_tsn);
        data_sent_state.append(
            &mut self
                .data_sent
                .iter()
                .map(|(_, tmit_data)| tmit_data.state)
                .collect::<VecDeque<SctpTransmitDataState>>(),
        );

        let mut lost_pathid = BTreeMap::new();
        for opt in self.path_list.iter_mut() {
            if let Some(path) = opt {
                if path.check_datas_lost(&data_sent_state) {
                    lost_pathid.insert(path.id, false);
                }
            }
        }

        for tsn in lost_tsn {
            let tmit_data = self.data_sent.get_mut(tsn).unwrap();
            let pathid = tmit_data.pathid;

            trace!("{} lost tsn={}, pathid={}", self.trace_id, tsn, pathid,);
            if let Some(second) = lost_pathid.get_mut(&pathid) {
                if !tmit_data.fast_retrans {
                    self.tsn_waiting_fast_retrans.insert(
                        tsn,
                        (tmit_data.pathid, tmit_data.bytes_len, *second == false),
                    );
                    *second = true;
                    tmit_data.fast_retrans = true;
                    trace!(
                        "{} try to fast retransmit tsn={}, pathid={}",
                        self.trace_id,
                        tsn,
                        tmit_data.pathid
                    );
                }
            }

            self.total_flight -= tmit_data.bytes_len;
            self.total_flight_count -= 1;
            trace!(
                "{} total_flight={}, total_flight_count={}",
                self.trace_id,
                self.total_flight,
                self.total_flight_count
            );

            self.on_enter_recovery(pathid);
        }
    }

    pub fn on_sack_received(&mut self, chunk: SctpChunk, now: Instant) {
        if let SctpChunk::Sack(sack_chunk) = chunk {
            if SerialNumber(sack_chunk.cum_ack) < self.cum_ack {
                return;
            }

            self.rwnd = sack_chunk.a_rwnd as usize;

            assert_eq!(self.data_sent.smallest_tsn, self.cum_ack + 1);
            let smallest_tsn = self.data_sent.smallest_tsn;
            let mut last_ack = SerialNumber(sack_chunk.cum_ack);
            let old_cum_ack = self.cum_ack;

            if self.cum_ack < SerialNumber(sack_chunk.cum_ack) {
                let start = self.cum_ack + 1;
                let end = SerialNumber(sack_chunk.cum_ack) + 1;
                if start.0 < end.0 {
                    for i in start.0..end.0 {
                        self.on_data_acked(SerialNumber(i), SctpTransmitDataState::CumAcked);
                    }
                } else {
                    for i in start.0..0xffffffff {
                        self.on_data_acked(SerialNumber(i), SctpTransmitDataState::CumAcked);
                    }
                    self.on_data_acked(SerialNumber(0xffffffff), SctpTransmitDataState::CumAcked);
                    for i in 0..end.0 {
                        self.on_data_acked(SerialNumber(i), SctpTransmitDataState::CumAcked);
                    }
                }
                self.cum_ack = SerialNumber(sack_chunk.cum_ack);
            }

            for ack_block in sack_chunk.gap_acks {
                let start = SerialNumber(sack_chunk.cum_ack) + ack_block.start as u32;
                let end = SerialNumber(sack_chunk.cum_ack) + ack_block.end as u32 + 1;
                last_ack = SerialNumber(sack_chunk.cum_ack) + ack_block.end as u32;
                if start.0 < end.0 {
                    for i in start.0..end.0 {
                        self.on_data_acked(SerialNumber(i), SctpTransmitDataState::GapAcked);
                    }
                } else {
                    for i in start.0..0xffffffff {
                        self.on_data_acked(SerialNumber(i), SctpTransmitDataState::GapAcked);
                    }
                    self.on_data_acked(SerialNumber(0xffffffff), SctpTransmitDataState::GapAcked);
                    for i in 0..end.0 {
                        self.on_data_acked(SerialNumber(i), SctpTransmitDataState::GapAcked);
                    }
                }
            }

            if last_ack > self.highest_ack {
                self.highest_ack = last_ack;
                self.highest_newly_ack = Some(last_ack);
            } else {
                self.highest_newly_ack = None;
            }

            trace!(
                "{} SACK received old_cum_ack={}, cum_ack={}, highest_ack={}, highest_newly_ack={:?}",
                self.trace_id,
                old_cum_ack,
                self.cum_ack,
                self.highest_ack,
                self.highest_newly_ack
            );

            let mut data_sent_state: SctpTsnQueue<SctpTransmitDataState> =
                SctpTsnQueue::new(self.data_sent.smallest_tsn);
            data_sent_state.append(
                &mut self
                    .data_sent
                    .iter()
                    .map(|(_, tmit_data)| tmit_data.state)
                    .collect::<VecDeque<SctpTransmitDataState>>(),
            );
            for opt in self.path_list.iter_mut() {
                if let Some(path) = opt {
                    path.on_sack_received(&data_sent_state, now);
                }
            }

            if smallest_tsn <= self.cum_ack {
                self.data_sent.drain(smallest_tsn.0, (self.cum_ack + 1).0);
            }
            self.check_datas_lost();
        }
    }

    fn on_data_acked(&mut self, tsn: SerialNumber<u32>, state: SctpTransmitDataState) {
        if tsn < self.cum_ack {
            return;
        }
        if tsn > self.largest_tsn {
            return; // Protocol violation
        }

        if let Some(recovery_point) = self.recovery_point {
            if recovery_point == tsn && state == SctpTransmitDataState::CumAcked {
                self.on_exit_recovery();
            }
        }

        let tmit_data = self.data_sent.get_mut(tsn.0).unwrap();

        if tmit_data.state != state {
            trace!(
                "{} Acked tsn={}, old_state={:?}, state={:?}",
                self.trace_id,
                tsn,
                tmit_data.state,
                state
            );
        }

        match state {
            SctpTransmitDataState::GapAcked | SctpTransmitDataState::CumAcked => {
                if tmit_data.state == SctpTransmitDataState::Sent {
                    self.total_flight -= tmit_data.bytes_len;
                    self.total_flight_count -= 1;
                }
                tmit_data.state = state;
            }
            _ => {
                return;
            }
        }

        trace!(
            "{} total_flight={}, total_flight_count={}",
            self.trace_id,
            self.total_flight,
            self.total_flight_count
        );
    }

    fn on_enter_recovery(&mut self, pathid: usize) {
        if self.fast_recovery {
            return;
        }
        trace!(
            "{} enter recovery pathid={}, recovery_point({:?})",
            self.trace_id,
            pathid,
            self.recovery_point
        );

        self.fast_recovery = true;
        self.recovery_point = Some(self.largest_tsn.0);
        if let Some(path) = self.get_path_mut(pathid) {
            path.on_enter_recovery();
        }
    }

    fn on_exit_recovery(&mut self) {
        trace!("{} exit recovery", self.trace_id);

        self.fast_recovery = false;
        self.recovery_point = None;
        for opt in self.path_list.iter_mut() {
            if let Some(path) = opt {
                path.on_exit_recovery();
            }
        }
    }

    pub fn on_enter_shutdown(&mut self, cumulative_tsn_ack: u32) -> bool {
        trace!(
            "{} enter shutdown cumulative_tsn_ack={}",
            self.trace_id,
            cumulative_tsn_ack
        );
        self.peer_cumulative_tsn_ack = Some(cumulative_tsn_ack);
        if self.shutdown_received {
            return self.check_shutdown_ready();
        }
        if !self.shutdown_pending {
            self.established = false;
            self.shutdown_pending = true;
        }
        return self.check_shutdown_ready();
    }

    pub fn on_shutdown_received(&mut self) -> bool {
        if self.shutdown_pending {
            self.shutdown_pending = false;
        }

        if !self.shutdown_received {
            self.established = false;
            self.shutdown_received = true;
        }
        return self.check_shutdown_ready();
    }

    fn check_shutdown_ready(&mut self) -> bool {
        if self.data_sent.is_empty() {
            if self.shutdown_pending {
                // Send Shutdown
                assert!(!self.shutdown_received);
                let shutdown = SctpChunk::Shutdown(self.peer_cumulative_tsn_ack.unwrap());
                trace!(
                    "{} send SHUTDONW peer_cumulative_tsn_ack={}",
                    self.trace_id,
                    self.peer_cumulative_tsn_ack.unwrap()
                );
                self.control_waiting_trans.insert(
                    self.next_control_sequence.0,
                    (shutdown, self.primary_path.unwrap_or(0)),
                );
                self.next_control_sequence += 1;
            }

            if self.shutdown_received {
                // Send Shutdown-ACK
                assert!(!self.shutdown_pending);
                let shutdown_ack = SctpChunk::ShutdownAck;
                trace!("{} send SHUTDONW-ACK", self.trace_id);
                self.control_waiting_trans.insert(
                    self.next_control_sequence.0,
                    (shutdown_ack, self.primary_path.unwrap_or(0)),
                );
                self.next_control_sequence += 1;
            }
            true
        } else {
            false
        }
    }

    pub fn on_shutdown_ack_received(&mut self) {
        self.t2_shutdown_timeout = None;
        // Send Shutdown-Complete
        let shutdown_complete = SctpChunk::ShutdownComplete(false);
        trace!("{} send SHUTDONW-COMPLETION", self.trace_id);
        self.control_waiting_trans.insert(
            self.next_control_sequence.0,
            (shutdown_complete, self.primary_path.unwrap_or(0)),
        );
        self.next_control_sequence += 1;
    }
}

impl SctpPath {
    fn update_rtt(&mut self, sent_time: Instant, recv_time: Instant) {
        self.latest_rtt = recv_time - sent_time;
        match self.srtt {
            None => {
                self.srtt = Some(self.latest_rtt);
                self.rttvar = self.latest_rtt / 2;
            }
            Some(srtt) => {
                self.rttvar = self.rttvar.mul_f64(1.0 - RTO_BETA)
                    + srtt
                        .checked_sub(self.latest_rtt)
                        .unwrap_or_else(|| self.latest_rtt - srtt)
                        .mul_f64(RTO_BETA);
                self.srtt =
                    Some(srtt.mul_f64(1.0 - RTO_ALPHA) + self.latest_rtt.mul_f64(RTO_ALPHA));
            }
        }
        trace!(
            "{} RTT: {:?}, Smoothed RTT: {:?}",
            self.trace_id,
            self.latest_rtt,
            self.srtt.unwrap()
        );
    }

    fn get_state(&self) -> Option<(bool, SctpPathState)> {
        Some((self.confirmed, self.state))
    }

    fn get_rto(&self) -> Duration {
        if let Some(srtt) = self.srtt {
            std::cmp::max(
                std::cmp::min(
                    (srtt + self.rttvar * 4) * 2_u32.pow(self.retrans_count),
                    RTO_MAX,
                ),
                RTO_MIN,
            )
        } else {
            std::cmp::min(RTO_INITIAL * 2_u32.pow(self.retrans_count), RTO_MAX)
        }
    }

    fn get_t1_timeout(&self, now: Instant) -> Option<Instant> {
        if let Some(t1_timeout) = self.t1_timeout {
            if t1_timeout <= now {
                return Some(now);
            } else {
                return Some(t1_timeout);
            }
        } else {
            return None;
        }
    }

    fn get_idle_timeout(&self, now: Instant) -> Option<Instant> {
        let rto = self.get_rto();
        if let Some(last_time) = self.last_time {
            if now.duration_since(last_time) > rto + HB_INTERVAL {
                return Some(now);
            } else {
                return Some(now + rto + HB_INTERVAL - now.duration_since(last_time));
            }
        } else {
            if self.next_hb_sequence == 0 {
                return Some(now);
            } else {
                return None;
            }
        }
    }

    fn get_heartbeats_timeout(&self, now: Instant) -> Option<Instant> {
        if let Some(heartbeat_timeout) = self.heartbeat_timeout {
            if heartbeat_timeout <= now {
                return Some(now);
            } else {
                return Some(heartbeat_timeout);
            }
        }
        return None;
    }

    fn get_t3_retrans_timeout(&self, now: Instant) -> Option<Instant> {
        if let Some(t3_timeout) = self.t3_retrans_timeout {
            if t3_timeout <= now {
                return Some(now);
            } else {
                return Some(t3_timeout);
            }
        }
        return None;
    }

    fn on_t1_timeout(&mut self, now: Instant) -> Option<(SctpChunk, usize)> {
        if self.t1_timeout.is_none() {
            return None;
        }
        let t1_timeout = self.t1_timeout.unwrap();
        if t1_timeout > now {
            return None;
        }
        self.t1_timeout = None;

        trace!("{} T1 INIT timeout fired pathid={}", self.trace_id, self.id);

        let mut iter =
            self.control_sent
                .iter()
                .enumerate()
                .filter_map(|(i, x)| match x.chunk.get_type() {
                    SctpChunkType::Init | SctpChunkType::CookieEcho => Some(i),
                    _ => None,
                });

        if let Some(i) = iter.next() {
            let tmit_ctrl = self.control_sent.remove(i).unwrap();
            if self.state != SctpPathState::InActive {
                self.retrans_count += 1;
                if self.retrans_count >= self.retrans_threshold {
                    self.state = SctpPathState::InActive;
                }
            }
            trace!(
                "{} try to retransmit INIT pathid={}",
                self.trace_id,
                self.id
            );
            return Some((tmit_ctrl.chunk, tmit_ctrl.pathid));
        }
        return None;
    }

    fn on_idle_timeout(&mut self, now: Instant) -> Option<(SctpChunk, usize)> {
        trace!("{} IDLE timeout fired pathid={}", self.trace_id, self.id);

        let rto = self.get_rto();
        if !self.wait_hb_trans
            && (self.last_time.is_none()
                || now.duration_since(self.last_time.unwrap()) > rto + HB_INTERVAL)
        {
            let heartbeat = SctpChunk::HeartbeatWithInfo(SctpHeartbeatInfo {
                sequence: self.next_hb_sequence,
                pathid: self.id,
                random_value: self.random_value,
            });
            self.next_hb_sequence += 1;
            self.wait_hb_trans = true;

            trace!(
                "{} try to transmit HEARTBEAT pathid={}",
                self.trace_id,
                self.id
            );
            return Some((heartbeat, self.id));
        }
        return None;
    }

    fn on_heartbeats_timeout(&mut self, now: Instant) {
        trace!(
            "{} HEARTBEAT timeout fired pathid={}",
            self.trace_id,
            self.id
        );

        self.check_heartbeats_lost(now);
        if let Some(heartbeat_timeout) = self.heartbeat_timeout {
            if heartbeat_timeout <= now {
                self.heartbeat_timeout = None;
            }
        }
    }

    fn on_t3_retrans_timeout(&mut self, now: Instant) -> bool {
        if self.t3_retrans_timeout.is_none() {
            return false;
        }
        let t3_timeout = self.t3_retrans_timeout.unwrap();
        if t3_timeout > now {
            return false;
        }
        self.t3_retrans_timeout = None;

        trace!(
            "{} T3 retransmission timeout fired pathid={}",
            self.trace_id,
            self.id
        );

        self.ssthresh = std::cmp::max(
            self.mtu.checked_mul(4).unwrap_or_else(|| std::usize::MAX),
            self.cwnd / 2,
        );
        self.cwnd = self.mtu;

        trace!(
            "{} congestion control pathid={}, cwnd={}, ssthresh={}",
            self.trace_id,
            self.id,
            self.cwnd,
            self.ssthresh
        );

        if self.state != SctpPathState::InActive {
            self.retrans_count += 1;
            if self.retrans_count >= self.retrans_threshold {
                self.state = SctpPathState::InActive;
            }
        }

        for sequence in self.data_sent.keys().map(|x| *x).collect::<Vec<u64>>() {
            if let Some(tmit_data_info) = self.data_sent.remove(&sequence) {
                self.flight -= tmit_data_info.bytes_len;
                self.flight_count -= 1;
            }
        }

        trace!(
            "{} t3 retransmission pathid={}, flight={}, flight_count={}",
            self.trace_id,
            self.id,
            self.flight,
            self.flight_count
        );
        self.wait_t3_retrans = true;

        self.lowest_sequence = None;
        return true;
    }

    pub fn on_control_sent(&mut self, chunk: SctpChunk, now: Instant) {
        match chunk {
            SctpChunk::Init(..) | SctpChunk::CookieEcho(..) => {
                self.control_sent.push_back(SctpTransmitControlChunk {
                    chunk: chunk,
                    pathid: self.id,
                    time: now,
                });
                self.last_time = Some(now);
                let rto = self.get_rto();
                trace!("{} set T1 INIT timeout rto={:?}", self.trace_id, rto);
                self.t1_timeout = Some(now + rto);
            }
            SctpChunk::HeartbeatWithInfo(hbinfo) => {
                self.heartbeat_sent.insert(
                    hbinfo.sequence,
                    SctpTransmitHeartbeatChunk {
                        hbinfo: hbinfo,
                        pathid: self.id,
                        time: now,
                    },
                );
                self.wait_hb_trans = false;
                self.last_time = Some(now);
                let rto = self.get_rto();
                trace!("{} set HEARTBEAT timeout rto={:?}", self.trace_id, rto);
                self.heartbeat_timeout = Some(now + rto);
            }
            _ => {}
        }
    }

    pub fn on_t1_chunk_received(&mut self, now: Instant) -> Option<SctpChunk> {
        self.t1_timeout = None;

        let mut iter =
            self.control_sent
                .iter()
                .enumerate()
                .filter_map(|(i, x)| match x.chunk.get_type() {
                    SctpChunkType::Init | SctpChunkType::CookieEcho => Some(i),
                    _ => None,
                });

        if let Some(i) = iter.next() {
            let tmit_ctrl = self.control_sent.remove(i).unwrap();
            self.update_rtt(tmit_ctrl.time, now);
            return Some(tmit_ctrl.chunk);
        } else {
            return None;
        }
    }

    pub fn on_heartbeatack_received(&mut self, chunk: SctpChunk, now: Instant) {
        if let SctpChunk::HeartbeatAckWithInfo(hbinfo) = chunk {
            if let Some(tmit_chunk) = self.heartbeat_sent.remove(&hbinfo.sequence) {
                if tmit_chunk.hbinfo.random_value == hbinfo.random_value {
                    if !self.confirmed {
                        self.confirmed = true;
                    }
                    self.update_rtt(tmit_chunk.time, now);
                    self.heartbeat_timeout = None;
                }
            }
        }
    }

    fn check_heartbeats_lost(&mut self, now: Instant) {
        let range_iter = self.heartbeat_sent.range(None, Some(self.next_hb_sequence));
        let lost_hbs: Vec<u64> = range_iter
            .filter_map(|(sequence, tmit_hb)| {
                if now.duration_since(tmit_hb.time) > self.get_rto() {
                    Some(*sequence)
                } else {
                    None
                }
            })
            .collect();
        if !lost_hbs.is_empty() {
            self.on_heartbeats_lost(lost_hbs);
        }
    }

    fn on_heartbeats_lost(&mut self, lost_hbs: Vec<u64>) {
        for sequence in lost_hbs {
            if let Some(_) = self.heartbeat_sent.remove(&sequence) {
                trace!("{} lost Heartbeat sequence={}", self.trace_id, sequence);
                if self.state != SctpPathState::InActive {
                    self.retrans_count += 1;
                    if self.retrans_count >= self.retrans_threshold {
                        self.state = SctpPathState::InActive;
                    }
                }
            }
        }
    }

    pub fn on_data_sent(
        &mut self,
        tsn: SerialNumber<u32>,
        bytes_len: usize,
        retrans: bool,
        earliest_retrans: bool,
        now: Instant,
    ) -> bool {
        let sequence = self.next_sequence;
        self.next_sequence += 1;

        self.data_sent.insert(
            sequence.0,
            SctpTransmitDataInfo {
                pathid: self.id,
                sequence: sequence,
                tsn: tsn,
                bytes_len: bytes_len,
                state: SctpTransmitDataState::Sent,
                time: now,
                do_rtt: self.needs_new_rtt && !retrans,
            },
        );

        if self.lowest_sequence.is_none() {
            self.lowest_sequence = Some(sequence);
        }

        self.last_time = Some(now);
        if self.t3_retrans_timeout.is_none() {
            let rto = self.get_rto();
            self.t3_retrans_timeout = Some(now + rto);
            trace!(
                "{} start T3 retransmission timeout rto={:?}",
                self.trace_id,
                rto
            );
        } else {
            if earliest_retrans {
                let rto = self.get_rto();
                self.t3_retrans_timeout = Some(now + rto);
                trace!(
                    "{} restart T3 retransmission timeout rto={:?}",
                    self.trace_id,
                    rto
                );
            }
        }

        self.flight += bytes_len;
        self.flight_count += 1;

        trace!(
            "{} transmission DATA tsn={}, pathid={}, flight={}, flight_count={}",
            self.trace_id,
            tsn,
            self.id,
            self.flight,
            self.flight_count
        );

        return self.needs_new_rtt;
    }

    fn check_datas_lost(&mut self, data_sent_state: &SctpTsnQueue<SctpTransmitDataState>) -> bool {
        if data_sent_state.is_empty() {
            return false;
        }

        let tsn_array = self
            .data_sent
            .range(None, None)
            .map(|(key, tmit_data_info)| (*key, tmit_data_info.tsn.0, tmit_data_info.state))
            .collect::<Vec<(u64, u32, SctpTransmitDataState)>>();

        if tsn_array.is_empty() {
            return false;
        }

        self.lowest_sequence = None;

        let lost_tsn_array = tsn_array
            .into_iter()
            .filter_map(|(sequence, tsn, _)| {
                assert!(tsn >= data_sent_state.smallest_tsn);
                if let Some(state1) = data_sent_state.get(tsn) {
                    if *state1 != SctpTransmitDataState::Lost {
                        if self.lowest_sequence.is_none() {
                            self.lowest_sequence = Some(SerialNumber(sequence));
                        }
                        return None;
                    }
                }
                return Some((sequence, tsn, SctpTransmitDataState::Lost));
            })
            .collect::<Vec<(u64, u32, SctpTransmitDataState)>>();

        if lost_tsn_array.is_empty() {
            return false;
        }
        self.on_datas_lost(lost_tsn_array);
        return true;
    }

    fn on_datas_lost(&mut self, lost_tsn_array: Vec<(u64, u32, SctpTransmitDataState)>) {
        for (sequence, tsn, _) in lost_tsn_array {
            let tmit_data_info = self.data_sent.remove(&sequence).unwrap();

            trace!(
                "{} lost DATA tsn={}, sequence={}, pathid={}",
                self.trace_id,
                tsn,
                sequence,
                self.id,
            );
            if tmit_data_info.state == SctpTransmitDataState::Sent {
                self.flight -= tmit_data_info.bytes_len;
                self.flight_count -= 1;
            }
        }
        self.wait_fast_retrans = true;
    }

    fn on_sack_received(
        &mut self,
        data_sent_state: &SctpTsnQueue<SctpTransmitDataState>,
        now: Instant,
    ) {
        if data_sent_state.is_empty() {
            return;
        }

        let tsn_array = self
            .data_sent
            .range(None, None)
            .map(|(key, tmit_data_info)| (*key, tmit_data_info.tsn.0, tmit_data_info.state))
            .collect::<Vec<(u64, u32, SctpTransmitDataState)>>();
        if tsn_array.is_empty() {
            return;
        }

        let mut lowest_tsn = None;

        for (sequence, tsn, state) in tsn_array {
            assert!(tsn >= data_sent_state.smallest_tsn);
            if tsn == data_sent_state.smallest_tsn {
                lowest_tsn = Some(tsn);
            }
            match data_sent_state.get(tsn) {
                Some(&new_state) => {
                    if (state == SctpTransmitDataState::Sent
                        && new_state == SctpTransmitDataState::GapAcked)
                        || new_state == SctpTransmitDataState::CumAcked
                    {
                        self.on_data_acked(sequence, new_state, now);
                    } else {
                        if let Some(tmit_data_info) = self.data_sent.get_mut(&sequence) {
                            if new_state != state {
                                tmit_data_info.state = new_state;
                            }
                        }
                    }
                }
                None => {}
            }
        }
        if self.data_sent.is_empty() {
            self.t3_retrans_timeout = None;
            trace!("{} stop T3 retransmission timeout", self.trace_id);
        } else {
            if let Some(tsn) = lowest_tsn {
                match data_sent_state.get(tsn) {
                    Some(SctpTransmitDataState::GapAcked)
                    | Some(SctpTransmitDataState::CumAcked) => {
                        let rto = self.get_rto();
                        self.t3_retrans_timeout = Some(now + rto);
                        trace!(
                            "{} restart T3 retransmission timeout rto={:?}",
                            self.trace_id,
                            rto
                        );
                    }
                    _ => {}
                }
            }
        }
        self.congestion_control();
    }

    fn on_data_acked(&mut self, sequence: u64, state: SctpTransmitDataState, now: Instant) {
        let mut do_rtt = false;
        let mut tmit_time = Instant::now();
        if let Some(tmit_data_info) = self.data_sent.remove(&sequence) {
            trace!(
                "{} Acked tsn={}, sequence={}, old_state={:?}, state={:?}",
                self.trace_id,
                tmit_data_info.tsn,
                sequence,
                tmit_data_info.state,
                state
            );

            if tmit_data_info.state == SctpTransmitDataState::Sent {
                if tmit_data_info.do_rtt {
                    do_rtt = true;
                    tmit_time = tmit_data_info.time;
                    self.needs_new_rtt = true;
                }
                self.flight -= tmit_data_info.bytes_len;
                self.flight_count -= 1;
                if state == SctpTransmitDataState::CumAcked {
                    self.ack += tmit_data_info.bytes_len;
                }
            }

            if do_rtt {
                self.update_rtt(tmit_time, now);
            }
        }
    }

    fn congestion_control(&mut self) {
        if !self.fast_recovery {
            self.increase_cwnd();
        }
    }

    fn on_enter_recovery(&mut self) {
        let old_ssthresh = self.ssthresh;
        let old_cwnd = self.cwnd;
        self.ssthresh = std::cmp::max(self.cwnd / 2, 4 * self.mtu);
        self.cwnd = self.ssthresh;
        self.fast_recovery = true;
        trace!(
            "{} enter recovery pathid={}, old_ssthresh={}, ssthresh={}, old_cwnd={}, cwnd={}",
            self.trace_id,
            self.id,
            old_ssthresh,
            self.ssthresh,
            old_cwnd,
            self.cwnd
        );
    }

    fn on_exit_recovery(&mut self) {
        self.fast_recovery = false;
        trace!("{} exit recovery pathid={}", self.trace_id, self.id);
    }

    fn increase_cwnd(&mut self) {
        let old_cwnd = self.cwnd;
        if self.cwnd <= self.ssthresh {
            if self.flight + self.ack >= self.cwnd {
                let increment = std::cmp::max(self.ack, self.mtu);
                self.cwnd += increment;
            }
            trace!(
                "{} increase cwnd pathid={}, ssthresh={}, old_cwnd={}, cwnd={}, ack={}",
                self.trace_id,
                self.id,
                self.ssthresh,
                old_cwnd,
                self.cwnd,
                self.ack
            );
        } else {
            let old_partial_bytes_acked = self.partial_bytes_acked;
            self.partial_bytes_acked += self.ack;
            if self.partial_bytes_acked >= self.cwnd {
                self.cwnd += self.mtu;
                self.partial_bytes_acked =
                    self.partial_bytes_acked.checked_sub(self.cwnd).unwrap_or(0);
            }
            trace!(
                "{} increase cwnd pathid={}, ssthresh={}, old_cwnd={}, cwnd={}, ack={}, old_partial_bytes_acked={}, partial_bytes_acked={}",
                self.trace_id,
                self.id,
                self.ssthresh,
                old_cwnd,
                self.cwnd,
                self.ack,
                old_partial_bytes_acked,
                self.partial_bytes_acked

            );
        }
        self.ack = 0;
    }
}

impl SctpTransmitData {
    pub fn new(chunk: SctpChunk, bytes_len: usize, tsn: u32, pathid: usize) -> Self {
        SctpTransmitData {
            chunk: vec![chunk],
            pathid: pathid,
            tsn: tsn,
            bytes_len: bytes_len,
            in_flight: false,
            retrans: false,
            fast_retrans: false,
            miss_indications: 0,
            state: SctpTransmitDataState::Sent,
            gapacked: false,
        }
    }
}

/*
#[test]
fn test_recovery_all_data_acked() {
    let mut recovery = SctpRecovery::new(0).unwrap();
    let datachunk = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 0,
        stream_id: 0,
        stream_seq: 1,
        proto_id: 0,
        data: vec![1u8],
    };
    let sackchunk = SctpSackChunk {
        cum_ack: 0,
        a_rwnd: 1024,
        num_gap_ack: 0,
        num_dup_ack: 0,
        gap_acks: Vec::new(),
        dup_acks: Vec::new(),
    };

    recovery.on_data_sent(SctpChunk::Data(datachunk), 0);
    assert_eq!(recovery.total_flight, 1);
    assert_eq!(recovery.total_flight_count, 1);
    recovery.on_sack_received(SctpChunk::Sack(sackchunk));
    assert_eq!(recovery.total_flight, 0);
    assert_eq!(recovery.total_flight_count, 0);
}

#[test]
fn test_recovery_some_data_cum_acked() {
    let mut recovery = SctpRecovery::new(0xffffffff).unwrap();
    let datachunk0 = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 0xffffffff,
        stream_id: 0,
        stream_seq: 1,
        proto_id: 0,
        data: vec![1u8],
    };
    let mut datachunk1 = datachunk0.clone();
    datachunk1.tsn = 0;
    datachunk1.stream_seq += 1;
    let sackchunk = SctpSackChunk {
        cum_ack: 0xffffffff,
        a_rwnd: 1024,
        num_gap_ack: 0,
        num_dup_ack: 0,
        gap_acks: Vec::new(),
        dup_acks: Vec::new(),
    };

    assert_eq!(recovery.cum_ack, 0xffffffff - 1);
    recovery.on_data_sent(SctpChunk::Data(datachunk0), 0);
    recovery.on_data_sent(SctpChunk::Data(datachunk1), 0);
    assert_eq!(recovery.total_flight, 2);
    assert_eq!(recovery.total_flight_count, 2);
    recovery.on_sack_received(SctpChunk::Sack(sackchunk));
    assert_eq!(recovery.total_flight, 1);
    assert_eq!(recovery.total_flight_count, 1);
    assert_eq!(recovery.cum_ack, 0xffffffff);
}

#[test]
fn test_recovery_some_data_gap_acked() {
    let mut recovery = SctpRecovery::new(0xffffffff).unwrap();
    let datachunk0 = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 0xffffffff,
        stream_id: 0,
        stream_seq: 1,
        proto_id: 0,
        data: vec![1u8],
    };
    let mut datachunk1 = datachunk0.clone();
    datachunk1.tsn = 0;
    datachunk1.stream_seq += 1;
    let sackchunk0 = SctpSackChunk {
        cum_ack: 0xffffffff - 1,
        a_rwnd: 1024,
        num_gap_ack: 1,
        num_dup_ack: 0,
        gap_acks: vec![SctpGapAckBlock { start: 2, end: 2 }],
        dup_acks: Vec::new(),
    };
    let sackchunk1 = SctpSackChunk {
        cum_ack: 0,
        a_rwnd: 1024,
        num_gap_ack: 0,
        num_dup_ack: 0,
        gap_acks: Vec::new(),
        dup_acks: Vec::new(),
    };

    assert_eq!(recovery.cum_ack, 0xffffffff - 1);
    recovery.on_data_sent(SctpChunk::Data(datachunk0), 0);
    recovery.on_data_sent(SctpChunk::Data(datachunk1), 0);
    assert_eq!(recovery.total_flight, 2);
    assert_eq!(recovery.total_flight_count, 2);
    recovery.on_sack_received(SctpChunk::Sack(sackchunk0));
    assert_eq!(recovery.total_flight, 1);
    assert_eq!(recovery.total_flight_count, 1);
    assert_eq!(recovery.cum_ack, 0xffffffff - 1);
    recovery.on_sack_received(SctpChunk::Sack(sackchunk1));
    assert_eq!(recovery.total_flight, 0);
    assert_eq!(recovery.total_flight_count, 0);
    assert_eq!(recovery.cum_ack, 0);
}

#[test]
fn test_recovery_gap_acked_and_revoked() {
    let mut recovery = SctpRecovery::new(0xffffffff).unwrap();
    let datachunk0 = SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 0xffffffff,
        stream_id: 0,
        stream_seq: 1,
        proto_id: 0,
        data: vec![1u8],
    };
    let mut datachunk1 = datachunk0.clone();
    datachunk1.tsn = 0;
    datachunk1.stream_seq += 1;
    let sackchunk0 = SctpSackChunk {
        cum_ack: 0xffffffff - 1,
        a_rwnd: 1024,
        num_gap_ack: 1,
        num_dup_ack: 0,
        gap_acks: vec![SctpGapAckBlock { start: 2, end: 2 }],
        dup_acks: Vec::new(),
    };
    let sackchunk1 = SctpSackChunk {
        cum_ack: 0xffffffff,
        a_rwnd: 1024,
        num_gap_ack: 0,
        num_dup_ack: 0,
        gap_acks: Vec::new(),
        dup_acks: Vec::new(),
    };

    assert_eq!(recovery.cum_ack, 0xffffffff - 1);
    recovery.on_data_sent(SctpChunk::Data(datachunk0), 0);
    recovery.on_data_sent(SctpChunk::Data(datachunk1), 0);
    assert_eq!(recovery.total_flight, 2);
    assert_eq!(recovery.total_flight_count, 2);
    recovery.on_sack_received(SctpChunk::Sack(sackchunk0));
    assert_eq!(recovery.total_flight, 1);
    assert_eq!(recovery.total_flight_count, 1);
    assert_eq!(recovery.cum_ack, 0xffffffff - 1);
    recovery.on_sack_received(SctpChunk::Sack(sackchunk1));
    assert_eq!(recovery.total_flight, 0);
    assert_eq!(recovery.total_flight_count, 0);
    assert_eq!(recovery.cum_ack, 0xffffffff);
}
*/
