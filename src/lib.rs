#[macro_use]
extern crate nom;
#[macro_use]
extern crate rusticata_macros;
#[macro_use]
extern crate log;

extern crate crc;
extern crate crypto;
extern crate sna;

use std::cmp;
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use crc::crc32;
use sna::SerialNumber;

use crate::sctp_mapping_array::SctpMappingArray;
use crate::sctp_recovery::{SctpPathState, SctpRecovery};
use crate::sctp_stream::{SctpStreamIn, SctpStreamIter, SctpStreamOut};
pub use sctp_pkt::*;

mod sctp_collections;
mod sctp_mapping_array;
pub mod sctp_pkt;
mod sctp_recovery;
mod sctp_stream;

pub type Result<T> = std::result::Result<T, SctpError>;

const MAX_BURST: usize = 4;

const DEFAULT_ACK_DELAY: Duration = Duration::from_millis(200);
const _MAX_ACK_DELAY: Duration = Duration::from_millis(500);
const DEFAULT_ACK_FREQ: u32 = 2;

const DEFAULT_MTU: usize = 1500;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum SctpError {
    Done = -1,
    InvalidChunk = -2,
    TooShort = -3,
    InvalidValue = -4,
    ProtocolViolation = -5,
    NotFound = -6,
    OOTB = -7,
}

#[derive(Debug)]
pub struct SctpAssociation {
    pub src_port: u16,
    pub dst_port: u16,
    pub my_vtag: u32,
    pub peer_vtag: u32,

    state: SctpAssociationState,

    a_rwnd: u32,

    initial_tsn: SerialNumber<u32>,

    raddr_list: VecDeque<SctpRemoteAddress>,
    laddr_list: VecDeque<SctpLocalAddress>,

    delayed_ack: bool,
    num_data_pkts_seen: u32,
    ack_delay: Duration,
    ack_freq: u32,
    delayed_ack_timeout: Option<Instant>,
    send_sack: bool,

    last_data_from: Option<usize>,
    mapping_array: SctpMappingArray,
    recovery: SctpRecovery,
    stream_in: Vec<SctpStreamIn>,
    stream_out: Vec<SctpStreamOut>,

    control_waiting_trans: BTreeMap<u64, (SctpChunk, usize)>,
    next_control_sequence: SerialNumber<u64>,

    send_burst_count: usize,
    sent_data_count: usize,
    recv_data_count: usize,

    trace_id: String,
    error_cause: Option<SctpErrorCause>,
}

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum SctpAssociationState {
    Closed = 0,
    CookieWait = 1,
    CookieEchoed = 2,
    Established = 3,
    ShutdownPending = 4,
    ShutdownSent = 5,
    ShutdownReceived = 6,
    ShutdownAckSent = 7,
}

#[derive(Debug)]
struct SctpRemoteAddress {
    addr: IpAddr,
    mtu: usize,
    pathid: usize,
    state: SctpRemoteAddressState,
    is_primary: bool,
}

impl SctpRemoteAddress {
    fn new(addr: &IpAddr, mtu: usize, pathid: usize) -> Self {
        SctpRemoteAddress {
            addr: addr.clone(),
            mtu: mtu,
            state: SctpRemoteAddressState::Deleted,
            pathid: pathid,
            is_primary: false,
        }
    }
}

impl PartialEq for SctpRemoteAddress {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum SctpRemoteAddressState {
    Added,
    Deleted,
}

#[derive(Debug)]
struct SctpLocalAddress {
    addr: IpAddr,
    state: SctpLocalAddressState,
}

impl SctpLocalAddress {
    fn new(addr: &IpAddr) -> Self {
        SctpLocalAddress {
            addr: addr.clone(),
            state: SctpLocalAddressState::Empty,
        }
    }
}

impl PartialEq for SctpLocalAddress {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum SctpLocalAddressState {
    Empty,
    Adding,
    Added,
    _Deleting,
    _Deleted,
}

macro_rules! write_retrans_chunks_for_single_pkt {
    ($recovery:expr, $waiting:expr, $sbuf:expr, $send_time:expr, $fast_retrans:expr, $trace_id:expr) => {{
        if $waiting.len() > 0 {
            let old_len = $sbuf.len();
            let tsns = $waiting.keys().map(|key| *key).collect::<Vec<u32>>();
            let mut pathid = None;
            let mut entered = false;
            let mut mtu = None;
            for tsn in tsns {
                let (pathid1, bytes_len, first) = $waiting.get(&tsn).unwrap();
                if !*first {
                    continue;
                }
                let pathid1 = *pathid1;
                let bytes_len = *bytes_len;
                if pathid.is_none() {
                    pathid = Some(pathid1);
                } else {
                    if pathid.unwrap() != pathid1 {
                        continue;
                    }
                }

                if !entered {
                    entered = if $fast_retrans {
                        $recovery.enter_fast_retrans(pathid.unwrap())
                    } else {
                        $recovery.enter_t3_retrans(pathid.unwrap())
                    };
                    if !entered {
                        break;
                    }
                }

                if mtu.is_none() {
                    mtu = Some($recovery.get_path_mtu(pathid.unwrap()).unwrap());
                }
                let available_space = mtu.unwrap() - $sbuf.len().checked_sub(12).unwrap_or(0);
                if available_space < bytes_len {
                    break;
                }
                $waiting.remove(&tsn);
                if let Some(chunk) = $recovery.pop_retrans_chunk(tsn) {
                    trace!("{} retransmission tsn={}", $trace_id, tsn);
                    chunk.to_bytes($sbuf).unwrap();
                    $recovery.on_data_sent(chunk, pathid.unwrap(), $send_time, true);
                }
            }
            if $sbuf.len() > old_len {
                Ok((pathid.unwrap(), $sbuf.len() - old_len))
            } else {
                Err(SctpError::Done)
            }
        } else {
            Err(SctpError::Done)
        }
    }};
}

macro_rules! write_control_chunks {
    ($recovery:expr, $waiting:expr, $sbuf:expr, $pathid:expr, $send_time:expr, $trace_id:expr) => {{
        if $waiting.len() > 0 {
            let mut pathid = $pathid;
            let old_len = $sbuf.len();
            let sequences = $waiting.keys().map(|key| *key).collect::<Vec<u64>>();
            let mut mtu = None;
            for sequence in sequences {
                let (chunk, pathid1) = $waiting.get(&sequence).unwrap();
                if pathid.is_none() {
                    pathid = Some(*pathid1);
                } else {
                    if pathid.unwrap() != *pathid1 {
                        break;
                    }
                }
                if mtu.is_none() {
                    mtu = Some($recovery.get_path_mtu(pathid.unwrap()).unwrap());
                }

                let available_space = mtu.unwrap() - $sbuf.len().checked_sub(12).unwrap_or(0);
                if available_space < chunk.bytes_len() {
                    break;
                }
                let (chunk, _) = $waiting.remove(&sequence).unwrap();
                trace!(
                    "{} transmission CONTROL chunk type={}",
                    $trace_id,
                    chunk.get_type()
                );

                chunk.to_bytes($sbuf).unwrap();
                $recovery.on_control_sent(chunk, pathid.unwrap(), $send_time);
            }
            if pathid.is_some() && $sbuf.len() > old_len {
                Ok((pathid.unwrap(), $sbuf.len() - old_len))
            } else {
                Err(SctpError::Done)
            }
        } else {
            Err(SctpError::Done)
        }
    }};
}

macro_rules! write_retrans_chunks {
    ($recovery:expr, $waiting:expr, $sbuf:expr, $pathid:expr, $send_time:expr, $fast_retrans:expr, $trace_id:expr) => {{
        if $waiting.len() > 0 {
            let mut pathid = $pathid;
            let old_len = $sbuf.len();
            let tsns = $waiting.keys().map(|key| *key).collect::<Vec<u32>>();
            let mut mtu = None;
            for tsn in tsns {
                let (pathid1, bytes_len, _) = $waiting.get(&tsn).unwrap();
                let pathid1 = *pathid1;
                let bytes_len = *bytes_len;

                if pathid.is_none() {
                    pathid = Some(pathid1);
                } else {
                    if pathid.unwrap() != pathid1 {
                        break;
                    }
                }
                if mtu.is_none() {
                    mtu = Some($recovery.get_path_mtu(pathid.unwrap()).unwrap());
                }
                let cwnd = $recovery.get_available_cwnd(pathid.unwrap()).unwrap();

                if mtu.unwrap() <= $sbuf.len().checked_sub(12).unwrap_or(0) {
                    break;
                }
                let available_space = std::cmp::min(
                    mtu.unwrap() - $sbuf.len().checked_sub(12).unwrap_or(0),
                    cwnd,
                );
                if available_space < bytes_len {
                    break;
                }
                $waiting.remove(&tsn);
                if let Some(chunk) = $recovery.pop_retrans_chunk(tsn) {
                    trace!("{} retransmission tsn={}", $trace_id, tsn);
                    chunk.to_bytes($sbuf).unwrap();
                    $recovery.on_data_sent(chunk, pathid.unwrap(), $send_time, true);
                }
            }
            if pathid.is_some() && $sbuf.len() > old_len {
                Ok((pathid.unwrap(), $sbuf.len() - old_len))
            } else {
                Err(SctpError::Done)
            }
        } else {
            Err(SctpError::Done)
        }
    }};
}

#[derive(Clone)]
pub struct SctpStats {
    pub sent: usize,
}

impl SctpAssociation {
    pub fn connect(
        src_port: u16,
        dst_port: u16,
        src_ip_list: &Vec<IpAddr>,
        dst_ip: &IpAddr,
    ) -> Result<SctpAssociation> {
        let my_vtag = rand::random::<u32>();
        let init_tsn = rand::random::<u32>();
        let mut assoc = SctpAssociation::new(src_port, dst_port, my_vtag, 65536, init_tsn).unwrap();

        for src_ip in src_ip_list {
            assoc.add_laddr(src_ip).unwrap();
        }
        let pathid = assoc.add_raddr(&dst_ip).unwrap();
        assoc.state = SctpAssociationState::CookieWait;

        let params: Vec<SctpParameter> = assoc
            .laddr_list
            .iter()
            .filter_map(|x| match x.addr {
                IpAddr::V4(ip4) => Some(SctpParameter::Ipv4(ip4.clone())),
                IpAddr::V6(ip6) => Some(SctpParameter::Ipv6(ip6.clone())),
            })
            .collect();
        assoc.control_waiting_trans.insert(
            assoc.next_control_sequence.0,
            (
                SctpChunk::Init(SctpInitChunk {
                    init_tag: my_vtag,
                    a_rwnd: 65536,
                    num_out_strm: 10,
                    num_in_strm: 2048,
                    init_tsn: init_tsn,
                    params: params,
                }),
                pathid,
            ),
        );
        assoc.next_control_sequence += 1;
        Ok(assoc)
    }

    pub fn accept(
        rip: &IpAddr,
        header: &SctpCommonHeader,
        rbuf: &[u8],
        sbuf: &mut Vec<u8>,
        secret_key: &[u8],
    ) -> Result<(Option<SctpAssociation>, usize)> {
        trace!("accept from={}, len={}", rip, rbuf.len());
        let (chunk, consumed) = match SctpChunk::from_bytes(rbuf) {
            Ok(v) => v,
            Err(e) => {
                return Err(e);
            }
        };
        trace!("recv CHUNK type={}", chunk.get_type());

        match chunk {
            SctpChunk::Init(v) => {
                let my_vtag = rand::random::<u32>();

                let new_header = SctpCommonHeader {
                    src_port: header.dst_port,
                    dst_port: header.src_port,
                    vtag: v.init_tag,
                    checksum: 0,
                };
                let mut init_ack_contents = SctpInitChunk {
                    init_tag: my_vtag,
                    a_rwnd: 65536,
                    num_out_strm: 10,
                    num_in_strm: 2048,
                    init_tsn: rand::random::<u32>(),
                    params: Vec::new(),
                };
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                let cookie = SctpStateCookie {
                    init: SctpChunk::Init(v.clone()),
                    init_ack: SctpChunk::InitAck(init_ack_contents.clone()),
                    my_vtag: my_vtag,
                    peer_vtag: new_header.vtag,
                    src_port: new_header.src_port,
                    dst_port: new_header.dst_port,
                    dst_addr: rip.clone(),
                    time: now.as_secs(),
                };
                let mut cookie_bytes = Vec::new();
                cookie.to_bytes(secret_key, &mut cookie_bytes).unwrap();
                init_ack_contents
                    .params
                    .push(SctpParameter::Cookie(cookie_bytes));
                let init_ack = SctpChunk::InitAck(init_ack_contents);
                new_header.to_bytes(sbuf).unwrap();
                init_ack.to_bytes(sbuf).unwrap();
                SctpAssociation::set_checksum(sbuf);
                trace!("send INIT-ACK to {}", rip);
                return Ok((None, consumed));
            }
            SctpChunk::CookieEcho(v) => {
                let (cookie, _) = match SctpStateCookie::from_bytes(secret_key, &v) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(e);
                    }
                };
                let (peer_init_tsn, peer_a_rwnd, peer_num_in_strm, peer_num_out_strm, peer_params) =
                    match cookie.init {
                        SctpChunk::Init(v) => (
                            v.init_tsn,
                            v.a_rwnd,
                            v.num_in_strm,
                            v.num_out_strm,
                            v.params,
                        ),
                        _ => (0, 0, 0, 0, Vec::new()),
                    };
                let (my_init_tsn, my_a_rwnd, my_num_in_strm, my_num_out_strm) = match cookie
                    .init_ack
                {
                    SctpChunk::InitAck(v) => (v.init_tsn, v.a_rwnd, v.num_in_strm, v.num_out_strm),
                    _ => (0, 0, 0, 0),
                };
                let mut assoc = SctpAssociation::new(
                    cookie.src_port,
                    cookie.dst_port,
                    cookie.my_vtag,
                    my_a_rwnd,
                    my_init_tsn,
                )
                .unwrap();

                trace!("new association my_vtag={}", cookie.my_vtag);

                assoc.mapping_array.initialize(peer_init_tsn).unwrap();
                assoc.peer_vtag = cookie.peer_vtag;
                assoc
                    .generate_stream_in(cmp::min(my_num_in_strm, peer_num_out_strm))
                    .unwrap();
                assoc
                    .generate_stream_out(cmp::min(my_num_out_strm, peer_num_in_strm))
                    .unwrap();

                for param in peer_params {
                    let ip = match param {
                        SctpParameter::Ipv4(addr4) => IpAddr::V4(addr4),
                        SctpParameter::Ipv6(addr6) => IpAddr::V6(addr6),
                        _ => {
                            continue;
                        }
                    };
                    if let Err(e) = assoc.add_raddr(&ip) {
                        if e != SctpError::Done {
                            return Err(e);
                        }
                    }
                }

                let pathid = match assoc.get_pathid(&cookie.dst_addr) {
                    Some(v) => v,
                    None => {
                        let ret = assoc.add_raddr(&cookie.dst_addr);
                        if ret.is_err() {
                            return Err(ret.unwrap_err());
                        }
                        ret.unwrap()
                    }
                };

                assoc.recovery.initialize(peer_a_rwnd as usize);
                assoc.recovery.establish();
                assoc.recovery.confirm_path(pathid).unwrap();
                assoc.set_primary_path(pathid).unwrap();

                assoc.state = SctpAssociationState::Established;
                assoc.control_waiting_trans.insert(
                    assoc.next_control_sequence.0,
                    (SctpChunk::CookieAck, pathid),
                );
                assoc.next_control_sequence += 1;
                return Ok((Some(assoc), consumed));
            }
            _ => {
                SctpAssociation::handle_ootb(header, chunk, sbuf);
                return Ok((None, consumed));
            }
        }
    }

    fn handle_ootb(header: &SctpCommonHeader, chunk: SctpChunk, sbuf: &mut Vec<u8>) {
        let sending_chunk = match chunk.get_type() {
            SctpChunkType::Abort | SctpChunkType::ShutdownComplete => {
                return;
            }
            SctpChunkType::ShutdownAck => SctpChunk::ShutdownComplete(true),
            _ => SctpChunk::Abort(SctpAbortChunk {
                t_bit: true,
                error_cause: None,
            }),
        };
        let new_header = SctpCommonHeader {
            src_port: header.dst_port,
            dst_port: header.src_port,
            vtag: header.vtag,
            checksum: 0,
        };
        new_header.to_bytes(sbuf).unwrap();
        sending_chunk.to_bytes(sbuf).unwrap();
        SctpAssociation::set_checksum(sbuf);
    }

    fn new(
        src_port: u16,
        dst_port: u16,
        vtag: u32,
        a_rwnd: u32,
        init_tsn: u32,
    ) -> Result<SctpAssociation> {
        let trace_id = format!("{:X}", vtag);
        let assoc = SctpAssociation {
            src_port: src_port,
            dst_port: dst_port,
            my_vtag: vtag,
            peer_vtag: 0,
            state: SctpAssociationState::Closed,
            a_rwnd: a_rwnd,
            initial_tsn: SerialNumber(init_tsn),
            mapping_array: SctpMappingArray::new(trace_id.clone()),

            delayed_ack: true,
            num_data_pkts_seen: 0,
            ack_delay: DEFAULT_ACK_DELAY,
            ack_freq: DEFAULT_ACK_FREQ,
            delayed_ack_timeout: None,

            last_data_from: None,
            send_sack: false,

            stream_in: Vec::new(),
            stream_out: Vec::new(),
            control_waiting_trans: BTreeMap::new(),
            next_control_sequence: SerialNumber(0),
            recovery: SctpRecovery::new(init_tsn, trace_id.clone()).unwrap(),
            raddr_list: VecDeque::new(),
            laddr_list: VecDeque::new(),
            send_burst_count: 0,
            sent_data_count: 0,
            recv_data_count: 0,

            trace_id: trace_id.clone(),
            error_cause: None,
        };
        Ok(assoc)
    }

    fn generate_stream_in(&mut self, num_in_strm: u16) -> Result<u16> {
        self.stream_in = (0..num_in_strm).map(|i| SctpStreamIn::new(i)).collect();
        Ok(num_in_strm)
    }

    fn generate_stream_out(&mut self, num_out_strm: u16) -> Result<u16> {
        self.stream_out = (0..num_out_strm)
            .map(|i| SctpStreamOut::new(i as u16))
            .collect();
        Ok(num_out_strm)
    }

    pub fn add_laddr(&mut self, addr: &IpAddr) -> Result<()> {
        let ret = self.laddr_list.iter_mut().find(|x| x.addr == *addr);
        let mut laddr = if ret.is_some() {
            ret.unwrap()
        } else {
            self.laddr_list.push_back(SctpLocalAddress::new(addr));
            self.laddr_list.back_mut().unwrap()
        };

        if laddr.state == SctpLocalAddressState::Adding
            || laddr.state == SctpLocalAddressState::Added
        {
            trace!(
                "{} already added local address addr={}",
                self.trace_id,
                laddr.addr,
            );

            return Err(SctpError::Done);
        }
        if self.state == SctpAssociationState::Closed {
            laddr.state = SctpLocalAddressState::Added;
        } else {
            laddr.state = SctpLocalAddressState::Adding;
        }
        trace!(
            "{} local address assigned added={}",
            self.trace_id,
            laddr.addr,
        );

        Ok(())
    }

    fn add_raddr(&mut self, addr: &IpAddr) -> Result<usize> {
        let ret = self.raddr_list.iter_mut().find(|x| x.addr == *addr);
        let mut raddr = if ret.is_some() {
            ret.unwrap()
        } else {
            let len = self.raddr_list.len();
            let mtu = if addr.is_ipv4() {
                DEFAULT_MTU - 20 - 8 - 12 // IPv4 hdr, UDP hdr, and SCTP hdr
            } else {
                DEFAULT_MTU - 40 - 8 - 12 // IPv6 hdr, UDP hdr, and SCTP hdr
            };
            self.raddr_list
                .push_back(SctpRemoteAddress::new(addr, mtu, len));
            self.raddr_list.back_mut().unwrap()
        };

        if raddr.state != SctpRemoteAddressState::Deleted {
            trace!(
                "{} already assigned remote address addr={}, pathid={}",
                self.trace_id,
                raddr.addr,
                raddr.pathid
            );
            return Err(SctpError::Done);
        }
        raddr.state = SctpRemoteAddressState::Added;
        let pathid = self.recovery.add_path(raddr.mtu);
        assert!(pathid == raddr.pathid);
        trace!(
            "{} remote address assigned addr={}, pathid={}",
            self.trace_id,
            raddr.addr,
            raddr.pathid
        );
        Ok(raddr.pathid)
    }

    pub fn get_pathid(&self, addr: &IpAddr) -> Option<usize> {
        if let Some(raddr) = self.raddr_list.iter().find(|x| x.addr == *addr) {
            Some(raddr.pathid)
        } else {
            None
        }
    }

    pub fn get_remote_ip(&self, pathid: usize) -> Option<IpAddr> {
        if let Some(raddr) = self.raddr_list.get(pathid) {
            Some(raddr.addr)
        } else {
            None
        }
    }

    pub fn get_primary_path(&self) -> Option<usize> {
        self.recovery.get_primary_path()
    }

    pub fn set_primary_path(&mut self, pathid: usize) -> Result<()> {
        self.recovery.set_primary_path(pathid)
    }

    pub fn get_timeout(&self) -> Option<Duration> {
        let mut timeouts = Vec::new();
        if let Some(timeout) = self.delayed_ack_timeout {
            timeouts.push(timeout);
        }
        if let Some(timeout) = self.recovery.get_timeout() {
            timeouts.push(timeout);
        }

        let min_timeout = timeouts.into_iter().min();
        if let Some(timeout) = min_timeout {
            let now = Instant::now();
            if timeout <= now {
                return Some(Duration::new(0, 0));
            } else {
                return Some(timeout.duration_since(now));
            }
        } else {
            return None;
        }
    }

    pub fn on_timeout(&mut self) {
        let now = Instant::now();
        self.on_delayed_ack_timeout(now);
        self.recovery.on_timeout(now);
    }

    fn on_delayed_ack_timeout(&mut self, now: Instant) {
        if let Some(timeout) = self.delayed_ack_timeout {
            if timeout <= now {
                trace!("{} delayed ack timeout expired", self.trace_id);
                self.send_sack = true;
                self.delayed_ack_timeout = None;
            }
        }
    }
    fn set_delayed_ack_timer(&mut self) -> bool {
        if self.delayed_ack_timeout.is_none() {
            trace!(
                "{} set delayed ack timeout ack_delay={:?}",
                self.trace_id,
                self.ack_delay
            );
            self.delayed_ack_timeout = Some(Instant::now() + self.ack_delay);
            true
        } else {
            false
        }
    }

    fn set_checksum(sbuf: &mut Vec<u8>) {
        let checksum = crc32::checksum_castagnoli(sbuf);
        let bytes = sbuf.as_mut_slice();
        bytes[0x08] = ((checksum >> 0) & 0x000000FF) as u8;
        bytes[0x09] = ((checksum >> 8) & 0x000000FF) as u8;
        bytes[0x0a] = ((checksum >> 16) & 0x000000FF) as u8;
        bytes[0x0b] = ((checksum >> 24) & 0x000000FF) as u8;
    }

    pub fn recv(&mut self, from: &IpAddr, rbuf: &[u8], sbuf: &mut Vec<u8>) -> Result<usize> {
        let mut off = 0;
        let recv_time = Instant::now();
        let pathid = self.get_pathid(&from);
        let mut data_appears = false;

        while off < rbuf.len() {
            let (chunk, consumed) = match SctpChunk::from_bytes(&rbuf[off..]) {
                Ok(v) => v,
                Err(e) => {
                    return Err(e);
                }
            };
            off += consumed;

            trace!(
                "{} recv CHUNK type={}, from={}",
                self.trace_id,
                chunk.get_type(),
                from
            );
            if chunk.is_control() && data_appears {
                self.abort(
                    sbuf,
                    Some(SctpErrorCause::ProtocolViolation(Vec::from(
                        format!(
                            "DATA chunk followed by CONTROL chunk type={}",
                            chunk.get_type()
                        )
                        .as_str(),
                    ))),
                );
                return Err(SctpError::ProtocolViolation);
            }

            if pathid.is_none() {
                self.abort(sbuf, None);
                return Err(SctpError::OOTB);
            }

            match chunk {
                SctpChunk::Data(data_chunk) => {
                    self.recv_data_count += 1;

                    let stream_id = data_chunk.proto_id;
                    let tsn = data_chunk.tsn;

                    self.mapping_array.update(tsn)?;

                    let stream_in = match self.stream_in.get_mut(stream_id as usize) {
                        Some(v) => v,
                        None => {
                            trace!("{} invalid id stream_in={}", self.trace_id, stream_id);
                            continue;
                        }
                    };
                    stream_in.recv(data_chunk)?;

                    self.num_data_pkts_seen += 1;
                    if !self.delayed_ack || self.num_data_pkts_seen >= self.ack_freq {
                        self.send_sack = true;
                    } else {
                        self.set_delayed_ack_timer();
                    }
                    data_appears = true;
                    self.last_data_from = pathid;
                }
                SctpChunk::InitAck(initack) => {
                    let remote_addresses: Vec<IpAddr> = initack
                        .params
                        .iter()
                        .filter_map(|x| match x {
                            SctpParameter::Ipv4(addr4) => Some(IpAddr::V4(*addr4)),
                            SctpParameter::Ipv6(addr6) => Some(IpAddr::V6(*addr6)),
                            _ => None,
                        })
                        .collect();

                    let cookie = initack
                        .params
                        .into_iter()
                        .filter_map(|x| {
                            if let SctpParameter::Cookie(cookie) = x {
                                return Some(cookie);
                            } else {
                                return None;
                            }
                        })
                        .next();
                    if cookie.is_none() {
                        trace!("{} no Cookie", self.trace_id);
                        return Err(SctpError::ProtocolViolation);
                    }

                    let init = match self.recovery.on_t1_chunk_received(recv_time) {
                        Some(SctpChunk::Init(v)) => v,
                        Some(_) | None => {
                            trace!("{} no INIT", self.trace_id);
                            return Err(SctpError::InvalidValue);
                        }
                    };
                    self.mapping_array.initialize(initack.init_tsn).unwrap();
                    self.peer_vtag = initack.init_tag;
                    self.generate_stream_in(cmp::min(init.num_in_strm, initack.num_out_strm))
                        .unwrap();
                    self.generate_stream_out(cmp::min(init.num_out_strm, initack.num_in_strm))
                        .unwrap();

                    remote_addresses.iter().for_each(|ip| {
                        if let Err(e) = self.add_raddr(&ip) {
                            if e != SctpError::Done {
                                trace!(
                                    "{} failed to add remote address, addr={}",
                                    self.trace_id,
                                    ip
                                );
                            }
                        }
                    });

                    let pathid = match self.get_pathid(&from) {
                        Some(v) => v,
                        None => {
                            let ret = self.add_raddr(&from);
                            if ret.is_err() {
                                return Err(ret.unwrap_err());
                            }
                            ret.unwrap()
                        }
                    };

                    self.recovery.initialize(initack.a_rwnd as usize);

                    self.recovery.confirm_path(pathid).unwrap();
                    self.set_primary_path(pathid).unwrap();

                    self.state = SctpAssociationState::CookieEchoed;
                    self.control_waiting_trans.insert(
                        self.next_control_sequence.0,
                        (SctpChunk::CookieEcho(cookie.unwrap()), pathid),
                    );
                    self.next_control_sequence += 1;
                }
                SctpChunk::Sack(..) => {
                    self.recovery.on_sack_received(chunk, recv_time);
                    if self.state == SctpAssociationState::ShutdownPending {
                        if self
                            .recovery
                            .on_enter_shutdown(self.mapping_array.cummulative_tsn.0)
                        {
                            self.state = SctpAssociationState::ShutdownSent;
                        }
                    }
                }
                SctpChunk::Heartbeat(hbinfo) => {
                    self.control_waiting_trans.insert(
                        self.next_control_sequence.0,
                        (SctpChunk::HeartbeatAck(hbinfo), pathid.unwrap()),
                    );
                    self.next_control_sequence += 1;
                }
                SctpChunk::HeartbeatAckWithInfo(..) => {
                    self.recovery.on_heartbeatack_received(chunk, recv_time);
                }
                SctpChunk::Abort(abort) => {
                    self.error_cause = abort.error_cause;
                    self.state = SctpAssociationState::Closed;
                    break;
                }
                SctpChunk::Shutdown(_) => {
                    self.state = SctpAssociationState::ShutdownReceived;
                    self.recovery.on_shutdown_received();
                }
                SctpChunk::ShutdownAck => {
                    if self.state == SctpAssociationState::ShutdownSent {
                        self.state = SctpAssociationState::Closed;
                        self.recovery.on_shutdown_ack_received();
                    }
                }
                SctpChunk::CookieAck => {
                    match self.recovery.on_t1_chunk_received(recv_time) {
                        Some(SctpChunk::CookieEcho(..)) => {}
                        Some(_) | None => {
                            trace!("{} no COOKIE-ECHO", self.trace_id);
                            return Err(SctpError::InvalidValue);
                        }
                    };
                    self.recovery.establish();
                    self.state = SctpAssociationState::Established;
                }
                SctpChunk::ShutdownComplete(_) => {
                    self.state = SctpAssociationState::Closed;
                }
                _ => {}
            }
        }
        return Ok(off);
    }

    pub fn read_from_stream(&mut self, stream_id: u16, wbuf: &mut Vec<u8>) -> Result<usize> {
        let stream_in = match self.stream_in.get_mut(stream_id as usize) {
            Some(v) => v,
            None => {
                trace!("{} invalid id stream_in={}", self.trace_id, stream_id);
                return Err(SctpError::InvalidValue);
            }
        };
        let len = match stream_in.read(wbuf) {
            Ok(v) => v,
            Err(e) => {
                return Err(e);
            }
        };
        Ok(len)
    }

    pub fn get_readable(&self) -> SctpStreamIter {
        let readable = self
            .stream_in
            .iter()
            .filter(|v| v.is_readable())
            .map(|v| v.stream_id)
            .collect();
        SctpStreamIter::new(readable)
    }

    pub fn write_into_stream(
        &mut self,
        stream_id: u16,
        rbuf: &[u8],
        is_unordered: bool,
        is_complete: bool,
    ) -> Result<usize> {
        let stream_out = match self.stream_out.get_mut(stream_id as usize) {
            Some(v) => v,
            None => {
                trace!("{} invalid id stream_out={}", self.trace_id, stream_id);
                return Err(SctpError::InvalidValue);
            }
        };
        let len = match stream_out.write(rbuf, is_unordered, is_complete) {
            Ok(v) => v,
            Err(e) => {
                return Err(e);
            }
        };
        Ok(len)
    }

    pub fn get_pending(&self) -> SctpStreamIter {
        SctpStreamIter::new(
            self.stream_out
                .iter()
                .filter(|v| v.is_pending())
                .map(|v| v.stream_id)
                .collect(),
        )
    }

    pub fn get_waiting_num(&self, is_unordered: bool) -> usize {
        self.stream_in
            .iter()
            .map(|v| v.get_waiting_num(is_unordered))
            .sum()
    }

    pub fn get_readble_num(&self, is_unordered: bool) -> usize {
        self.stream_in
            .iter()
            .map(|v| v.get_readable_num(is_unordered))
            .sum()
    }

    pub fn send(&mut self, sbuf: &mut Vec<u8>) -> Result<(usize, IpAddr)> {
        let send_time = Instant::now();
        let old_len = sbuf.len();

        let header = SctpCommonHeader {
            src_port: self.src_port,
            dst_port: self.dst_port,
            vtag: self.peer_vtag,
            checksum: 0,
        };
        header.to_bytes(sbuf).unwrap();

        match self.state {
            SctpAssociationState::Established
            | SctpAssociationState::ShutdownPending
            | SctpAssociationState::ShutdownReceived => {
                if let Ok((pathid1, written)) =
                    self.send_for_first_fast_retransmission(sbuf, send_time)
                {
                    SctpAssociation::set_checksum(sbuf);
                    return Ok((written, self.get_remote_ip(pathid1).unwrap()));
                }

                if let Ok((pathid1, written)) =
                    self.send_for_first_t3_retransmission(sbuf, send_time)
                {
                    SctpAssociation::set_checksum(sbuf);
                    return Ok((written, self.get_remote_ip(pathid1).unwrap()));
                }
            }
            _ => {}
        }

        match self.state {
            SctpAssociationState::Established
            | SctpAssociationState::ShutdownPending
            | SctpAssociationState::ShutdownSent => {
                if self.delayed_ack_timeout.is_some() || self.send_sack {
                    self.send_sack();
                }
            }
            _ => {}
        }

        let mut pathid = None;
        if let Ok((pathid1, _)) = self.send_for_control_transmission(sbuf, send_time) {
            pathid = Some(pathid1);
        }

        let mut sent_for_retrans = false;
        match self.state {
            SctpAssociationState::Established
            | SctpAssociationState::ShutdownPending
            | SctpAssociationState::ShutdownReceived => {
                if let Ok((pathid1, _)) = self.send_for_fast_retransmission(sbuf, pathid, send_time)
                {
                    if pathid.is_none() {
                        pathid = Some(pathid1);
                    }
                    sent_for_retrans = true;
                }

                if let Ok((pathid1, _)) = self.send_for_t3_retransmission(sbuf, pathid, send_time) {
                    if pathid.is_none() {
                        pathid = Some(pathid1);
                    }
                    sent_for_retrans = true;
                }
            }
            _ => {}
        }

        if self.state == SctpAssociationState::Established && !sent_for_retrans {
            self.send_burst_count += 1;

            if self.send_burst_count > MAX_BURST {
                sbuf.clear();
                self.send_burst_count = 0;
                return Err(SctpError::Done);
            }

            if let Ok((pathid1, _)) = self.send_for_transmission(sbuf, pathid, send_time) {
                if pathid.is_none() {
                    pathid = Some(pathid1);
                }
            }
        }

        if pathid.is_some() && sbuf.len() > old_len {
            SctpAssociation::set_checksum(sbuf);
            Ok((
                sbuf.len() - old_len,
                self.get_remote_ip(pathid.unwrap()).unwrap(),
            ))
        } else {
            sbuf.clear();
            self.send_burst_count = 0;
            Err(SctpError::Done)
        }
    }

    fn send_for_first_t3_retransmission(
        &mut self,
        sbuf: &mut Vec<u8>,
        send_time: Instant,
    ) -> Result<(usize, usize)> {
        write_retrans_chunks_for_single_pkt!(
            self.recovery,
            self.recovery.tsn_waiting_t3_retrans,
            sbuf,
            send_time,
            false,
            self.trace_id
        )
    }

    fn send_for_first_fast_retransmission(
        &mut self,
        sbuf: &mut Vec<u8>,
        send_time: Instant,
    ) -> Result<(usize, usize)> {
        write_retrans_chunks_for_single_pkt!(
            self.recovery,
            self.recovery.tsn_waiting_fast_retrans,
            sbuf,
            send_time,
            true,
            self.trace_id
        )
    }

    fn send_for_control_transmission(
        &mut self,
        sbuf: &mut Vec<u8>,
        send_time: Instant,
    ) -> Result<(usize, usize)> {
        let mut pathid = None;
        let old_len = sbuf.len();
        if let Ok((pathid1, _)) = write_control_chunks!(
            self.recovery,
            self.control_waiting_trans,
            sbuf,
            pathid,
            send_time,
            self.trace_id
        ) {
            pathid = Some(pathid1);
        }

        if let Ok((pathid1, _)) = write_control_chunks!(
            self.recovery,
            self.recovery.control_waiting_trans,
            sbuf,
            pathid,
            send_time,
            self.trace_id
        ) {
            pathid = Some(pathid1);
        }

        if pathid.is_some() && sbuf.len() > old_len {
            return Ok((pathid.unwrap(), sbuf.len() - old_len));
        } else {
            return Err(SctpError::Done);
        }
    }

    fn send_for_t3_retransmission(
        &mut self,
        sbuf: &mut Vec<u8>,
        pathid: Option<usize>,
        send_time: Instant,
    ) -> Result<(usize, usize)> {
        write_retrans_chunks!(
            self.recovery,
            self.recovery.tsn_waiting_t3_retrans,
            sbuf,
            pathid,
            send_time,
            false,
            self.trace_id
        )
    }

    fn send_for_fast_retransmission(
        &mut self,
        sbuf: &mut Vec<u8>,
        pathid: Option<usize>,
        send_time: Instant,
    ) -> Result<(usize, usize)> {
        write_retrans_chunks!(
            self.recovery,
            self.recovery.tsn_waiting_fast_retrans,
            sbuf,
            pathid,
            send_time,
            true,
            self.trace_id
        )
    }

    fn send_for_transmission(
        &mut self,
        sbuf: &mut Vec<u8>,
        mut pathid: Option<usize>,
        send_time: Instant,
    ) -> Result<(usize, usize)> {
        let pending: Vec<u16> = self.get_pending().collect();
        let old_len = sbuf.len();
        let mut mtu = None;
        for strmid in pending {
            if pathid.is_none() {
                pathid = self.get_primary_path();
            }

            if pathid.unwrap() != self.get_primary_path().unwrap() {
                continue;
            }

            let strmout = match self.stream_out.get_mut(strmid as usize) {
                Some(v) => v,
                None => {
                    trace!("{} invalid id stream_out={}", self.trace_id, strmid);
                    break;
                }
            };

            while strmout.is_pending() {
                if mtu.is_none() {
                    mtu = Some(self.recovery.get_path_mtu(pathid.unwrap()).unwrap());
                }
                let window = self.recovery.get_available_window(pathid.unwrap()).unwrap();
                if mtu.unwrap() <= sbuf.len() {
                    break;
                }
                let available_space = std::cmp::min(
                    mtu.unwrap() - sbuf.len().checked_sub(12).unwrap_or(0),
                    window,
                );
                if available_space <= 16 {
                    break;
                }
                let fragment_point = available_space - 16;
                let data_chunk =
                    match strmout.generate_data(self.recovery.get_next_tsn(), fragment_point) {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            continue;
                        }
                        Err(_) => {
                            break;
                        }
                    };
                trace!("{} transmission tsn={}", self.trace_id, data_chunk.tsn);

                let chunk = SctpChunk::Data(data_chunk);
                chunk.to_bytes(sbuf).unwrap();
                self.recovery
                    .on_data_sent(chunk, pathid.unwrap(), send_time, false);
                self.sent_data_count += 1;
            }
        }

        if pathid.is_some() && sbuf.len() > old_len {
            Ok((pathid.unwrap(), sbuf.len() - old_len))
        } else {
            Err(SctpError::Done)
        }
    }

    fn send_sack(&mut self) {
        let chunk = self.mapping_array.genarate_sack(self.get_rwnd()).unwrap();
        let mut pathid = self
            .last_data_from
            .unwrap_or(self.get_primary_path().unwrap());
        if let Ok((path_confirmed, path_state)) = self.recovery.get_path_state(pathid) {
            // TODO: We should find alternate path
            if !path_confirmed || path_state == SctpPathState::InActive {
                pathid = self.get_primary_path().unwrap();
            }
        } else {
            // Invalid pathid
            pathid = self.get_primary_path().unwrap();
        }
        self.control_waiting_trans
            .insert(self.next_control_sequence.0, (chunk, pathid));
        self.next_control_sequence += 1;
        self.num_data_pkts_seen = 0;
        self.send_sack = false;
        self.delayed_ack_timeout = None;
    }

    fn abort(&mut self, sbuf: &mut Vec<u8>, error_cause: Option<SctpErrorCause>) -> usize {
        let old_len = sbuf.len();
        let header = SctpCommonHeader {
            src_port: self.src_port,
            dst_port: self.dst_port,
            vtag: self.peer_vtag,
            checksum: 0,
        };
        let abort = SctpChunk::Abort(SctpAbortChunk {
            t_bit: false,
            error_cause: error_cause,
        });
        header.to_bytes(sbuf).unwrap();
        abort.to_bytes(sbuf).unwrap();
        self.state = SctpAssociationState::Closed;

        sbuf.len() - old_len
    }

    pub fn close(&mut self) -> Result<()> {
        match self.state {
            SctpAssociationState::CookieWait | SctpAssociationState::CookieEchoed => {
                Err(SctpError::InvalidValue)
            }
            SctpAssociationState::Established => {
                if self
                    .recovery
                    .on_enter_shutdown(self.mapping_array.cummulative_tsn.0)
                {
                    self.state = SctpAssociationState::ShutdownSent;
                } else {
                    self.state = SctpAssociationState::ShutdownPending;
                }
                Ok(())
            }
            SctpAssociationState::Closed
            | SctpAssociationState::ShutdownPending
            | SctpAssociationState::ShutdownSent
            | SctpAssociationState::ShutdownReceived
            | SctpAssociationState::ShutdownAckSent => Ok(()),
        }
    }

    fn get_rwnd(&self) -> u32 {
        let len: usize = self.stream_in.iter().map(|v| v.len()).sum();
        let rwnd: u32 = if self.a_rwnd > len as u32 {
            self.a_rwnd - len as u32
        } else {
            0
        };
        return rwnd;
    }

    pub fn is_established(&self) -> bool {
        return self.state == SctpAssociationState::Established;
    }

    pub fn is_closed(&self) -> bool {
        return self.state == SctpAssociationState::Closed;
    }
}
