use byteorder::{BigEndian, WriteBytesExt};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;

use nom::error::ErrorKind;
use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use nom::{Err, IResult};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Result;
use crate::SctpError;

#[derive(Debug, PartialEq)]
pub struct SctpCommonHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub vtag: u32,
    pub checksum: u32,
}

impl SctpCommonHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<(SctpCommonHeader, usize)> {
        let (remain, header) = match SctpCommonHeader::parse_sctp_common_header(bytes) {
            Ok(v) => v,
            Err(e) => {
                trace!("{:?}", e);
                return Err(SctpError::InvalidChunk);
            }
        };
        Ok((header, bytes.len() - remain.len()))
    }

    pub fn bytes_len(&self) -> usize {
        let mut len = 2; // Source Port Number
        len += 2; // Destination Port Number
        len += 4; // Verification Tag
        len += 4; // Checksum
        len
    }

    pub fn to_bytes(&self, bytes: &mut Vec<u8>) -> Result<usize> {
        let prev_len = bytes.len();
        bytes.write_u16::<BigEndian>(self.src_port).unwrap();
        bytes.write_u16::<BigEndian>(self.dst_port).unwrap();
        bytes.write_u32::<BigEndian>(self.vtag).unwrap();
        bytes.write_u32::<BigEndian>(self.checksum).unwrap();
        Ok(bytes.len() - prev_len)
    }

    named! {parse_sctp_common_header<SctpCommonHeader>,
        do_parse!(
            s: be_u16 >>
            d: be_u16 >>
            v: be_u32 >>
            c: be_u32 >>
            (
                SctpCommonHeader {
                    src_port: s,
                    dst_port: d,
                    vtag: v,
                    checksum: c,
                }
            )
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SctpChunkType(pub u8);

newtype_enum! {
impl debug SctpChunkType {
    Data                = 0,
    Init                = 1,
    InitAck             = 2,
    Sack                = 3,
    Heartbeat           = 4,
    HeartbeatAck        = 5,
    Abort               = 6,
    Shutdown            = 7,
    ShutdownAck         = 8,
    Error               = 9,
    CookieEcho          = 10,
    CookieAck           = 11,
    ShutdownComplete    = 14,
    Auth                = 15,
    AsconfAck           = 128,
    ReConfig            = 130,
    ForwardTsn          = 192,
    Asconf              = 193,
}
}

impl From<SctpChunkType> for u8 {
    fn from(v: SctpChunkType) -> u8 {
        v.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SctpChunk {
    Data(SctpDataChunk),
    Init(SctpInitChunk),
    InitAck(SctpInitChunk),
    Sack(SctpSackChunk),
    Heartbeat(Vec<u8>),
    HeartbeatAck(Vec<u8>),
    HeartbeatWithInfo(SctpHeartbeatInfo),
    HeartbeatAckWithInfo(SctpHeartbeatInfo),
    Abort(SctpAbortChunk),
    CookieEcho(Vec<u8>),
    CookieAck,
    Shutdown(u32),
    ShutdownAck,
    ShutdownComplete(bool),
    Unknown(SctpChunkType, u8, Vec<u8>),
}

impl SctpChunk {
    pub fn from_bytes(bytes: &[u8]) -> Result<(SctpChunk, usize)> {
        let (remain, chunk) = match SctpChunk::parse_sctp_chunk(bytes) {
            Ok(v) => v,
            Err(_) => {
                return Err(SctpError::InvalidChunk);
            }
        };
        Ok((chunk, bytes.len() - remain.len()))
    }

    pub fn bytes_len(&self) -> usize {
        let mut len = match self {
            SctpChunk::Data(v) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += 4; // TSN
                len += 2; // Stream Identifier
                len += 2; // Stream Sequence Number
                len += 4; // Payload Protocol Identifier
                len += v.data.len();
                len
            }
            SctpChunk::Init(v) | SctpChunk::InitAck(v) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += 4; // Initiate Tag
                len += 4; // Advertised Receiver Window Credit
                len += 2; // Number of Outbound Streams
                len += 2; // Number of Inbound Streams
                len += 4; // Initial TSN
                for param in &v.params {
                    len += param.bytes_len();
                }
                len
            }
            SctpChunk::Sack(v) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += 4; // Cumulative TSN Ack
                len += 4; // Advertised Receiver Window Credit
                len += 2; // Number of Gap Ack Blocks
                len += 2; // Number of Duplicate TSNs
                len += (2 + 2) * v.gap_acks.len(); // Gap Ack Block #n Start, End
                len += 4 * v.dup_acks.len(); // Duplicate TSN #n
                len
            }
            SctpChunk::Heartbeat(v) | SctpChunk::HeartbeatAck(v) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += v.len();
                len
            }
            SctpChunk::HeartbeatWithInfo(..) | SctpChunk::HeartbeatAckWithInfo(..) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += 2; // Heartbeat Info Type
                len += 2; // HB Info Length
                len += 8; // pathid: u64
                len += 8; // sequence: u64
                len += 8; // random_value: u64
                len
            }
            SctpChunk::Abort(v) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                if let Some(cause) = &v.error_cause {
                    len += cause.bytes_len();
                }
                len
            }
            SctpChunk::Shutdown(_) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += 4; // Cumulative TSN Ack
                len
            }
            SctpChunk::ShutdownAck | SctpChunk::CookieAck | SctpChunk::ShutdownComplete(..) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len
            }
            SctpChunk::CookieEcho(v) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += v.len();
                len
            }
            SctpChunk::Unknown(_, _, v) => {
                let mut len = 1; // Chunk Type
                len += 1; // Chunk flags
                len += 2; // Chunk Length
                len += v.len();
                len
            }
        };
        if len % 4 > 0 {
            len += 4 - (len % 4);
        }
        len
    }

    pub fn to_bytes(&self, bytes: &mut Vec<u8>) -> Result<usize> {
        let prev_len = bytes.len();
        match self {
            SctpChunk::Data(v) => {
                bytes.write_u8(u8::from(SctpChunkType::Data)).unwrap();
                bytes
                    .write_u8(
                        if v.e_bit { 0b0000_0001 } else { 0x00 }
                            | if v.b_bit { 0b0000_0010 } else { 0x00 }
                            | if v.u_bit { 0b0000_0100 } else { 0x00 },
                    )
                    .unwrap();
                bytes
                    .write_u16::<BigEndian>(16 + v.data.len() as u16)
                    .unwrap();
                bytes.write_u32::<BigEndian>(v.tsn).unwrap();
                bytes.write_u16::<BigEndian>(v.stream_id).unwrap();
                bytes.write_u16::<BigEndian>(v.stream_seq).unwrap();
                bytes.write_u32::<BigEndian>(v.proto_id).unwrap();
                bytes.extend(&v.data);
            }
            SctpChunk::Init(v) => {
                let mut param_bytes = Vec::new();
                let mut param_len = 0;
                for param in &v.params {
                    param_len += param.to_bytes(&mut param_bytes).unwrap()
                }
                bytes.write_u8(u8::from(SctpChunkType::Init)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(20 + param_len as u16).unwrap();
                bytes.write_u32::<BigEndian>(v.init_tag).unwrap();
                bytes.write_u32::<BigEndian>(v.a_rwnd).unwrap();
                bytes.write_u16::<BigEndian>(v.num_out_strm).unwrap();
                bytes.write_u16::<BigEndian>(v.num_in_strm).unwrap();
                bytes.write_u32::<BigEndian>(v.init_tsn).unwrap();
                bytes.extend(&param_bytes);
            }
            SctpChunk::InitAck(v) => {
                let mut param_bytes = Vec::new();
                let mut param_len = 0;
                for param in &v.params {
                    param_len += param.to_bytes(&mut param_bytes).unwrap()
                }
                bytes.write_u8(u8::from(SctpChunkType::InitAck)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(20 + param_len as u16).unwrap();
                bytes.write_u32::<BigEndian>(v.init_tag).unwrap();
                bytes.write_u32::<BigEndian>(v.a_rwnd).unwrap();
                bytes.write_u16::<BigEndian>(v.num_out_strm).unwrap();
                bytes.write_u16::<BigEndian>(v.num_in_strm).unwrap();
                bytes.write_u32::<BigEndian>(v.init_tsn).unwrap();
                bytes.extend(&param_bytes);
            }
            SctpChunk::Sack(v) => {
                bytes.write_u8(u8::from(SctpChunkType::Sack)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes
                    .write_u16::<BigEndian>(
                        16 + 4 * v.gap_acks.len() as u16 + 4 * v.dup_acks.len() as u16,
                    )
                    .unwrap();
                bytes.write_u32::<BigEndian>(v.cum_ack).unwrap();
                bytes.write_u32::<BigEndian>(v.a_rwnd).unwrap();
                bytes.write_u16::<BigEndian>(v.num_gap_ack).unwrap();
                bytes.write_u16::<BigEndian>(v.num_dup_ack).unwrap();
                for gap in &v.gap_acks {
                    bytes.write_u16::<BigEndian>(gap.start).unwrap();
                    bytes.write_u16::<BigEndian>(gap.end).unwrap();
                }
                for tsn in &v.dup_acks {
                    bytes.write_u32::<BigEndian>(*tsn).unwrap();
                }
            }
            SctpChunk::Heartbeat(v) => {
                bytes.write_u8(u8::from(SctpChunkType::Heartbeat)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(4 + v.len() as u16).unwrap();
                bytes.extend(v);
            }
            SctpChunk::HeartbeatWithInfo(v) => {
                bytes.write_u8(u8::from(SctpChunkType::Heartbeat)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(4 + 4 + 24).unwrap();
                bytes.write_u16::<BigEndian>(1).unwrap();
                bytes.write_u16::<BigEndian>(4 + 24).unwrap();
                bytes.write_u64::<BigEndian>(v.pathid as u64).unwrap();
                bytes.write_u64::<BigEndian>(v.sequence).unwrap();
                bytes.write_u64::<BigEndian>(v.random_value).unwrap();
            }
            SctpChunk::HeartbeatAck(v) => {
                bytes
                    .write_u8(u8::from(SctpChunkType::HeartbeatAck))
                    .unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(4 + v.len() as u16).unwrap();
                bytes.extend(v);
            }
            SctpChunk::HeartbeatAckWithInfo(v) => {
                bytes
                    .write_u8(u8::from(SctpChunkType::HeartbeatAck))
                    .unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(4 + 4 + 24).unwrap();
                bytes.write_u64::<BigEndian>(v.pathid as u64).unwrap();
                bytes.write_u64::<BigEndian>(4 + 24).unwrap();
                bytes.write_u64::<BigEndian>(v.pathid as u64).unwrap();
                bytes.write_u64::<BigEndian>(v.sequence).unwrap();
                bytes.write_u64::<BigEndian>(v.random_value).unwrap();
            }
            SctpChunk::Abort(v) => {
                let mut cause_bytes = Vec::new();
                if let Some(cause) = &v.error_cause {
                    cause.to_bytes(&mut cause_bytes).unwrap();
                }
                bytes.write_u8(u8::from(SctpChunkType::Abort)).unwrap();
                bytes
                    .write_u8(if v.t_bit { 0b0000_0001 } else { 0x00 })
                    .unwrap();
                bytes
                    .write_u16::<BigEndian>(4 + cause_bytes.len() as u16)
                    .unwrap();
                bytes.extend(cause_bytes);
            }
            SctpChunk::Shutdown(cum_ack) => {
                bytes.write_u8(u8::from(SctpChunkType::Shutdown)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(8).unwrap();
                bytes.write_u32::<BigEndian>(*cum_ack).unwrap();
            }
            SctpChunk::ShutdownAck => {
                bytes
                    .write_u8(u8::from(SctpChunkType::ShutdownAck))
                    .unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(4).unwrap();
            }
            SctpChunk::CookieEcho(v) => {
                bytes.write_u8(u8::from(SctpChunkType::CookieEcho)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(4 + v.len() as u16).unwrap();
                bytes.extend(v);
            }
            SctpChunk::CookieAck => {
                bytes.write_u8(u8::from(SctpChunkType::CookieAck)).unwrap();
                bytes.write_u8(0).unwrap();
                bytes.write_u16::<BigEndian>(4).unwrap();
            }
            SctpChunk::ShutdownComplete(v) => {
                bytes
                    .write_u8(u8::from(SctpChunkType::ShutdownComplete))
                    .unwrap();
                bytes.write_u8(if *v { 0b0000_0001 } else { 0x00 }).unwrap();
                bytes.write_u16::<BigEndian>(4).unwrap();
            }
            _ => {}
        };
        if (bytes.len() - prev_len) % 4 > 0 {
            for _ in 0..(4 - ((bytes.len() - prev_len) % 4)) {
                bytes.write_u8(0).unwrap();
            }
        };
        Ok(bytes.len() - prev_len)
    }

    pub fn get_type(&self) -> SctpChunkType {
        match self {
            SctpChunk::Data(..) => SctpChunkType::Data,
            SctpChunk::Init(..) => SctpChunkType::Init,
            SctpChunk::InitAck(..) => SctpChunkType::InitAck,
            SctpChunk::Sack(..) => SctpChunkType::Sack,
            SctpChunk::Heartbeat(..) => SctpChunkType::Heartbeat,
            SctpChunk::HeartbeatWithInfo(..) => SctpChunkType::Heartbeat,
            SctpChunk::HeartbeatAck(..) => SctpChunkType::HeartbeatAck,
            SctpChunk::HeartbeatAckWithInfo(..) => SctpChunkType::HeartbeatAck,
            SctpChunk::Abort(..) => SctpChunkType::Abort,
            SctpChunk::CookieEcho(..) => SctpChunkType::CookieEcho,
            SctpChunk::CookieAck => SctpChunkType::CookieAck,
            SctpChunk::Shutdown(..) => SctpChunkType::Shutdown,
            SctpChunk::ShutdownAck => SctpChunkType::ShutdownAck,
            SctpChunk::ShutdownComplete(..) => SctpChunkType::ShutdownComplete,
            SctpChunk::Unknown(chunk_type, _, _) => *chunk_type,
        }
    }
    pub fn is_control(&self) -> bool {
        match self {
            SctpChunk::Data(..) => false,
            _ => true,
        }
    }

    named! {parse_sctp_chunk<SctpChunk>,
        do_parse!(
            ctype: be_u8 >>
            flags: be_u8 >>
            length: be_u16 >>
            chunk: flat_map!(take!(length - 4),
                call!(SctpChunk::parse_sctp_chunk_with_type, SctpChunkType(ctype), length as usize - 4, flags)
                ) >>
            cond!(length % 4 > 0, take!(4 - (length % 4))) >> // skip padding bytes
            ( chunk )
        )
    }

    pub fn parse_sctp_chunk_with_type(
        i: &[u8],
        chunk_type: SctpChunkType,
        length: usize,
        flags: u8,
    ) -> IResult<&[u8], SctpChunk> {
        match chunk_type {
            SctpChunkType::Data => SctpChunk::parse_sctp_chunk_data(i, length, flags),
            SctpChunkType::Init => SctpChunk::parse_sctp_chunk_init(i, SctpChunkType::Init),
            SctpChunkType::InitAck => SctpChunk::parse_sctp_chunk_init(i, SctpChunkType::InitAck),
            SctpChunkType::Sack => SctpChunk::parse_sctp_chunk_sack(i),
            SctpChunkType::Abort => SctpChunk::parse_sctp_chunk_abort(i, length, flags),
            SctpChunkType::Heartbeat => SctpChunk::parse_sctp_chunk_heartbeat(i, length),
            SctpChunkType::HeartbeatAck => SctpChunk::parse_sctp_chunk_heartbeat_ack(i, length),
            SctpChunkType::Shutdown => SctpChunk::parse_sctp_chunk_shutdown(i),
            SctpChunkType::ShutdownAck => Ok((&i[0..], SctpChunk::ShutdownAck)),
            SctpChunkType::CookieEcho => SctpChunk::parse_sctp_chunk_cookie_echo(i, length),
            SctpChunkType::CookieAck => Ok((&i[0..], SctpChunk::CookieAck)),
            SctpChunkType::ShutdownComplete => {
                SctpChunk::parse_sctp_chunk_shutdown_complete(i, flags)
            }
            _ => map!(i, take!(length), |chunk| {
                SctpChunk::Unknown(chunk_type, flags, Vec::from(chunk))
            }),
        }
    }

    fn parse_sctp_chunk_data(i: &[u8], length: usize, flags: u8) -> IResult<&[u8], SctpChunk> {
        do_parse!(
            i,
            tsn: be_u32
                >> sid: be_u16
                >> seq: be_u16
                >> pid: be_u32
                >> v: take!(length - 12)
                >> (SctpChunk::Data(SctpDataChunk {
                    u_bit: if flags & 0b0000_0100 != 0 {
                        true
                    } else {
                        false
                    },
                    b_bit: if flags & 0b0000_0010 != 0 {
                        true
                    } else {
                        false
                    },
                    e_bit: if flags & 0b0000_0001 != 0 {
                        true
                    } else {
                        false
                    },
                    tsn: tsn,
                    stream_id: sid,
                    stream_seq: seq,
                    proto_id: pid,
                    data: Vec::from(v),
                }))
        )
    }

    fn parse_sctp_chunk_init(i: &[u8], chunk_type: SctpChunkType) -> IResult<&[u8], SctpChunk> {
        do_parse!(
            i,
            itag: be_u32
                >> arwnd: be_u32
                >> os: be_u16
                >> is: be_u16
                >> itsn: be_u32
                >> params: many0!(complete!(SctpParameter::parse_sctp_parameter))
                >> ({
                    let contents = SctpInitChunk {
                        init_tag: itag,
                        a_rwnd: arwnd,
                        num_out_strm: os,
                        num_in_strm: is,
                        init_tsn: itsn,
                        params: params,
                    };
                    if chunk_type == SctpChunkType::Init {
                        SctpChunk::Init(contents)
                    } else {
                        SctpChunk::InitAck(contents)
                    }
                })
        )
    }

    named! {parse_sctp_chunk_sack<SctpChunk>,
        do_parse!(
            cack: be_u32 >>
            arwnd: be_u32 >>
            ngap: be_u16 >>
            ndup: be_u16 >>
            gaps: map!(
                take!(2 * 2 * ngap),
                |s| s.chunks(4)
                    .map(|chunk| SctpGapAckBlock {
                        start: (chunk[0] as u16) << 8 | chunk[1] as u16,
                        end: (chunk[2] as u16) << 8 | chunk[3] as u16,})
                    .collect()
                ) >>
            dups: map!(
                take!(4 * ndup),
                |s| s.chunks(4)
                    .map(|chunk| (chunk[0] as u32) << 24 | (chunk[1] as u32) << 16 | (chunk[2] as u32) << 8 | chunk[3] as u32)
                    .collect()
               ) >>
            ( SctpChunk::Sack(
                SctpSackChunk {
                    cum_ack: cack,
                    a_rwnd: arwnd,
                    num_gap_ack: ngap,
                    num_dup_ack: ndup,
                    gap_acks: gaps,
                    dup_acks: dups,
                }
            ) )
        )
    }

    fn parse_sctp_chunk_abort(i: &[u8], length: usize, flags: u8) -> IResult<&[u8], SctpChunk> {
        do_parse!(
            i,
            cause:
                cond!(
                    length > 0,
                    flat_map!(take!(length), call!(SctpErrorCause::parse_sctp_error_cause))
                )
                >> (SctpChunk::Abort(SctpAbortChunk {
                    t_bit: if (flags & 0b0000_0001) != 0 {
                        true
                    } else {
                        false
                    },
                    error_cause: cause,
                }))
        )
    }

    fn parse_sctp_chunk_heartbeat(i: &[u8], length: usize) -> IResult<&[u8], SctpChunk> {
        do_parse!(i, v: take!(length) >> (SctpChunk::Heartbeat(Vec::from(v))))
    }

    fn parse_sctp_chunk_heartbeat_ack(i: &[u8], _length: usize) -> IResult<&[u8], SctpChunk> {
        do_parse!(
            i,
            _info_type: be_u16
                >> _info_length: be_u16
                >> pathid: be_u64
                >> sequence: be_u64
                >> random_value: be_u64
                >> (SctpChunk::HeartbeatAckWithInfo(SctpHeartbeatInfo {
                    pathid: pathid as usize,
                    sequence: sequence,
                    random_value: random_value,
                }))
        )
    }

    named! {parse_sctp_chunk_shutdown<SctpChunk>,
        do_parse!(
            cack: be_u32 >>
            ( SctpChunk::Shutdown(cack) )
        )
    }

    fn parse_sctp_chunk_cookie_echo(i: &[u8], length: usize) -> IResult<&[u8], SctpChunk> {
        do_parse!(i, v: take!(length) >> (SctpChunk::CookieEcho(Vec::from(v))))
    }

    fn parse_sctp_chunk_shutdown_complete(i: &[u8], flags: u8) -> IResult<&[u8], SctpChunk> {
        if i.len() > 0 {
            return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
        }
        let t_bit = if (flags & 0b0000_0001) != 0 {
            true
        } else {
            false
        };
        return Ok((&i[0..], SctpChunk::ShutdownComplete(t_bit)));
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SctpDataChunk {
    pub u_bit: bool,
    pub b_bit: bool,
    pub e_bit: bool,
    pub tsn: u32,
    pub stream_id: u16,
    pub stream_seq: u16,
    pub proto_id: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SctpInitChunk {
    pub init_tag: u32,
    pub a_rwnd: u32,
    pub num_out_strm: u16,
    pub num_in_strm: u16,
    pub init_tsn: u32,
    pub params: Vec<SctpParameter>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SctpSackChunk {
    pub cum_ack: u32,
    pub a_rwnd: u32,
    pub num_gap_ack: u16,
    pub num_dup_ack: u16,
    pub gap_acks: Vec<SctpGapAckBlock>,
    pub dup_acks: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SctpHeartbeatInfo {
    pub pathid: usize,
    pub sequence: u64,
    pub random_value: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SctpAbortChunk {
    pub t_bit: bool,
    pub error_cause: Option<SctpErrorCause>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SctpGapAckBlock {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SctpParameterType(pub u16);

newtype_enum! {
impl debug SctpParameterType {
    Ipv4            = 5,
    Ipv6            = 6,
    Cookie          = 7,
    CookiePreserv   = 9,
    Hostname        = 11,
    SupportedAddrs  = 12,
    Ecn             = 32768,
    Random          = 32770,
    Chunks          = 32771,
    HmacAlgo        = 32772,
    SupportedExts   = 32776,
    ForwardTsn      = 49152,
}
}

impl From<SctpParameterType> for u16 {
    fn from(v: SctpParameterType) -> u16 {
        v.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SctpParameter {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Cookie(Vec<u8>),
    CookiePreserv(u32),
    Hostname(Vec<u8>),
    SupportedAddrs(Vec<SctpParameterType>),
    Ecn,
    Random(Vec<u8>),
    Chunks(Vec<SctpChunkType>),
    HmacAlgo(Vec<SctpHmacAlgoId>),
    SupportedExts(Vec<SctpChunkType>),
    ForwardTsn,
    Unknown(SctpParameterType, Vec<u8>),
}

impl SctpParameter {
    pub fn bytes_len(&self) -> usize {
        let mut len = match self {
            SctpParameter::Ipv4(..) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += 4; // IPv4 Address
                len
            }
            SctpParameter::Ipv6(..) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += 16; // IPv6 Address
                len
            }
            SctpParameter::CookiePreserv(..) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += 4; // Suggested Cookie Life-Span Increment
                len
            }
            SctpParameter::Cookie(v) | SctpParameter::Hostname(v) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += v.len();
                len
            }
            SctpParameter::SupportedAddrs(v) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += 2 * v.len();
                len
            }
            SctpParameter::Ecn | SctpParameter::ForwardTsn => {
                let mut len = 2; // Type
                len += 1; // Length
                len
            }
            SctpParameter::Chunks(v) | SctpParameter::SupportedExts(v) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += v.len(); // Chunk Type #n
                len
            }
            SctpParameter::Random(v) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += 2 * v.len(); // Address Type #n
                len
            }
            SctpParameter::HmacAlgo(v) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += 2 * v.len(); // // Algo ID #n
                len
            }
            SctpParameter::Unknown(_, v) => {
                let mut len = 2; // Type
                len += 1; // Length
                len += v.len();
                len
            }
        };
        if len % 4 > 0 {
            len += 4 - (len % 4);
        }
        len
    }

    pub fn to_bytes(&self, bytes: &mut Vec<u8>) -> Result<usize> {
        let prev_len = bytes.len();
        match self {
            SctpParameter::Ipv4(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::Ipv4))
                    .unwrap();
                bytes.write_u16::<BigEndian>(8).unwrap();
                bytes.extend(&v.octets())
            }
            SctpParameter::Ipv6(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::Ipv6))
                    .unwrap();
                bytes.write_u16::<BigEndian>(20).unwrap();
                bytes.extend(&v.octets())
            }
            SctpParameter::Cookie(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::Cookie))
                    .unwrap();
                bytes.write_u16::<BigEndian>(4 + v.len() as u16).unwrap();
                bytes.extend(v)
            }
            SctpParameter::SupportedAddrs(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::SupportedAddrs))
                    .unwrap();
                bytes
                    .write_u16::<BigEndian>(4 + 2 * v.len() as u16)
                    .unwrap();
                for param_type in v {
                    bytes
                        .write_u16::<BigEndian>(u16::from(*param_type))
                        .unwrap();
                }
            }
            SctpParameter::Ecn => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::Ecn))
                    .unwrap();
                bytes.write_u16::<BigEndian>(4).unwrap();
            }
            SctpParameter::Random(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::Random))
                    .unwrap();
                bytes.write_u16::<BigEndian>(4 + v.len() as u16).unwrap();
                bytes.extend(v)
            }
            SctpParameter::Chunks(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::Chunks))
                    .unwrap();
                bytes
                    .write_u16::<BigEndian>(4 + 1 * v.len() as u16)
                    .unwrap();
                for chunk_type in v {
                    bytes.write_u8(u8::from(*chunk_type)).unwrap();
                }
            }
            SctpParameter::HmacAlgo(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::HmacAlgo))
                    .unwrap();
                bytes
                    .write_u16::<BigEndian>(4 + 2 * v.len() as u16)
                    .unwrap();
                for algo_id in v {
                    bytes.write_u16::<BigEndian>(u16::from(*algo_id)).unwrap();
                }
            }
            SctpParameter::SupportedExts(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::SupportedExts))
                    .unwrap();
                bytes
                    .write_u16::<BigEndian>(4 + 1 * v.len() as u16)
                    .unwrap();
                for chunk_type in v {
                    bytes.write_u8(u8::from(*chunk_type)).unwrap();
                }
            }
            SctpParameter::ForwardTsn => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpParameterType::ForwardTsn))
                    .unwrap();
                bytes.write_u16::<BigEndian>(4).unwrap();
            }
            SctpParameter::Unknown(param_type, v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(*param_type))
                    .unwrap();
                bytes.write_u16::<BigEndian>(4 + v.len() as u16).unwrap();
                bytes.extend(v)
            }
            _ => {}
        };
        if (bytes.len() - prev_len) % 4 > 0 {
            for _ in 0..(4 - ((bytes.len() - prev_len) % 4)) {
                bytes.write_u8(0).unwrap();
            }
        };
        Ok(bytes.len() - prev_len)
    }

    named! {parse_sctp_parameter<SctpParameter>,
        do_parse!(
            param_type: be_u16 >>
            param_length: be_u16 >>
            param: flat_map!(take!(param_length - 4),
                call!(SctpParameter::parse_sctp_parameter_with_type, SctpParameterType(param_type), param_length as usize - 4)
                ) >>
            cond!(param_length % 4 > 0, take!(4 - (param_length % 4))) >> // skip padding bytes
            ( param )
        )
    }

    fn parse_sctp_parameter_with_type(
        i: &[u8],
        param_type: SctpParameterType,
        length: usize,
    ) -> IResult<&[u8], SctpParameter> {
        match param_type {
            SctpParameterType::Ipv4 => SctpParameter::parse_sctp_parameter_ipv4(i),
            SctpParameterType::Ipv6 => SctpParameter::parse_sctp_parameter_ipv6(i),
            SctpParameterType::Cookie => SctpParameter::parse_sctp_parameter_cookie(i, length),
            SctpParameterType::SupportedAddrs => {
                SctpParameter::parse_sctp_parameter_supported_addrs(i, length)
            }
            SctpParameterType::Ecn => SctpParameter::parse_sctp_parameter_ecn(i, length),
            SctpParameterType::Random => SctpParameter::parse_sctp_parameter_random(i, length),
            SctpParameterType::Chunks => SctpParameter::parse_sctp_parameter_chunks(i, length),
            SctpParameterType::HmacAlgo => SctpParameter::parse_sctp_parameter_hmac_algo(i, length),
            SctpParameterType::SupportedExts => {
                SctpParameter::parse_sctp_parameter_supported_exts(i, length)
            }
            SctpParameterType::ForwardTsn => {
                SctpParameter::parse_sctp_parameter_forward_tsn(i, length)
            }
            _ => map!(i, take!(length), |param| {
                SctpParameter::Unknown(param_type, Vec::from(param))
            }),
        }
    }

    named! {parse_sctp_parameter_ipv4<SctpParameter>,
        do_parse!(
            v: take!(4) >>
            ( SctpParameter::Ipv4(Ipv4Addr::new(v[0], v[1], v[2], v[3])) )
        )
    }

    named! {parse_sctp_parameter_ipv6<SctpParameter>,
        do_parse!(
            v: flat_map!(take!(16),
                many0!(complete!(be_u16))
            ) >>
            ( SctpParameter::Ipv6(Ipv6Addr::new(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])) )
        )
    }

    fn parse_sctp_parameter_cookie(i: &[u8], length: usize) -> IResult<&[u8], SctpParameter> {
        do_parse!(i, v: take!(length) >> (SctpParameter::Cookie(Vec::from(v))))
    }

    fn parse_sctp_parameter_supported_addrs(
        i: &[u8],
        length: usize,
    ) -> IResult<&[u8], SctpParameter> {
        if length == 0 {
            return Ok((&i[0..], SctpParameter::SupportedAddrs(Vec::new())));
        }
        if length != i.len() {
            return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
        }
        let v = i
            .chunks(2)
            .map(|chunk| SctpParameterType(((chunk[0] as u16) << 8) | chunk[1] as u16))
            .collect();
        return Ok((&i[length..], SctpParameter::SupportedAddrs(v)));
    }

    fn parse_sctp_parameter_ecn(i: &[u8], length: usize) -> IResult<&[u8], SctpParameter> {
        if length == 0 {
            Ok((i, SctpParameter::Ecn))
        } else {
            Err(Err::Error(error_position!(i, ErrorKind::Verify)))
        }
    }

    fn parse_sctp_parameter_random(i: &[u8], length: usize) -> IResult<&[u8], SctpParameter> {
        do_parse!(i, v: take!(length) >> (SctpParameter::Random(Vec::from(v))))
    }

    fn parse_sctp_parameter_chunks(i: &[u8], length: usize) -> IResult<&[u8], SctpParameter> {
        if length == 0 {
            return Ok((&i[0..], SctpParameter::Chunks(Vec::new())));
        }
        if length != i.len() {
            return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
        }
        let v = i.iter().map(|&it| SctpChunkType(it)).collect();
        return Ok((&i[length..], SctpParameter::Chunks(v)));
    }

    fn parse_sctp_parameter_hmac_algo(i: &[u8], length: usize) -> IResult<&[u8], SctpParameter> {
        if length == 0 {
            return Ok((&i[0..], SctpParameter::HmacAlgo(Vec::new())));
        }
        if length != i.len() {
            return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
        }
        let v = i
            .chunks(2)
            .map(|chunk| SctpHmacAlgoId(((chunk[0] as u16) << 8) | chunk[1] as u16))
            .collect();
        return Ok((&i[length..], SctpParameter::HmacAlgo(v)));
    }

    fn parse_sctp_parameter_supported_exts(
        i: &[u8],
        length: usize,
    ) -> IResult<&[u8], SctpParameter> {
        if length == 0 {
            return Ok((&i[0..], SctpParameter::SupportedExts(Vec::new())));
        }
        if length != i.len() {
            return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
        }
        let v = i.iter().map(|&it| SctpChunkType(it)).collect();
        return Ok((&i[length..], SctpParameter::SupportedExts(v)));
    }

    fn parse_sctp_parameter_forward_tsn(i: &[u8], length: usize) -> IResult<&[u8], SctpParameter> {
        if length == 0 {
            Ok((i, SctpParameter::ForwardTsn))
        } else {
            Err(Err::Error(error_position!(i, ErrorKind::Verify)))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SctpStateCookie {
    pub init: SctpChunk,
    pub init_ack: SctpChunk,
    pub my_vtag: u32,
    pub peer_vtag: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub dst_addr: IpAddr,
    pub time: u64,
}

impl SctpStateCookie {
    pub fn from_bytes(key: &[u8], bytes: &[u8]) -> Result<(SctpStateCookie, usize)> {
        if bytes.len() < 32 {
            return Err(SctpError::BufferTooShort);
        }
        let mut mac = Hmac::new(Sha256::new(), key);
        mac.input(&bytes[0..(bytes.len() - 32)]);
        if mac.result().code() != &bytes[(bytes.len() - 32)..] {
            return Err(SctpError::InvalidChunk);
        }

        let (remain, cookie) =
            match SctpStateCookie::parse_sctp_state_cookie(&bytes[0..(bytes.len() - 32)]) {
                Ok(v) => v,
                Err(_) => {
                    return Err(SctpError::InvalidChunk);
                }
            };
        Ok((cookie, bytes.len() - remain.len()))
    }

    pub fn to_bytes(&self, key: &[u8], bytes: &mut Vec<u8>) -> Result<usize> {
        let prev_len = bytes.len();
        self.init.to_bytes(bytes).unwrap();
        self.init_ack.to_bytes(bytes).unwrap();
        bytes.write_u32::<BigEndian>(self.my_vtag).unwrap();
        bytes.write_u32::<BigEndian>(self.peer_vtag).unwrap();
        bytes.write_u16::<BigEndian>(self.src_port).unwrap();
        bytes.write_u16::<BigEndian>(self.dst_port).unwrap();
        bytes.write_u64::<BigEndian>(self.time).unwrap();
        if let IpAddr::V4(addr4) = self.dst_addr {
            SctpParameter::Ipv4(addr4).to_bytes(bytes).unwrap();
        }
        if let IpAddr::V6(addr6) = self.dst_addr {
            SctpParameter::Ipv6(addr6).to_bytes(bytes).unwrap();
        }
        let mut mac = Hmac::new(Sha256::new(), key);
        mac.input(bytes);
        bytes.extend(mac.result().code());
        Ok(bytes.len() - prev_len)
    }

    named! {parse_sctp_state_cookie<SctpStateCookie>,
        do_parse!(
            init: call!(SctpChunk::parse_sctp_chunk)
                >> init_ack: call!(SctpChunk::parse_sctp_chunk)
                >> my_vtag: be_u32
                >> peer_vtag: be_u32
                >> src_port: be_u16
                >> dst_port: be_u16
                >> time: be_u64
                >> param: call!(SctpParameter::parse_sctp_parameter)
                >> (SctpStateCookie {
                    init: init,
                    init_ack: init_ack,
                    my_vtag: my_vtag,
                    peer_vtag: peer_vtag,
                    src_port: src_port,
                    dst_port: dst_port,
                    dst_addr: match param {
                        SctpParameter::Ipv4(addr4) => IpAddr::V4(addr4),
                        SctpParameter::Ipv6(addr6) => IpAddr::V6(addr6),
                        _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    },
                    time: time,
                })
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SctpHmacAlgoId(pub u16);

newtype_enum! {
impl debug SctpHmacAlgoId {
    Sha1    = 1,
    Sha256  = 256,
}
}

impl From<SctpHmacAlgoId> for u16 {
    fn from(v: SctpHmacAlgoId) -> u16 {
        v.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SctpErrorCauseCode(pub u16);

newtype_enum! {
impl debug SctpErrorCauseCode {
    InvalidStreamId         = 1,
    MissingParam            = 2,
    CookieError             = 3,
    OutOfResource           = 4,
    UnresolvableAddr        = 5,
    UnrecognizedChunk       = 6,
    InvalidParam            = 7,
    UnrecognizedParam       = 8,
    NoUserData              = 9,
    CookieInShutdown        = 10,
    RestartAssocWithNewAddr = 11,
    UserInitiatedAbort      = 12,
    ProtocolViolation       = 13,
}
}

impl From<SctpErrorCauseCode> for u16 {
    fn from(v: SctpErrorCauseCode) -> u16 {
        v.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SctpErrorCause {
    InvalidStreamId(u16),
    MissingParam(Vec<SctpParameterType>),
    CookieError(u32),
    OutOfResource,
    UnresolvableAddr(SctpParameterType, u16, Vec<u8>),
    UnrecognizedChunk(SctpChunkType, u8, u16, Vec<u8>),
    InvalidParam,
    UnrecognizedParam(SctpParameterType, u16, Vec<u8>),
    NoUserData(u32),
    CookieInShutdown,
    RestartAssocWithNewAddr(SctpParameterType, u16, Vec<u8>),
    UserInitiatedAbort(Vec<u8>),
    ProtocolViolation(Vec<u8>),
    Unknown(SctpErrorCauseCode, Vec<u8>),
}

impl SctpErrorCause {
    pub fn bytes_len(&self) -> usize {
        let mut len = match self {
            SctpErrorCause::InvalidStreamId(_) => {
                let mut len = 2; //  Cause Code
                len += 2; // Cause Length
                len += 2; // Stream Identifier
                len += 2; //  (Reserved)
                len
            }
            SctpErrorCause::UserInitiatedAbort(v) => {
                let mut len = 2; //  Cause Code
                len += 2; // Cause Length
                len += v.len();
                len
            }
            SctpErrorCause::ProtocolViolation(v) => {
                let mut len = 2; //  Cause Code
                len += 2; // Cause Length
                len += v.len();
                len
            }
            _ => 0,
        };
        if len % 4 > 0 {
            len += 4 - (len % 4);
        }
        len
    }

    pub fn to_bytes(&self, bytes: &mut Vec<u8>) -> Result<usize> {
        let prev_len = bytes.len();
        match self {
            SctpErrorCause::InvalidStreamId(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpErrorCauseCode::InvalidStreamId))
                    .unwrap();
                bytes.write_u16::<BigEndian>(8).unwrap();
                bytes.write_u16::<BigEndian>(*v).unwrap();
                bytes.write_u16::<BigEndian>(0).unwrap();
            }
            SctpErrorCause::UserInitiatedAbort(v) => {
                bytes
                    .write_u16::<BigEndian>(u16::from(SctpErrorCauseCode::UserInitiatedAbort))
                    .unwrap();
                bytes.write_u16::<BigEndian>(4 + v.len() as u16).unwrap();
                bytes.extend(v);
            }
            _ => {}
        }
        if (bytes.len() - prev_len) % 4 > 0 {
            for _ in 0..(4 - ((bytes.len() - prev_len) % 4)) {
                bytes.write_u8(0).unwrap();
            }
        };
        Ok(bytes.len() - prev_len)
    }

    named! {parse_sctp_error_cause<SctpErrorCause>,
        do_parse!(
            code: be_u16 >>
            length: be_u16 >>
            cause: flat_map!(take!(length - 4),
                call!(SctpErrorCause::parse_sctp_error_cause_with_code, SctpErrorCauseCode(code), length as usize - 4)
                ) >>
            ( cause )
        )
    }

    fn parse_sctp_error_cause_with_code(
        i: &[u8],
        cause_code: SctpErrorCauseCode,
        length: usize,
    ) -> IResult<&[u8], SctpErrorCause> {
        match cause_code {
            SctpErrorCauseCode::InvalidStreamId => {
                SctpErrorCause::parse_sctp_error_cause_invalid_stream_id(i)
            }
            SctpErrorCauseCode::UserInitiatedAbort => {
                SctpErrorCause::parse_sctp_error_cause_user_initiated_abort(i, length)
            }
            SctpErrorCauseCode::ProtocolViolation => {
                SctpErrorCause::parse_sctp_error_cause_protocol_violation(i, length)
            }
            _ => map!(i, take!(length), |cause| {
                SctpErrorCause::Unknown(cause_code, Vec::from(cause))
            }),
        }
    }

    named! {parse_sctp_error_cause_invalid_stream_id<SctpErrorCause>,
        do_parse!(
            sid: be_u16 >>
            ( SctpErrorCause::InvalidStreamId(sid) )
        )
    }

    fn parse_sctp_error_cause_user_initiated_abort(
        i: &[u8],
        length: usize,
    ) -> IResult<&[u8], SctpErrorCause> {
        do_parse!(
            i,
            v: take!(length) >> (SctpErrorCause::UserInitiatedAbort(Vec::from(v)))
        )
    }
    fn parse_sctp_error_cause_protocol_violation(
        i: &[u8],
        length: usize,
    ) -> IResult<&[u8], SctpErrorCause> {
        do_parse!(
            i,
            v: take!(length) >> (SctpErrorCause::ProtocolViolation(Vec::from(v)))
        )
    }
}

#[test]
fn test_parse_sctp_common_header() {
    let data: &[u8] = include_bytes!("../assets/sctp_init.bin");
    let expected = SctpCommonHeader {
        src_port: 10001,
        dst_port: 10001,
        vtag: 0x00000000,
        checksum: 0xdefe340e,
    };
    let res = SctpCommonHeader::from_bytes(data);
    assert_eq!(res, Ok((expected, 12)));
}

#[test]
fn test_parse_sctp_data() {
    let data: &[u8] = include_bytes!("../assets/sctp_data.bin");
    let expected = SctpChunk::Data(SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 591162750,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: Vec::from(&data[0x1c..0x1d]),
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 20)));
}

#[test]
fn test_pack_sctp_data() {
    let data: &[u8] = include_bytes!("../assets/sctp_data.bin");
    let mut packed = Vec::new();
    SctpChunk::Data(SctpDataChunk {
        u_bit: false,
        b_bit: true,
        e_bit: true,
        tsn: 591162750,
        stream_id: 0,
        stream_seq: 0,
        proto_id: 0,
        data: Vec::from(&data[0x1c..0x1d]),
    })
    .to_bytes(&mut packed)
    .unwrap();
    assert_eq!(Vec::from(&data[12..]), packed);
}

#[test]
fn test_parse_sctp_init() {
    let data: &[u8] = include_bytes!("../assets/sctp_init.bin");
    let expected = SctpChunk::Init(SctpInitChunk {
        init_tag: 0xbf9ea55b,
        a_rwnd: 131072,
        num_out_strm: 10,
        num_in_strm: 2048,
        init_tsn: 3848980502,
        params: vec![
            SctpParameter::Ecn,
            SctpParameter::ForwardTsn,
            SctpParameter::SupportedExts(vec![
                SctpChunkType::ForwardTsn,
                SctpChunkType::Auth,
                SctpChunkType::Asconf,
                SctpChunkType::AsconfAck,
                SctpChunkType::ReConfig,
            ]),
            SctpParameter::Random(Vec::from(&data[56..88])), // Not checked
            SctpParameter::HmacAlgo(vec![SctpHmacAlgoId::Sha1]),
            SctpParameter::Chunks(vec![SctpChunkType::AsconfAck, SctpChunkType::Asconf]),
            SctpParameter::SupportedAddrs(vec![SctpParameterType::Ipv4, SctpParameterType::Ipv6]),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2601, 0x05c2, 0x0003, 0x30a0, 0x5535, 0xd5f0, 0xa036, 0xfe63,
            )),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2601, 0x05c2, 0x0003, 0x30a0, 0xf40a, 0xed83, 0xa6cb, 0xf5c0,
            )),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2601, 0x05c2, 0x0003, 0x30a0, 0x0000, 0x0000, 0x0000, 0x6e3e,
            )),
        ],
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 160)));
}

#[test]
fn test_pack_sctp_init() {
    let data: &[u8] = include_bytes!("../assets/sctp_init.bin");
    let mut packed = Vec::new();
    SctpChunk::Init(SctpInitChunk {
        init_tag: 0xbf9ea55b,
        a_rwnd: 131072,
        num_out_strm: 10,
        num_in_strm: 2048,
        init_tsn: 3848980502,
        params: vec![
            SctpParameter::Ecn,
            SctpParameter::ForwardTsn,
            SctpParameter::SupportedExts(vec![
                SctpChunkType::ForwardTsn,
                SctpChunkType::Auth,
                SctpChunkType::Asconf,
                SctpChunkType::AsconfAck,
                SctpChunkType::ReConfig,
            ]),
            SctpParameter::Random(Vec::from(&data[56..88])), // Not checked
            SctpParameter::HmacAlgo(vec![SctpHmacAlgoId::Sha1]),
            SctpParameter::Chunks(vec![SctpChunkType::AsconfAck, SctpChunkType::Asconf]),
            SctpParameter::SupportedAddrs(vec![SctpParameterType::Ipv4, SctpParameterType::Ipv6]),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2601, 0x05c2, 0x0003, 0x30a0, 0x5535, 0xd5f0, 0xa036, 0xfe63,
            )),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2601, 0x05c2, 0x0003, 0x30a0, 0xf40a, 0xed83, 0xa6cb, 0xf5c0,
            )),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2601, 0x05c2, 0x0003, 0x30a0, 0x0000, 0x0000, 0x0000, 0x6e3e,
            )),
        ],
    })
    .to_bytes(&mut packed)
    .unwrap();

    assert_eq!(Vec::from(&data[12..]), packed);
}

#[test]
fn test_parse_sctp_initack() {
    let data: &[u8] = include_bytes!("../assets/sctp_initack.bin");
    let expected = SctpChunk::InitAck(SctpInitChunk {
        init_tag: 0xb5203e2a,
        a_rwnd: 131072,
        num_out_strm: 10,
        num_in_strm: 2048,
        init_tsn: 510840415,
        params: vec![
            SctpParameter::Ecn,
            SctpParameter::ForwardTsn,
            SctpParameter::SupportedExts(vec![
                SctpChunkType::ForwardTsn,
                SctpChunkType::Auth,
                SctpChunkType::Asconf,
                SctpChunkType::AsconfAck,
                SctpChunkType::ReConfig,
            ]),
            SctpParameter::Random(Vec::from(&data[0x38..0x58])), // Not checked
            SctpParameter::HmacAlgo(vec![SctpHmacAlgoId::Sha1]),
            SctpParameter::Chunks(vec![SctpChunkType::AsconfAck, SctpChunkType::Asconf]),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2401, 0x2500, 0x0102, 0x1101, 0x0133, 0x0242, 0x0129, 0x0057,
            )),
            SctpParameter::Ipv4(Ipv4Addr::new(133, 242, 129, 57)),
            SctpParameter::Cookie(Vec::from(&data[0x88..0x224])), // Not checked
        ],
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 536)));
}

#[test]
fn test_pack_sctp_initack() {
    let data: &[u8] = include_bytes!("../assets/sctp_initack.bin");
    let mut packed = Vec::new();
    SctpChunk::InitAck(SctpInitChunk {
        init_tag: 0xb5203e2a,
        a_rwnd: 131072,
        num_out_strm: 10,
        num_in_strm: 2048,
        init_tsn: 510840415,
        params: vec![
            SctpParameter::Ecn,
            SctpParameter::ForwardTsn,
            SctpParameter::SupportedExts(vec![
                SctpChunkType::ForwardTsn,
                SctpChunkType::Auth,
                SctpChunkType::Asconf,
                SctpChunkType::AsconfAck,
                SctpChunkType::ReConfig,
            ]),
            SctpParameter::Random(Vec::from(&data[0x38..0x58])), // Not checked
            SctpParameter::HmacAlgo(vec![SctpHmacAlgoId::Sha1]),
            SctpParameter::Chunks(vec![SctpChunkType::AsconfAck, SctpChunkType::Asconf]),
            SctpParameter::Ipv6(Ipv6Addr::new(
                0x2401, 0x2500, 0x0102, 0x1101, 0x0133, 0x0242, 0x0129, 0x0057,
            )),
            SctpParameter::Ipv4(Ipv4Addr::new(133, 242, 129, 57)),
            SctpParameter::Cookie(Vec::from(&data[0x88..0x224])), // Not checked
        ],
    })
    .to_bytes(&mut packed)
    .unwrap();

    SctpChunk::from_bytes(&data[12..]).unwrap();
    assert_eq!(Vec::from(&data[12..]), packed);
}

#[test]
fn test_parse_sctp_sack() {
    let data: &[u8] = include_bytes!("../assets/sctp_sack.bin");
    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 591162750,
        a_rwnd: 130815,
        num_gap_ack: 0,
        num_dup_ack: 0,
        gap_acks: Vec::new(),
        dup_acks: Vec::new(),
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 16)));

    let data: &[u8] = include_bytes!("../assets/sctp_sack_with_gap.bin");
    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 591162750,
        a_rwnd: 130815,
        num_gap_ack: 1,
        num_dup_ack: 0,
        gap_acks: vec![SctpGapAckBlock { start: 1, end: 2 }],
        dup_acks: Vec::new(),
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 20)));

    let data: &[u8] = include_bytes!("../assets/sctp_sack_with_dup.bin");
    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 591162750,
        a_rwnd: 130815,
        num_gap_ack: 0,
        num_dup_ack: 1,
        gap_acks: Vec::new(),
        dup_acks: vec![591162750],
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 20)));

    let data: &[u8] = include_bytes!("../assets/sctp_sack_with_gap_and_dup.bin");
    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 591162750,
        a_rwnd: 130815,
        num_gap_ack: 1,
        num_dup_ack: 1,
        gap_acks: vec![SctpGapAckBlock { start: 1, end: 2 }],
        dup_acks: vec![591162750],
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 24)));
}

#[test]
fn test_parse_sctp_abort() {
    let empty = &b""[..];
    let data: &[u8] = include_bytes!("../assets/sctp_abort.bin");
    let expected = SctpChunk::Abort(SctpAbortChunk {
        t_bit: false,
        error_cause: Some(SctpErrorCause::UserInitiatedAbort(Vec::from(empty))),
    });

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 8)));
}

#[test]
fn test_parse_sctp_heartbeat() {
    let data: &[u8] = include_bytes!("../assets/sctp_heartbeat.bin");
    let expected = SctpChunk::Heartbeat(Vec::from(&data[0x10..0x38]));

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 44)));
}

#[test]
fn test_pack_sctp_heartbeat() {
    let data: &[u8] = include_bytes!("../assets/sctp_heartbeat.bin");
    let mut packed = Vec::new();
    SctpChunk::Heartbeat(Vec::from(&data[0x10..0x38]))
        .to_bytes(&mut packed)
        .unwrap();

    assert_eq!(Vec::from(&data[12..]), packed);
}

#[test]
fn test_parse_sctp_heartbeat_ack() {
    let data: &[u8] = include_bytes!("../assets/sctp_heartbeatack.bin");
    let expected = SctpChunk::HeartbeatAck(Vec::from(&data[0x10..0x38]));

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 44)));
}

#[test]
fn test_parse_sctp_shutdown() {
    let data: &[u8] = include_bytes!("../assets/sctp_shutdown.bin");
    let expected = SctpChunk::Shutdown(4094720724);

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 8)));
}

#[test]
fn test_parse_sctp_shutdown_ack() {
    let data: &[u8] = include_bytes!("../assets/sctp_shutdownack.bin");
    let expected = SctpChunk::ShutdownAck;

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 4)));
}

#[test]
fn test_parse_sctp_cookie_echo() {
    let data: &[u8] = include_bytes!("../assets/sctp_cookieecho.bin");
    let expected = SctpChunk::CookieEcho(Vec::from(&data[0x10..0x1ac]));

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 416)));
}

#[test]
fn test_parse_sctp_cookie_ack() {
    let data: &[u8] = include_bytes!("../assets/sctp_cookieack.bin");
    let expected = SctpChunk::CookieAck;

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 4)));
}

#[test]
fn test_parse_sctp_shutdown_complete() {
    let data: &[u8] = include_bytes!("../assets/sctp_shutdowncomplete.bin");
    let expected = SctpChunk::ShutdownComplete(false);

    let res = SctpChunk::from_bytes(&data[12..]);
    assert_eq!(res, Ok((expected, 4)));
}
