use sna::SerialNumber;

pub use crate::sctp_pkt::*;
use crate::Result;
use crate::SctpError;

#[derive(Debug)]
pub struct SctpMappingArray {
    storage: Vec<u8>,
    base_tsn: SerialNumber<u32>,
    pub largest_tsn: SerialNumber<u32>,
    pub cummulative_tsn: SerialNumber<u32>,
    trace_id: String,
}

impl SctpMappingArray {
    pub fn new(trace_id: String) -> Self {
        SctpMappingArray {
            storage: Vec::new(),
            base_tsn: SerialNumber(0),
            largest_tsn: SerialNumber(0),
            cummulative_tsn: SerialNumber(0),
            trace_id: trace_id,
        }
    }

    pub fn initialize(&mut self, init_tsn: u32) -> Result<u32> {
        let initial_tsn_minus1 = if init_tsn == 0 {
            SerialNumber(0xffffffff)
        } else {
            SerialNumber(init_tsn - 1)
        };
        self.base_tsn = SerialNumber(init_tsn);
        self.largest_tsn = initial_tsn_minus1;
        self.cummulative_tsn = initial_tsn_minus1;
        self.storage = (0..256).map(|_| 0x00).collect();

        Ok(init_tsn)
    }

    pub fn update(&mut self, tsn: u32) -> Result<Option<u32>> {
        if SerialNumber(tsn) < self.base_tsn {
            return Err(SctpError::InvalidValue);
        };
        if SerialNumber(tsn) < self.cummulative_tsn {
            return Err(SctpError::InvalidValue);
        }
        let gap = if tsn >= self.base_tsn.0 {
            tsn - self.base_tsn.0
        } else {
            0xffffffff - self.base_tsn.0 + 1 + tsn
        };
        if (gap >> 3) as usize > self.storage.len() {
            self.storage
                .reserve((gap >> 3) as usize - self.storage.len());
        }
        self.storage[(gap >> 3) as usize] |= 0x01 << (gap & 0x07);

        if tsn > self.largest_tsn {
            self.largest_tsn = SerialNumber(tsn);
        }

        let mut cummulative_tsn = if self.base_tsn.0 == 0 {
            SerialNumber(0xffffffff)
        } else {
            SerialNumber(self.base_tsn.0 - 1)
        };
        let mut moved = 0;
        for byte in &self.storage[0..] {
            if *byte == 0xff {
                cummulative_tsn += 8;
                moved += 1;
                continue;
            }
            for i in 0..8 {
                if ((*byte >> i) & 0x01) == 0x01 {
                    cummulative_tsn += 1;
                } else {
                    break;
                }
            }
            break;
        }

        if moved > 0 {
            for i in 0..moved {
                self.storage[i] = 0x00u8;
            }
            self.storage.rotate_left(moved);
            self.base_tsn += 8;
        }

        trace!(
            "{} update base_tsn={}, cummulative_tsn={}, largest_tsn={}",
            self.trace_id,
            self.base_tsn,
            cummulative_tsn,
            self.largest_tsn
        );
        if cummulative_tsn > self.cummulative_tsn {
            self.cummulative_tsn = cummulative_tsn;
            Ok(Some(self.cummulative_tsn.0))
        } else {
            Ok(None)
        }
    }

    pub fn genarate_sack(&self, a_rwnd: u32) -> Result<SctpChunk> {
        let mut gap_ack_blocks: Vec<SctpGapAckBlock> = Vec::new();

        if self.largest_tsn > self.cummulative_tsn {
            let mut offset = 0;
            if self.cummulative_tsn >= self.base_tsn {
                offset = if self.cummulative_tsn.0 >= self.base_tsn.0 {
                    0 - (self.cummulative_tsn.0 - self.base_tsn.0 + 1) as i16
                } else {
                    0 - (0xffffffff - self.cummulative_tsn.0 + 1 + self.base_tsn.0 + 1) as i16
                };
                assert!(offset > -8);
            }

            let mut mergenable = false;
            for (i, item) in self.storage.iter().enumerate() {
                let byte = if i == 0 && offset < 0 {
                    *item & (0xff << (0 - offset))
                } else {
                    *item
                };
                let track = SctpAckTrack::get(byte);
                for gap in &track.gaps {
                    if !mergenable || !track.right_edge {
                        gap_ack_blocks.push(SctpGapAckBlock {
                            start: if offset < 0 {
                                gap.start - (0 - offset) as u16 + 1
                            } else {
                                gap.start + offset as u16 + 1
                            },
                            end: if offset < 0 {
                                gap.end - (0 - offset) as u16 + 1
                            } else {
                                gap.end + offset as u16 + 1
                            },
                        });
                    }
                    let len = gap_ack_blocks.len();
                    gap_ack_blocks[len - 1].end = if offset < 0 {
                        gap.end - (0 - offset) as u16 + 1
                    } else {
                        gap.end + offset as u16 + 1
                    };
                    mergenable = false;
                }
                if track.left_edge {
                    mergenable = true;
                }
                offset += 8;
                if self.cummulative_tsn + offset as u32 >= self.largest_tsn {
                    break;
                }
            }
        }

        let sack = SctpChunk::Sack(SctpSackChunk {
            cum_ack: self.cummulative_tsn.0,
            a_rwnd: a_rwnd,
            num_gap_ack: gap_ack_blocks.len() as u16,
            num_dup_ack: 0,
            gap_acks: gap_ack_blocks,
            dup_acks: Vec::new(),
        });
        Ok(sack)
    }
}

#[derive(Debug, PartialEq)]
struct SctpAckTrack {
    right_edge: bool,
    left_edge: bool,
    gaps: Vec<SctpGapAckBlock>,
}

impl SctpAckTrack {
    fn get(byte: u8) -> SctpAckTrack {
        match byte {
            0x00 /* 0b00000000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![]},
            0x01 /* 0b00000001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}]},
            0x02 /* 0b00000010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}]},
            0x03 /* 0b00000011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}]},
            0x04 /* 0b00000100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}]},
            0x05 /* 0b00000101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}]},
            0x06 /* 0b00000110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}]},
            0x07 /* 0b00000111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}]},
            0x08 /* 0b00001000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 3}]},
            0x09 /* 0b00001001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}]},
            0x0a /* 0b00001010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}]},
            0x0b /* 0b00001011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}]},
            0x0c /* 0b00001100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 3}]},
            0x0d /* 0b00001101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}]},
            0x0e /* 0b00001110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 3}]},
            0x0f /* 0b00001111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 3}]},
            0x10 /* 0b00010000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 4, end: 4}]},
            0x11 /* 0b00010001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 4}]},
            0x12 /* 0b00010010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 4}]},
            0x13 /* 0b00010011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 4}]},
            0x14 /* 0b00010100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}]},
            0x15 /* 0b00010101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}]},
            0x16 /* 0b00010110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 4}]},
            0x17 /* 0b00010111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 4}]},
            0x18 /* 0b00011000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 4}]},
            0x19 /* 0b00011001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 4}]},
            0x1a /* 0b00011010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 4}]},
            0x1b /* 0b00011011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 4}]},
            0x1c /* 0b00011100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 4}]},
            0x1d /* 0b00011101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 4}]},
            0x1e /* 0b00011110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 4}]},
            0x1f /* 0b00011111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 4}]},
            0x20 /* 0b00100000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 5, end: 5}]},
            0x21 /* 0b00100001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 5, end: 5}]},
            0x22 /* 0b00100010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 5, end: 5}]},
            0x23 /* 0b00100011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 5, end: 5}]},
            0x24 /* 0b00100100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 5}]},
            0x25 /* 0b00100101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 5}]},
            0x26 /* 0b00100110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 5, end: 5}]},
            0x27 /* 0b00100111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 5, end: 5}]},
            0x28 /* 0b00101000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x29 /* 0b00101001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x2a /* 0b00101010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x2b /* 0b00101011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x2c /* 0b00101100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x2d /* 0b00101101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x2e /* 0b00101110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x2f /* 0b00101111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 3}, SctpGapAckBlock{start: 5, end: 5}]},
            0x30 /* 0b00110000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 4, end: 5}]},
            0x31 /* 0b00110001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 5}]},
            0x32 /* 0b00110010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 5}]},
            0x33 /* 0b00110011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 5}]},
            0x34 /* 0b00110100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 5}]},
            0x35 /* 0b00110101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 5}]},
            0x36 /* 0b00110110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 5}]},
            0x37 /* 0b00110111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 5}]},
            0x38 /* 0b00111000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 5}]},
            0x39 /* 0b00111001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 5}]},
            0x3a /* 0b00111010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 5}]},
            0x3b /* 0b00111011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 5}]},
            0x3c /* 0b00111100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 5}]},
            0x3d /* 0b00111101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 5}]},
            0x3e /* 0b00111110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 5}]},
            0x3f /* 0b00111111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 5}]},
            0x40 /* 0b01000000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 6, end: 6}]},
            0x41 /* 0b01000001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 6, end: 6}]},
            0x42 /* 0b01000010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 6, end: 6}]},
            0x43 /* 0b01000011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 6, end: 6}]},
            0x44 /* 0b01000100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 6, end: 6}]},
            0x45 /* 0b01000101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 6, end: 6}]},
            0x46 /* 0b01000110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 6, end: 6}]},
            0x47 /* 0b01000111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 6, end: 6}]},
            0x48 /* 0b01001000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x49 /* 0b01001001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x4a /* 0b01001010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x4b /* 0b01001011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x4c /* 0b01001100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x4d /* 0b01001101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x4e /* 0b01001110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x4f /* 0b01001111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 3}, SctpGapAckBlock{start: 6, end: 6}]},
            0x50 /* 0b01010000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x51 /* 0b01010001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x52 /* 0b01010010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x53 /* 0b01010011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x54 /* 0b01010100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x55 /* 0b01010101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x56 /* 0b01010110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x57 /* 0b01010111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x58 /* 0b01011000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x59 /* 0b01011001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x5a /* 0b01011010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x5b /* 0b01011011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x5c /* 0b01011100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x5d /* 0b01011101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x5e /* 0b01011110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x5f /* 0b01011111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 4}, SctpGapAckBlock{start: 6, end: 6}]},
            0x60 /* 0b01100000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 5, end: 6}]},
            0x61 /* 0b01100001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 5, end: 6}]},
            0x62 /* 0b01100010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 5, end: 6}]},
            0x63 /* 0b01100011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 5, end: 6}]},
            0x64 /* 0b01100100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 6}]},
            0x65 /* 0b01100101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 6}]},
            0x66 /* 0b01100110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 5, end: 6}]},
            0x67 /* 0b01100111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 5, end: 6}]},
            0x68 /* 0b01101000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x69 /* 0b01101001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x6a /* 0b01101010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x6b /* 0b01101011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x6c /* 0b01101100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x6d /* 0b01101101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x6e /* 0b01101110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x6f /* 0b01101111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 3}, SctpGapAckBlock{start: 5, end: 6}]},
            0x70 /* 0b01110000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 4, end: 6}]},
            0x71 /* 0b01110001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 6}]},
            0x72 /* 0b01110010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 6}]},
            0x73 /* 0b01110011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 6}]},
            0x74 /* 0b01110100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 6}]},
            0x75 /* 0b01110101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 6}]},
            0x76 /* 0b01110110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 6}]},
            0x77 /* 0b01110111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 6}]},
            0x78 /* 0b01111000 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 3, end: 6}]},
            0x79 /* 0b01111001 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 6}]},
            0x7a /* 0b01111010 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 6}]},
            0x7b /* 0b01111011 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 6}]},
            0x7c /* 0b01111100 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 2, end: 6}]},
            0x7d /* 0b01111101 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 6}]},
            0x7e /* 0b01111110 */ => SctpAckTrack {right_edge: false, left_edge: false, gaps: vec![SctpGapAckBlock{start: 1, end: 6}]},
            0x7f /* 0b01111111 */ => SctpAckTrack {right_edge: true, left_edge: false, gaps: vec![SctpGapAckBlock{start: 0, end: 6}]},
            0x80 /* 0b10000000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 7, end: 7}]},
            0x81 /* 0b10000001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 7, end: 7}]},
            0x82 /* 0b10000010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 7, end: 7}]},
            0x83 /* 0b10000011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 7, end: 7}]},
            0x84 /* 0b10000100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 7, end: 7}]},
            0x85 /* 0b10000101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 7, end: 7}]},
            0x86 /* 0b10000110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 7, end: 7}]},
            0x87 /* 0b10000111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 7, end: 7}]},
            0x88 /* 0b10001000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x89 /* 0b10001001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x8a /* 0b10001010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x8b /* 0b10001011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x8c /* 0b10001100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x8d /* 0b10001101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x8e /* 0b10001110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x8f /* 0b10001111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 3}, SctpGapAckBlock{start: 7, end: 7}]},
            0x90 /* 0b10010000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x91 /* 0b10010001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x92 /* 0b10010010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x93 /* 0b10010011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x94 /* 0b10010100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x95 /* 0b10010101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x96 /* 0b10010110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x97 /* 0b10010111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x98 /* 0b10011000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x99 /* 0b10011001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x9a /* 0b10011010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x9b /* 0b10011011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x9c /* 0b10011100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x9d /* 0b10011101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x9e /* 0b10011110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0x9f /* 0b10011111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 4}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa0 /* 0b10100000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa1 /* 0b10100001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa2 /* 0b10100010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa3 /* 0b10100011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa4 /* 0b10100100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa5 /* 0b10100101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa6 /* 0b10100110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa7 /* 0b10100111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa8 /* 0b10101000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xa9 /* 0b10101001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xaa /* 0b10101010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xab /* 0b10101011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xac /* 0b10101100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xad /* 0b10101101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xae /* 0b10101110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xaf /* 0b10101111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 3}, SctpGapAckBlock{start: 5, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb0 /* 0b10110000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb1 /* 0b10110001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb2 /* 0b10110010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb3 /* 0b10110011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb4 /* 0b10110100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb5 /* 0b10110101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb6 /* 0b10110110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb7 /* 0b10110111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb8 /* 0b10111000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xb9 /* 0b10111001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xba /* 0b10111010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xbb /* 0b10111011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xbc /* 0b10111100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xbd /* 0b10111101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xbe /* 0b10111110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xbf /* 0b10111111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 5}, SctpGapAckBlock{start: 7, end: 7}]},
            0xc0 /* 0b11000000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 6, end: 7}]},
            0xc1 /* 0b11000001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc2 /* 0b11000010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc3 /* 0b11000011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc4 /* 0b11000100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc5 /* 0b11000101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc6 /* 0b11000110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc7 /* 0b11000111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc8 /* 0b11001000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xc9 /* 0b11001001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xca /* 0b11001010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xcb /* 0b11001011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xcc /* 0b11001100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xcd /* 0b11001101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xce /* 0b11001110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xcf /* 0b11001111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 3}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd0 /* 0b11010000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd1 /* 0b11010001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd2 /* 0b11010010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd3 /* 0b11010011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd4 /* 0b11010100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd5 /* 0b11010101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd6 /* 0b11010110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd7 /* 0b11010111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd8 /* 0b11011000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xd9 /* 0b11011001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xda /* 0b11011010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xdb /* 0b11011011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xdc /* 0b11011100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xdd /* 0b11011101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xde /* 0b11011110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xdf /* 0b11011111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 4}, SctpGapAckBlock{start: 6, end: 7}]},
            0xe0 /* 0b11100000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 5, end: 7}]},
            0xe1 /* 0b11100001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe2 /* 0b11100010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe3 /* 0b11100011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe4 /* 0b11100100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe5 /* 0b11100101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe6 /* 0b11100110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe7 /* 0b11100111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe8 /* 0b11101000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xe9 /* 0b11101001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xea /* 0b11101010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xeb /* 0b11101011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xec /* 0b11101100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xed /* 0b11101101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xee /* 0b11101110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xef /* 0b11101111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 3}, SctpGapAckBlock{start: 5, end: 7}]},
            0xf0 /* 0b11110000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 4, end: 7}]},
            0xf1 /* 0b11110001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 4, end: 7}]},
            0xf2 /* 0b11110010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 4, end: 7}]},
            0xf3 /* 0b11110011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 4, end: 7}]},
            0xf4 /* 0b11110100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 7}]},
            0xf5 /* 0b11110101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 2}, SctpGapAckBlock{start: 4, end: 7}]},
            0xf6 /* 0b11110110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 2}, SctpGapAckBlock{start: 4, end: 7}]},
            0xf7 /* 0b11110111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 2}, SctpGapAckBlock{start: 4, end: 7}]},
            0xf8 /* 0b11111000 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 3, end: 7}]},
            0xf9 /* 0b11111001 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 3, end: 7}]},
            0xfa /* 0b11111010 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 1}, SctpGapAckBlock{start: 3, end: 7}]},
            0xfb /* 0b11111011 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 1}, SctpGapAckBlock{start: 3, end: 7}]},
            0xfc /* 0b11111100 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 2, end: 7}]},
            0xfd /* 0b11111101 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 0}, SctpGapAckBlock{start: 2, end: 7}]},
            0xfe /* 0b11111110 */ => SctpAckTrack {right_edge: false, left_edge: true, gaps: vec![SctpGapAckBlock{start: 1, end: 7}]},
            0xff /* 0b11111111 */ => SctpAckTrack {right_edge: true, left_edge: true, gaps: vec![SctpGapAckBlock{start: 0, end: 7}]},
        }
    }
}

#[test]
fn test_sctp_tsn_record() {
    let mut record = SctpMappingArray::new(String::from("test"));
    record.initialize(510840415).unwrap();

    assert_eq!(record.cummulative_tsn, 510840415 - 1);
    assert_eq!(record.largest_tsn, 510840415 - 1);

    let ret = record.update(510840415).unwrap();
    assert_eq!(ret, Some(510840415));
    assert_eq!(record.cummulative_tsn, 510840415);
    assert_eq!(record.largest_tsn, 510840415);

    let ret = record.update(510840415 + 2).unwrap();
    assert_eq!(ret, None);
    assert_eq!(record.cummulative_tsn, 510840415);
    assert_eq!(record.largest_tsn, 510840415 + 2);

    let ret = record.update(510840415 + 1).unwrap();
    assert_eq!(ret, Some(510840415 + 2));
    assert_eq!(record.largest_tsn, 510840415 + 2);
    assert_eq!(record.cummulative_tsn, 510840415 + 2);

    let ret = record.update(510840415 + 8).unwrap();
    assert_eq!(ret, None);
    assert_eq!(record.largest_tsn, 510840415 + 8);
    assert_eq!(record.cummulative_tsn, 510840415 + 2);

    let ret = record.update(510840415 + 4).unwrap();
    assert_eq!(ret, None);
    assert_eq!(record.largest_tsn, 510840415 + 8);
    assert_eq!(record.cummulative_tsn, 510840415 + 2);

    let ret = record.update(510840415 + 5).unwrap();
    assert_eq!(ret, None);
    assert_eq!(record.largest_tsn, 510840415 + 8);
    assert_eq!(record.cummulative_tsn, 510840415 + 2);

    let ret = record.update(510840415 + 6).unwrap();
    assert_eq!(ret, None);
    assert_eq!(record.largest_tsn, 510840415 + 8);
    assert_eq!(record.cummulative_tsn, 510840415 + 2);

    let ret = record.update(510840415 + 7).unwrap();
    assert_eq!(ret, None);
    assert_eq!(record.largest_tsn, 510840415 + 8);
    assert_eq!(record.cummulative_tsn, 510840415 + 2);
    assert_eq!(record.base_tsn, 510840415);

    let ret = record.update(510840415 + 3).unwrap();
    assert_eq!(ret, Some(510840415 + 8));
    assert_eq!(record.largest_tsn, 510840415 + 8);
    assert_eq!(record.cummulative_tsn, 510840415 + 8);
    assert_eq!(record.base_tsn, 510840415 + 8);

    let ret = record.update(510840415 + 9).unwrap();
    assert_eq!(ret, Some(510840415 + 9));
    assert_eq!(record.largest_tsn, 510840415 + 9);
    assert_eq!(record.cummulative_tsn, 510840415 + 9);
}

#[test]
fn test_sctp_ack_track() {
    let mut record = SctpMappingArray::new(String::from("test"));
    record.initialize(0).unwrap();
    for i in 0..13 {
        record.update(i).unwrap();
    }

    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 12,
        a_rwnd: 0,
        num_gap_ack: 0,
        num_dup_ack: 0,
        gap_acks: Vec::new(),
        dup_acks: Vec::new(),
    });
    let sack = record.genarate_sack(0).unwrap();
    assert_eq!(sack, expected);

    record.update(14).unwrap();
    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 12,
        a_rwnd: 0,
        num_gap_ack: 1,
        num_dup_ack: 0,
        gap_acks: vec![SctpGapAckBlock { start: 2, end: 2 }],
        dup_acks: Vec::new(),
    });
    let sack = record.genarate_sack(0).unwrap();
    assert_eq!(sack, expected);

    record.update(15).unwrap();
    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 12,
        a_rwnd: 0,
        num_gap_ack: 1,
        num_dup_ack: 0,
        gap_acks: vec![SctpGapAckBlock { start: 2, end: 3 }],
        dup_acks: Vec::new(),
    });
    let sack = record.genarate_sack(0).unwrap();
    assert_eq!(sack, expected);

    record.update(17).unwrap();
    let expected = SctpChunk::Sack(SctpSackChunk {
        cum_ack: 12,
        a_rwnd: 0,
        num_gap_ack: 2,
        num_dup_ack: 0,
        gap_acks: vec![
            SctpGapAckBlock { start: 2, end: 3 },
            SctpGapAckBlock { start: 5, end: 5 },
        ],
        dup_acks: Vec::new(),
    });
    let sack = record.genarate_sack(0).unwrap();
    assert_eq!(sack, expected);
}
