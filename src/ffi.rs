use std::ffi;
use std::ptr;
use std::slice;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::ssize_t;

use crate::*;

#[no_mangle]
pub extern "C" fn rusctp_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}
