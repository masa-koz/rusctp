extern crate os_socketaddr;
#[cfg(target_family = "windows")]
extern crate winapi;

use std::ffi;
use std::ptr;
use std::slice;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::ssize_t;

#[cfg(target_family = "unix")]
use libc::sockaddr;
#[cfg(target_family = "windows")]
use winapi::shared::ws2def::SOCKADDR as sockaddr;

use os_socketaddr::OsSocketAddr;

use crate::*;

#[no_mangle]
pub extern "C" fn rusctp_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}

#[no_mangle]
pub extern "C" fn rusctp_header_info(
    rbuf: *mut u8,
    rbuf_len: size_t,
    src_port: *mut u16,
    dst_port: *mut u16,
    vtag: *mut u32,
) -> c_int {
    let rbuf = unsafe { slice::from_raw_parts_mut(rbuf, rbuf_len) };
    match SctpCommonHeader::from_bytes(&rbuf[0..rbuf_len]) {
        Ok((sh, _)) => unsafe {
            *src_port = sh.src_port;
            *dst_port = sh.dst_port;
            *vtag = sh.vtag;
            0
        },
        Err(e) => {
            error!("SctpCommonHeader::from_bytes() failed: {:?}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rusctp_accept(
    from_sa: &sockaddr,
    from_salen: size_t,
    sh: &SctpCommonHeader,
    rbuf: *mut u8,
    rbuf_len: size_t,
    sbuf: *mut u8,
    sbuf_len: *mut size_t,
    secret: *mut u8,
    secret_len: size_t,
) -> *mut SctpAssociation {
    if from_salen == 0 {
        return ptr::null_mut();
    }
    let from = unsafe {
        OsSocketAddr::from_raw_parts(&from_sa as *const _ as *const u8, from_salen).into_addr()
    };
    if from.is_none() {
        return ptr::null_mut();
    }
    let rbuf = unsafe { slice::from_raw_parts_mut(rbuf, rbuf_len) };
    let mut sbuf = unsafe { Vec::from_raw_parts(sbuf, 0, *sbuf_len) };
    let secret = unsafe { slice::from_raw_parts_mut(secret, secret_len) };

    match SctpAssociation::accept(&from.unwrap().ip(), sh, &rbuf, &mut sbuf, &secret) {
        Ok((Some(assoc), consumed)) => unsafe {
            *sbuf_len = consumed;
            Box::into_raw(Box::from_raw(&assoc as *const _ as *mut SctpAssociation))
        },
        Ok((None, consumed)) => {
            unsafe {
                *sbuf_len = consumed;
            };
            ptr::null_mut()
        }
        Err(_) => ptr::null_mut(),
    }
}
