extern crate os_socketaddr;
#[cfg(target_family = "windows")]
extern crate winapi;

use std::ptr;
use std::slice;
use std::sync::atomic;

use libc::c_int;
use libc::c_void;
use libc::size_t;

#[cfg(target_family = "unix")]
use libc::sockaddr;
#[cfg(target_family = "windows")]
use winapi::shared::ws2def::SOCKADDR as sockaddr;

use os_socketaddr::OsSocketAddr;

use crate::*;

struct Logger {
    cb: extern "C" fn(line: *const u8, argp: *mut c_void),
    argp: std::sync::atomic::AtomicPtr<c_void>,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = format!("{}: {}\0", record.target(), record.args());
        (self.cb)(line.as_ptr(), self.argp.load(atomic::Ordering::Relaxed));
    }

    fn flush(&self) {}
}

#[repr(C)]
pub enum LogLevel {
    /// A level lower than all log levels.
    _Off = 0,
    /// Corresponds to the `Error` log level.
    _Error = 1,
    /// Corresponds to the `Warn` log level.
    _Warn = 2,
    /// Corresponds to the `Info` log level.
    _Info = 3,
    /// Corresponds to the `Debug` log level.
    _Debug = 4,
    /// Corresponds to the `Trace` log level.
    _Trace = 5,
}

#[no_mangle]
pub extern "C" fn rusctp_enable_logging(
    cb: extern "C" fn(line: *const u8, argp: *mut c_void),
    argp: *mut c_void,
    max_level: LogLevel,
) -> c_int {
    let argp = atomic::AtomicPtr::new(argp);
    let logger = Box::new(Logger { cb, argp });

    if log::set_boxed_logger(logger).is_err() {
        return -1;
    }

    let max_level = match max_level {
        LogLevel::_Off => log::LevelFilter::Off,
        LogLevel::_Error => log::LevelFilter::Error,
        LogLevel::_Warn => log::LevelFilter::Warn,
        LogLevel::_Info => log::LevelFilter::Info,
        LogLevel::_Debug => log::LevelFilter::Debug,
        LogLevel::_Trace => log::LevelFilter::Trace,
    };

    log::set_max_level(max_level);

    0
}

#[no_mangle]
pub extern "C" fn rusctp_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}

#[no_mangle]
pub extern "C" fn rusctp_config_new(sh_local_port: u16) -> *mut SctpInitialConfig {
    Box::into_raw(Box::new(SctpInitialConfig::new(sh_local_port)))
}

#[no_mangle]
pub extern "C" fn rusctp_config_set_secret_key(
    config: &mut SctpInitialConfig,
    secret: *mut u8,
    secret_len: size_t,
) -> c_int {
    let secret = unsafe { slice::from_raw_parts_mut(secret, secret_len) };
    config.set_secret_key(secret);
    0
}

#[no_mangle]
pub extern "C" fn rusctp_config_add_laddr(
    config: &mut SctpInitialConfig,
    laddr_sa: &sockaddr,
    laddr_salen: size_t,
) -> c_int {
    if laddr_salen == 0 {
        return -1;
    }
    let laddr = unsafe {
        OsSocketAddr::from_raw_parts(laddr_sa as *const _ as *const u8, laddr_salen)
            .into_addr()
            .unwrap()
    };
    match config.add_laddr(laddr.ip()) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn rusctp_config_free(config: *mut SctpInitialConfig) {
    unsafe { Box::from_raw(config) };
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
    rbuf: *mut u8,
    rbuf_len: *mut size_t,
    sbuf: *mut u8,
    sbuf_len: *mut size_t,
    config: &SctpInitialConfig,
) -> *mut SctpAssociation {
    if from_salen == 0 {
        unsafe {
            *sbuf_len = 0;
        }
        return ptr::null_mut();
    }
    let from = unsafe {
        OsSocketAddr::from_raw_parts(from_sa as *const _ as *const u8, from_salen).into_addr()
    };
    if from.is_none() {
        unsafe {
            *sbuf_len = 0;
        }
        return ptr::null_mut();
    }
    let rbuf = unsafe { slice::from_raw_parts_mut(rbuf, *rbuf_len) };
    let mut sbuf1 = Vec::new();

    if let Ok((sh, consumed)) = SctpCommonHeader::from_bytes(&rbuf) {
        match SctpAssociation::accept(
            &from.unwrap().ip(),
            &sh,
            &rbuf[consumed..],
            &mut sbuf1,
            config,
        ) {
            Ok((Some(assoc), consumed)) => unsafe {
                *rbuf_len = consumed;
                *sbuf_len = std::cmp::min(*sbuf_len, sbuf1.len());
                ptr::copy(sbuf1.as_mut_ptr(), sbuf, *sbuf_len);
                return Box::into_raw(assoc);
            },
            Ok((None, consumed)) => {
                unsafe {
                    *rbuf_len = consumed;
                    *sbuf_len = std::cmp::min(*sbuf_len, sbuf1.len());
                    ptr::copy(sbuf1.as_mut_ptr(), sbuf, *sbuf_len);
                };
                return ptr::null_mut();
            }
            Err(_) => {
                return ptr::null_mut();
            }
        };
    } else {
        return ptr::null_mut();
    }
}

#[no_mangle]
pub extern "C" fn rusctp_assoc_free(assoc: *mut SctpAssociation) {
    unsafe { Box::from_raw(assoc) };
}
