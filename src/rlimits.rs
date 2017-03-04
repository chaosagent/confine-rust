// Partially from https://github.com/nix-rust/nix/pull/364

use std::mem;

use libc::{self, c_int, rlim64_t, rlimit64};
pub use libc::RLIM_INFINITY;
#[cfg(any(target_os = "linux",
target_os = "openbsd",
target_os = "netbsd",
target_os = "bitrig"))]
pub use libc::{RLIM_SAVED_CUR, RLIM_SAVED_MAX};

use nix::{Errno, Result};

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    // POSIX
    RLIMIT_CORE = libc::RLIMIT_CORE,
    RLIMIT_CPU = libc::RLIMIT_CPU,
    RLIMIT_DATA = libc::RLIMIT_DATA,
    RLIMIT_FSIZE = libc::RLIMIT_FSIZE,
    RLIMIT_NOFILE = libc::RLIMIT_NOFILE,
    RLIMIT_STACK = libc::RLIMIT_STACK,
    RLIMIT_AS = libc::RLIMIT_AS,
    // BSDs and Linux
    #[cfg(all(unix, not(target_os = "solaris")))]
    RLIMIT_MEMLOCK = libc::RLIMIT_MEMLOCK,
    #[cfg(all(unix, not(target_os = "solaris")))]
    RLIMIT_NPROC = libc::RLIMIT_NPROC,
    #[cfg(all(unix, not(target_os = "solaris")))]
    RLIMIT_RSS = libc::RLIMIT_RSS,
    // Linux-only
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RLIMIT_LOCKS = libc::RLIMIT_LOCKS,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RLIMIT_MSGQUEUE = libc::RLIMIT_MSGQUEUE,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RLIMIT_NICE = libc::RLIMIT_NICE,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RLIMIT_RTPRIO = libc::RLIMIT_RTPRIO,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RLIMIT_RTTIME = libc::RLIMIT_RTTIME,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RLIMIT_SIGPENDING = libc::RLIMIT_SIGPENDING,
}

pub struct RLimit64 {
    resource: Resource,
    rlim_cur: rlim64_t,
    rlim_max: rlim64_t,
}

impl RLimit64 {
    pub fn new(resource: Resource, rlim_cur: rlim64_t, rlim_max: rlim64_t) -> RLimit64 {
        RLimit64 {
            resource: resource,
            rlim_cur: rlim_cur,
            rlim_max: rlim_max,
        }
    }

    // Creates a new rlimit with rlim_max being 1 more than rlim_cur in order to allow detection
    // and handling of resource overages. rlim_cur is set to the passed rlim.
    pub fn new_offsetted(resource: Resource, rlim: rlim64_t) -> RLimit64 {
        RLimit64 {
            resource: resource,
            rlim_cur: rlim,
            rlim_max: RLIM_INFINITY,
        }
    }

    pub fn get(resource: Resource) -> Result<RLimit64> {
        getrlimit(resource).map(|rlim: rlimit64| RLimit64 {
            resource: resource,
            rlim_cur: rlim.rlim_cur,
            rlim_max: rlim.rlim_max,
        })
    }

    pub fn set(&self) -> Result<()> {
        let rlim = rlimit64 {
            rlim_cur: self.rlim_cur,
            rlim_max: self.rlim_max,
        };
        setrlimit(self.resource, rlim)
    }
}

fn getrlimit(resource: Resource) -> Result<rlimit64> {
    let mut rlim = unsafe { mem::uninitialized() };
    let res = unsafe { libc::getrlimit64(resource as c_int, &mut rlim as *mut _) };
    Errno::result(res).map(|_| rlim)
}

fn setrlimit(resource: Resource, rlim: rlimit64) -> Result<()> {
    let res = unsafe { libc::setrlimit64(resource as c_int, &rlim as *const _) };
    Errno::result(res).map(drop)
}