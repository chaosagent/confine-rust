use constants::NOP_SYSCALL;
use fnv::FnvHashSet;
use libc;
use process::ProcessController;
use ptrace;
use std::cmp::min;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::iter::Iterator;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use syscall::nr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OkCode {
    Ok,
    Break,
    Passthrough,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", content = "value")]
pub enum ErrCode {
    InternalError,

    RuntimeError,
    IllegalSyscall(usize),
    IllegalWrite,
    IllegalOpen,

    TimeLimitExceeded,
    MemoryLimitExceeded,
}

// TODO: implement syscall exit handling.
// TODO: support syscall modification
pub trait SyscallHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize];
    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode>;
    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode>;
}

pub struct DefaultHandler {
    // This should be moved out of DefaultHandler if/when non-execve-based executors are supported.
    execve_entry_handler: Box<FnMut(&mut ptrace::Syscall) -> Result<OkCode, ErrCode>>,
}

impl DefaultHandler {
    pub fn new() -> DefaultHandler {
        DefaultHandler {
            execve_entry_handler: get_default_execve_entry_handler(),
        }
    }
}

impl SyscallHandler for DefaultHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 5] = [
            nr::EXECVE,
            nr::EXIT,
            nr::EXIT_GROUP,
            NOP_SYSCALL,
            NOP_SYSCALL + 1,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::EXECVE => (self.execve_entry_handler)(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            NOP_SYSCALL => set_return_val(syscall, 0), // TODO: Track individual nopped syscalls
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub fn get_default_execve_entry_handler() -> Box<FnMut(&mut ptrace::Syscall) -> Result<OkCode, ErrCode>> {
    let mut seen_execve = false;
    box move |syscall: &mut ptrace::Syscall| {
        if seen_execve {
            Err(ErrCode::IllegalSyscall(syscall.call))
        } else {
            seen_execve = true;
            Ok(OkCode::Ok)
        }
    }
}

pub struct RWHandler {
    max_total_write: usize,
    written: usize,
}

impl RWHandler {
    pub fn new(max_total_write: usize) -> RWHandler {
        RWHandler {
            max_total_write: max_total_write,
            written: 0,
        }
    }

    // Does NOT update written if an Err is returned.
    fn handle_write(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let new_written = self.written + syscall.args[2];

        // Check for overflow too
        if new_written < self.written || new_written > self.max_total_write {
            Err(ErrCode::IllegalWrite)
        } else {
            self.written = new_written;
            Ok(OkCode::Ok)
        }
    }
}

impl SyscallHandler for RWHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::READ,
            nr::WRITE,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::WRITE => self.handle_write(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct FDHandler;

impl FDHandler {
    pub fn new() -> FDHandler {
        FDHandler {}
    }
}

impl SyscallHandler for FDHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 20] = [
            nr::CLOSE,
            nr::FSTAT,
            nr::POLL,
            nr::LSEEK,
            nr::IOCTL,
            nr::PREAD64,
            nr::PWRITE64,
            nr::READV,
            nr::WRITEV,
            nr::PIPE,
            nr::SELECT,
            nr::DUP,
            nr::DUP2,
            nr::FCNTL,
            nr::FTRUNCATE,
            nr::GETDENTS,
            nr::GETDENTS64,
            nr::FADVISE64,
            nr::DUP3,
            nr::PIPE2,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct MemoryHandler;

impl MemoryHandler {
    pub fn new() -> MemoryHandler {
        MemoryHandler {}
    }
}

impl SyscallHandler for MemoryHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 8] = [
            nr::MMAP,
            nr::MPROTECT,
            nr::MUNMAP,
            nr::BRK,
            nr::MREMAP,
            nr::MSYNC,
            nr::MADVISE,
            nr::ARCH_PRCTL,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct FilesystemHandler {
    allowed_files: FnvHashSet<OsString>,
    allowed_prefixes: FnvHashSet<OsString>,
}

impl FilesystemHandler {
    pub fn new() -> FilesystemHandler {
        FilesystemHandler {
            allowed_files: FnvHashSet::default(),
            allowed_prefixes: FnvHashSet::default(),
        }
    }

    pub fn new_with_default_rules() -> FilesystemHandler {
        let mut handler = FilesystemHandler::new();
        handler.allow_files(vec![
            "/etc/ld.so.cache",
            "/etc/ld.so.preload",
            "/etc/ld.so.nohwcap",
            "/usr",
            "/sys/devices/system/cpu",
        ].into_iter());
        handler.allow_prefixes(vec![
            "/lib/",
            "/usr/",
            "/sys/devices/system/cpu/",
        ].into_iter());
        handler
    }

    pub fn allow_file<T>(&mut self, filename: T) where T: Into<OsString> {
        self.allowed_files.insert(filename.into());
    }

    pub fn allow_files<T, U>(&mut self, files: T) where T: Iterator<Item=U>, U: Into<OsString> {
        for filename in files {
            self.allowed_files.insert(filename.into());
        }
    }

    pub fn allow_prefix<T>(&mut self, prefix: T) where T: Into<OsString> {
        self.allowed_prefixes.insert(prefix.into());
    }

    pub fn allow_prefixes<T, U>(&mut self, prefixes: T) where T: Iterator<Item=U>, U: Into<OsString> {
        for prefix in prefixes {
            self.allowed_prefixes.insert(prefix.into());
        }
    }

    // TODO: account for working directory if working directory of child process is ever changed.
    fn is_allowed(&self, process: &ProcessController, filename: &OsStr) -> bool {
        let canonical_filename: OsString = match fs::canonicalize(&OsStr::from_bytes(filename.as_bytes())) {
            Ok(buf) => buf.into_os_string(),
            _ => return true
        };

        info!("Canonicalized filename: {}", canonical_filename.to_string_lossy());

        if self.allowed_files.contains(&canonical_filename) {
            return true;
        }

        if self.allowed_prefixes.iter().any(|prefix: &OsString| {
            prefix.as_os_str().as_bytes() == &canonical_filename.as_os_str().as_bytes()[0..min(canonical_filename.len(), prefix.len())]
        }) {
            return true;
        }

        // Check if the file is a /proc/self
        if let Some(s) = filename.to_str() {
            if s.starts_with("/proc/self/") && !s.contains("..") {
                return true;
            }
        }

        return false;
    }

    fn handle_open_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename_vec: Vec<u8> = process.get_reader()
            .read_string(syscall.args[0], libc::PATH_MAX as usize)
            .expect("Could not read filename from memory!");
        let filename: OsString = OsString::from_vec(filename_vec);
        info!("open called for {}", filename.to_string_lossy());

        let readonly_flag = syscall.args[1] & 3 == libc::O_RDONLY as usize;
        if !self.is_allowed(process, &filename) || !readonly_flag {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }

    fn handle_stat_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename_vec: Vec<u8> = process.get_reader()
            .read_string(syscall.args[0], libc::PATH_MAX as usize)
            .expect("Could not read filename from memory!");
        let filename: OsString = OsString::from_vec(filename_vec);
        info!("stat called for {}", filename.to_string_lossy());

        if !self.is_allowed(process, &filename) {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }

    fn handle_lstat_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename_vec: Vec<u8> = process.get_reader()
            .read_string(syscall.args[0], libc::PATH_MAX as usize)
            .expect("Could not read filename from memory!");
        let filename: OsString = OsString::from_vec(filename_vec);
        info!("lstat called for {}", filename.to_string_lossy());

        if !self.is_allowed(process, &filename) {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }

    fn handle_access_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename_vec: Vec<u8> = process.get_reader()
            .read_string(syscall.args[0], libc::PATH_MAX as usize)
            .expect("Could not read filename from memory!");
        let filename: OsString = OsString::from_vec(filename_vec);
        info!("access called for {}", filename.to_string_lossy());

        if !self.is_allowed(process, &filename) {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }

    // TODO: Handle getcwd
    fn handle_getcwd_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }

    fn handle_readlink_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename_vec: Vec<u8> = process.get_reader()
            .read_string(syscall.args[0], libc::PATH_MAX as usize)
            .expect("Could not read filename from memory!");
        let filename: OsString = OsString::from_vec(filename_vec);
        info!("readlink called for {}", filename.to_string_lossy());

        if !self.is_allowed(process, &filename) && filename.as_os_str().as_bytes() != b"/proc/self/exe" {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }
}

impl SyscallHandler for FilesystemHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 8] = [
            nr::OPEN,
            nr::STAT,
            nr::LSTAT,
            nr::ACCESS,
            nr::GETCWD,
            nr::FCHDIR,
            nr::UNLINK,
            nr::READLINK,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::OPEN => self.handle_open_entry(process, syscall),
            nr::STAT => self.handle_stat_entry(process, syscall),
            nr::LSTAT => self.handle_lstat_entry(process, syscall),
            nr::ACCESS => self.handle_access_entry(process, syscall),
            nr::GETCWD => self.handle_getcwd_entry(process, syscall),
            nr::FCHDIR => nop_syscall(syscall),
            nr::UNLINK => nop_syscall(syscall),
            nr::READLINK => self.handle_readlink_entry(process, syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct SignalsHandler;

impl SignalsHandler {
    pub fn new() -> SignalsHandler {
        SignalsHandler {}
    }
}

impl SyscallHandler for SignalsHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 4] = [
            nr::RT_SIGACTION,
            nr::RT_SIGPROCMASK,
            nr::KILL,
            nr::SIGALTSTACK,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::RT_SIGACTION => nop_syscall(syscall),
            nr::RT_SIGPROCMASK => nop_syscall(syscall),
            nr::KILL => nop_syscall(syscall),
            nr::SIGALTSTACK => nop_syscall(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct ThreadingHandler;

impl ThreadingHandler {
    pub fn new() -> ThreadingHandler {
        ThreadingHandler {}
    }

    // TODO: handle other kinds of clones
    fn handle_clone_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        if syscall.args[0] & libc::CLONE_THREAD as usize != 0 {
            Ok(OkCode::Ok)
        } else {
            Err(ErrCode::IllegalSyscall(syscall.call))
        }
    }
}

impl SyscallHandler for ThreadingHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 6] = [
            nr::CLONE,
            nr::GETTID,
            nr::FUTEX,
            nr::SET_TID_ADDRESS,
            nr::SET_ROBUST_LIST,
            nr::GET_ROBUST_LIST,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::CLONE => self.handle_clone_entry(process, syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct SchedulingHandler;

impl SchedulingHandler {
    pub fn new() -> SchedulingHandler {
        SchedulingHandler {}
    }
}

impl SyscallHandler for SchedulingHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::SCHED_GETAFFINITY,
            nr::SCHED_YIELD,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct RLimitsHandler;

impl RLimitsHandler {
    pub fn new() -> RLimitsHandler {
        RLimitsHandler {}
    }
}

impl SyscallHandler for RLimitsHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::GETRLIMIT,
            nr::SETRLIMIT,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::SETRLIMIT => nop_syscall(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct ClockHandler;

impl ClockHandler {
    pub fn new() -> ClockHandler {
        ClockHandler {}
    }
}

impl SyscallHandler for ClockHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::CLOCK_GETTIME,
            nr::CLOCK_GETRES,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct UserInfoHandler;

impl UserInfoHandler {
    pub fn new() -> UserInfoHandler {
        UserInfoHandler {}
    }
}

impl SyscallHandler for UserInfoHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 4] = [
            nr::GETUID,
            nr::GETEUID,
            nr::GETGID,
            nr::GETEGID,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    // TODO: maybe clear output on return?
    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct SocketHandler;

impl SocketHandler {
    pub fn new() -> SocketHandler {
        SocketHandler {}
    }
}

// TODO: murder sockets
impl SyscallHandler for SocketHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::SOCKET,
            nr::CONNECT,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::SOCKET => nop_syscall_no_return(syscall),
            nr::CONNECT => nop_syscall_no_return(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct MiscHandler;

impl MiscHandler {
    pub fn new() -> MiscHandler {
        MiscHandler {}
    }
}

impl SyscallHandler for MiscHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 3] = [
            nr::SYSINFO,
            nr::UNAME,
            nr::GETRANDOM,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::SYSINFO => nop_syscall(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

fn nop_syscall(syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
    syscall.call = NOP_SYSCALL;
    syscall.write();
    Ok(OkCode::Ok)
}

fn nop_syscall_no_return(syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
    syscall.call = NOP_SYSCALL + 1;
    syscall.write();
    Ok(OkCode::Ok)
}

fn set_return_val(syscall: &mut ptrace::Syscall, val: isize) -> Result<OkCode, ErrCode> {
    syscall.return_val = val;
    syscall.write();
    Ok(OkCode::Ok)
}
