use constants::NOP_SYSCALL;
use fnv::FnvHashSet;
use libc;
use process::ProcessController;
use ptrace;
use std::iter::Iterator;
use syscall::nr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OkCode {
    Ok,
    Break,
    Passthrough,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrCode {
    InternalError,

    RuntimeError,
    IllegalSyscall(usize),
    IllegalRead,
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
        static SYSCALL_WHITELIST: [usize; 4] = [
            nr::EXECVE,
            nr::EXIT,
            nr::EXIT_GROUP,
            NOP_SYSCALL,
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
        static SYSCALL_WHITELIST: [usize; 19] = [
            nr::CLOSE,
            nr::FSTAT,
            nr::POLL,
            nr::LSEEK,
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
    allowed_files: FnvHashSet<Vec<u8>>,
    allowed_prefixes: FnvHashSet<Vec<u8>>,
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
            b"/etc/ld.so.cache".to_vec(),
            b"/etc/ld.so.preload".to_vec(),
        ].into_iter());
        handler.allow_prefixes(vec![
            b"/usr/lib".to_vec(),
        ].into_iter());
        handler
    }

    pub fn allow_file(&mut self, filename: Vec<u8>) {
        self.allowed_files.insert(filename);
    }

    pub fn allow_files<T>(&mut self, files: T) where T: Iterator<Item=Vec<u8>> {
        for filename in files {
            self.allowed_files.insert(filename);
        }
    }

    pub fn allow_prefix(&mut self, prefix: Vec<u8>) {
        self.allowed_prefixes.insert(prefix);
    }

    pub fn allow_prefixes<T>(&mut self, prefixes: T) where T: Iterator<Item=Vec<u8>> {
        for prefix in prefixes {
            self.allowed_prefixes.insert(prefix);
        }
    }

    fn is_allowed(&self, filename: Vec<u8>) -> bool {
        if self.allowed_files.contains(&filename) {
            return true;
        }

        if self.allowed_prefixes.iter().any(|prefix: &Vec<u8>| {
            prefix.as_slice() == &filename[..prefix.len()]
        }) {
            return true;
        }

        return false;
    }

    fn handle_open_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename = process.get_reader().read_string(syscall.args[0], libc::PATH_MAX as usize).expect("Could not read filename from memory!");
        println!("open called for {}", String::from_utf8_lossy(filename.as_slice()));

        let readonly_flag = syscall.args[1] & 3 == libc::O_RDONLY as usize;
        if !self.is_allowed(filename) || !readonly_flag {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }

    fn handle_stat_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename = process.get_reader().read_string(syscall.args[0], libc::PATH_MAX as usize).expect("Could not read filename from memory!");
        println!("stat called for {}", String::from_utf8_lossy(filename.as_slice()));

        if !self.is_allowed(filename) {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }

    fn handle_lstat_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename = process.get_reader().read_string(syscall.args[0], libc::PATH_MAX as usize).expect("Could not read filename from memory!");
        println!("lstat called for {}", String::from_utf8_lossy(filename.as_slice()));

        if !self.is_allowed(filename) {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }

    fn handle_access_entry(&self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        let filename = process.get_reader().read_string(syscall.args[0], libc::PATH_MAX as usize).expect("Could not read filename from memory!");
        println!("access called for {}", String::from_utf8_lossy(filename.as_slice()));

        if !self.is_allowed(filename) {
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
        let filename = process.get_reader().read_string(syscall.args[0], libc::PATH_MAX as usize).expect("Could not read filename from memory!");
        println!("readlink called for {}", String::from_utf8_lossy(filename.as_slice()));

        if !self.is_allowed(filename) {
            Err(ErrCode::IllegalOpen)
        } else {
            Ok(OkCode::Ok)
        }
    }
}

impl SyscallHandler for FilesystemHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 6] = [
            nr::OPEN,
            nr::STAT,
            nr::LSTAT,
            nr::ACCESS,
            nr::GETCWD,
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
        static SYSCALL_WHITELIST: [usize; 3] = [
            nr::RT_SIGACTION,
            nr::RT_SIGPROCMASK,
            nr::KILL,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::RT_SIGACTION => nop_syscall(syscall),
            nr::RT_SIGPROCMASK => nop_syscall(syscall),
            nr::KILL => nop_syscall(syscall),
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
        static SYSCALL_WHITELIST: [usize; 1] = [
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
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::GETUID,
            nr::GETEUID,
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

pub struct MiscHandler;

impl MiscHandler {
    pub fn new() -> MiscHandler {
        MiscHandler {}
    }
}

impl SyscallHandler for MiscHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::SYSINFO,
            nr::UNAME,
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

fn set_return_val(syscall: &mut ptrace::Syscall, val: isize) -> Result<OkCode, ErrCode> {
    syscall.return_val = val;
    syscall.write();
    Ok(OkCode::Ok)
}