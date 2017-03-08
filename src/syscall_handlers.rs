use constants::NOP_SYSCALL;
use libc;
use ptrace;
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
    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode>;
    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode>;
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::EXECVE => (self.execve_entry_handler)(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::WRITE => self.handle_write(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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
        static SYSCALL_WHITELIST: [usize; 18] = [
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
            nr::DUP3,
            nr::PIPE2,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub struct FilesystemHandler;

impl FilesystemHandler {
    pub fn new() -> FilesystemHandler {
        FilesystemHandler {}
    }

    // TODO: implement file access filtering.
    fn handle_open_entry(&self, _: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }

    fn handle_stat_entry(&self, _: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }

    fn handle_lstat_entry(&self, _: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }

    fn handle_access_entry(&self, _: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }

    fn handle_getcwd_entry(&self, _: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }

    fn handle_readlink_entry(&self, _: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::OPEN => self.handle_open_entry(syscall),
            nr::STAT => self.handle_stat_entry(syscall),
            nr::LSTAT => self.handle_lstat_entry(syscall),
            nr::ACCESS => self.handle_access_entry(syscall),
            nr::GETCWD => self.handle_getcwd_entry(syscall),
            nr::READLINK => self.handle_readlink_entry(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::RT_SIGACTION => nop_syscall(syscall),
            nr::RT_SIGPROCMASK => nop_syscall(syscall),
            nr::KILL => nop_syscall(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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
    fn handle_clone_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::CLONE => self.handle_clone_entry(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::SETRLIMIT => nop_syscall(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }

    // TODO: maybe clear output on return?
    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::SYSINFO => nop_syscall(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::SYSINFO => nop_syscall(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

    fn handle_syscall_exit(&mut self, syscall: &mut ptrace::Syscall) -> Result<OkCode, ErrCode> {
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