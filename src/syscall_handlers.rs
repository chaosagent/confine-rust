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
    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode>;
}

pub struct DefaultHandler {
    // This should be moved out of DefaultHandler if/when non-execve-based executors are supported.
    execve_entry_handler: Box<FnMut(&ptrace::Syscall) -> Result<OkCode, ErrCode>>,
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
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::EXECVE,
            nr::EXIT_GROUP,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::EXECVE => (self.execve_entry_handler)(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }
}

pub fn get_default_execve_entry_handler() -> Box<FnMut(&ptrace::Syscall) -> Result<OkCode, ErrCode>> {
    let mut seen_execve = false;
    box move |syscall: &ptrace::Syscall| {
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
    fn handle_write(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
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

    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::WRITE => self.handle_write(syscall),
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
        static SYSCALL_WHITELIST: [usize; 14] = [
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

            nr::DUP3,
            nr::PIPE2,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
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
        static SYSCALL_WHITELIST: [usize; 7] = [
            nr::MMAP,
            nr::MPROTECT,
            nr::MUNMAP,
            nr::BRK,
            nr::MREMAP,
            nr::MSYNC,
            nr::ARCH_PRCTL,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
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
    fn handle_open(&self, _: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }

    fn handle_access(&self, _: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        Ok(OkCode::Ok)
    }
}

impl SyscallHandler for FilesystemHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 2] = [
            nr::OPEN,
            nr::ACCESS,
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::OPEN => self.handle_open(syscall),
            nr::ACCESS => self.handle_access(syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }

}
