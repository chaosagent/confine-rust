use ptrace;
use syscall::nr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OkCode {
    Ok,
    Break,
    Passthrough,
}

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
        static SYSCALL_WHITELIST: [usize; 1] = [
            nr::EXECVE,
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
