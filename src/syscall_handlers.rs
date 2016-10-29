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