use ptrace;

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