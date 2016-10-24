use ptrace;
use nix::unistd;
use std::ffi::CString;
use std::string::String;
use std::vec::Vec;
use syscall::nr;

use executors::Executor;
use syscall_handlers::ErrCode;
use syscall_handlers::OkCode;
use syscall_handlers::SyscallHandler;

pub struct CXXExecutor {
    args: Vec<CString>,
}

impl CXXExecutor {
    pub fn new(args: &[String]) -> CXXExecutor {
        CXXExecutor {
            args: args.iter().map(|s| CString::new(&s as &str).unwrap()).collect(),
        }
    }
}

impl Executor for CXXExecutor {
    fn execute(&self) -> Result<(), ()> {
        match unistd::execve(&self.args[0], &self.args, &[]) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

pub struct CXXSyscallHandler {
    seen_execve: bool,
}

impl CXXSyscallHandler {
    pub fn new() -> CXXSyscallHandler {
        CXXSyscallHandler {
            seen_execve: false,
        }
    }

    fn handle_execve_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        if self.seen_execve {
            Err(ErrCode::IllegalSyscall(syscall.call))
        } else {
            self.seen_execve = true;
            Ok(OkCode::Ok)
        }
    }
}

impl SyscallHandler for CXXSyscallHandler {
    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            nr::EXECVE => self.handle_execve_entry(&syscall),
            _ => Ok(OkCode::Passthrough)
        }
    }
}