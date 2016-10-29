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
}

impl CXXSyscallHandler {
    pub fn new() -> CXXSyscallHandler {
        CXXSyscallHandler {
        }
    }
}

impl SyscallHandler for CXXSyscallHandler {
    fn get_syscall_whitelist(&self) -> &'static [usize] {
        static SYSCALL_WHITELIST: [usize; 0] = [
        ];
        &SYSCALL_WHITELIST
    }

    fn handle_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<OkCode, ErrCode> {
        match syscall.call {
            _ => Ok(OkCode::Passthrough)
        }
    }
}