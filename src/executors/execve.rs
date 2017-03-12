use ptrace;
use nix::unistd;
use std::ffi::CString;
use std::string::String;
use std::vec::Vec;
use syscall::nr;

use executors::Executor;

pub struct ExecveExecutor {
    args: Vec<CString>,
}

impl ExecveExecutor {
    pub fn new(args: &[&str]) -> ExecveExecutor {
        ExecveExecutor {
            args: args.iter().map(|s| CString::new(*s).unwrap()).collect(),
        }
    }
}

impl Executor for ExecveExecutor {
    fn execute(&self) -> Result<(), ()> {
        match unistd::execve(&self.args[0], &self.args, &[]) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}
