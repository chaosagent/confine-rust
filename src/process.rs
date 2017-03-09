use libc;
use ptrace;

pub struct Process {
    pub pid: libc::pid_t,
    pub in_syscall: bool,
}

impl Process {
    pub fn new(pid: libc::pid_t) -> Process {
        Process {
            pid: pid,
            in_syscall: false,
        }
    }

    pub fn get_controller(&self) -> ProcessController {
        ProcessController {
            pid: self.pid,
        }
    }
}

#[derive(Clone)]
pub struct ProcessController {
    pub pid: libc::pid_t,
}

impl ProcessController {
    pub fn new(pid: libc::pid_t) -> ProcessController {
        ProcessController {
            pid: pid,
        }
    }

    pub fn get_reader(&self) -> ptrace::Reader {
        return ptrace::Reader {
            pid: self.pid,
        }
    }

    pub fn get_writer(&self) -> ptrace::Writer {
        return ptrace::Writer {
            pid: self.pid,
        }
    }
}