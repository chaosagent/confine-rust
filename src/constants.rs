use std::os::unix::io::RawFd;


pub const NOP_SYSCALL: usize = 1024;  // Random invalid syscall number to cancel syscall

pub const STDIN: RawFd = 0;
pub const STDOUT: RawFd = 1;
pub const STDERR: RawFd = 2;