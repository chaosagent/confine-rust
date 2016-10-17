#![feature(custom_derive)]

#[macro_use] extern crate bitflags;
#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate nix;
extern crate ptrace;
#[macro_use] extern crate syscall;

use nix::unistd;
use nix::sys::wait;
use std::ffi::CString;
use std::mem;

fn main() {
    let pid : libc::pid_t = unsafe { libc::fork() };
    if pid == -1 {
        panic!("Failed to fork!")
    } else if pid == 0 {
        // Sandboxed child
        sandbox();
    } else {
        println!("{}", pid);
        sandbox_monitor(pid);
    }
}

fn sandbox_monitor(pid: libc::pid_t) {
    loop {
        let status = wait::waitpid(pid, None).expect("Failed to wait");
        println!("{:?}", status);
        match status {
            wait::WaitStatus::Exited(_, code) => {
                println!("Exited with code {}", code);
                break;
            },
            wait::WaitStatus::Stopped(_, sig) => {
                println!("Stopped with sig {}", sig as i32);
                match sig as i32 {
                    5 => {
                        let syscall = ptrace::Syscall::from_pid(pid).expect("Failed to get syscall");
                        println!("{:?}", syscall);
                    },
                    _ => ()
                }
            },
            _ => ()
        }
        ptrace::cont_syscall(pid, None);
    }
    let mut usage: libc::rusage = unsafe { mem::uninitialized() };
    unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage); }
    println!("User Time: {}.{:06}s", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
    println!("System Time: {}.{:06}s", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
}

fn sandbox() {
    ptrace::traceme();
    unistd::execve(&CString::new("/tmp/test").unwrap(), &[CString::new("/tmp/test").unwrap()], &[]);
}