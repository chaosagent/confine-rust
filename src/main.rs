#![feature(box_syntax)]
#![feature(conservative_impl_trait)]
#![feature(custom_derive)]

extern crate libc;
extern crate nix;
extern crate ptrace;
#[macro_use] extern crate syscall;

mod executors;
mod sandbox;
mod syscall_handlers;

use std::ffi::CString;

fn main() {
    let executor_factory = executors::get_executor("cxx").expect("Invalid executor!");
    let executor = executor_factory(&[String::from("/bin/cat"), String::from("/tmp/lol")]);
    let syscall_handler_factory = executors::get_syscall_handler("cxx").expect("Invalid executor!");
    let mut syscall_handler = syscall_handler_factory();
    let mut handlers: Vec<Box<syscall_handlers::SyscallHandler>> = vec![box syscall_handler];
    let mut sandbox = sandbox::Sandbox::new(box executor, handlers);
    println!("{:?}", sandbox.start());
}