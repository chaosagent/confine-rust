#![feature(box_syntax)]
#![feature(conservative_impl_trait)]
#![feature(custom_derive)]

extern crate libc;
extern crate nix;
extern crate ptrace;
#[macro_use] extern crate syscall;

mod executors;
mod rlimits;
mod sandbox;
mod syscall_handlers;

fn main() {
    let executor_factory = executors::get_executor("cxx").expect("Invalid executor!");
    let executor = executor_factory(&[String::from("/bin/cat"), String::from("/tmp/lol")]);
    let syscall_handler_factory = executors::get_syscall_handler("cxx").expect("Invalid executor!");
    let syscall_handler = box syscall_handler_factory();
    let rw_handler = box syscall_handlers::RWHandler::new(!0);
    let fd_handler = box syscall_handlers::FDHandler::new();
    let memory_handler = box syscall_handlers::MemoryHandler::new();
    let fs_handler = box syscall_handlers::FilesystemHandler::new();
    let default_syscall_handler = box syscall_handlers::DefaultHandler::new();
    let handlers: Vec<Box<syscall_handlers::SyscallHandler>> = vec![
        syscall_handler,
        rw_handler,
        fd_handler,
        memory_handler,
        fs_handler,
        default_syscall_handler,
    ];
    let rlimits: Vec<rlimits::RLimit64> = vec![
        rlimits::RLimit64::new_offsetted(rlimits::Resource::RLIMIT_CPU, 1),
    ];
    let mut sandbox = sandbox::Sandbox::new(box executor, handlers, rlimits);
    println!("{:?}", sandbox.start());
}