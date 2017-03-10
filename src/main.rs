#![feature(box_syntax)]
#![feature(conservative_impl_trait)]
#![feature(custom_derive)]

extern crate fnv;
extern crate libc;
extern crate nix;
extern crate ptrace;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
#[macro_use] extern crate syscall;

mod constants;
mod executors;
mod rlimits;
mod process;
mod sandbox;
mod syscall_handlers;

use executors::Executor;
use executors::execve::ExecveExecutor;
use std::fs::File;

#[derive(Serialize, Deserialize)]
struct SandboxConfig {
    cputime_limit: Option<u64>,
    memory_limit: Option<u64>,

    allowed_files: Option<Vec<String>>,
    allowed_prefixes: Option<Vec<String>>,
}

impl SandboxConfig {
    pub fn get_sandbox<T>(&self, executor: T) -> sandbox::Sandbox where T: Executor + 'static {
        let mut sandbox = sandbox::Sandbox::new(box executor);
        self.apply(&mut sandbox);
        sandbox
    }

    pub fn apply(&self, sandbox: &mut sandbox::Sandbox) {
        sandbox.add_syscall_handler(syscall_handlers::RWHandler::new(!0));
        sandbox.add_syscall_handler(syscall_handlers::FDHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::MemoryHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::SignalsHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::ThreadingHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::SchedulingHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::RLimitsHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::ClockHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::UserInfoHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::SocketHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::MiscHandler::new());
        sandbox.add_syscall_handler(syscall_handlers::DefaultHandler::new());

        let mut fs_handler = syscall_handlers::FilesystemHandler::new_with_default_rules();
        if let Some(ref allowed_files) = self.allowed_files {
            fs_handler.allow_files(allowed_files.iter());
        }
        if let Some(ref allowed_prefixes) = self.allowed_prefixes {
            fs_handler.allow_prefixes(allowed_prefixes.iter());
        }
        sandbox.add_syscall_handler(fs_handler);

        if let Some(limit) = self.cputime_limit {
            sandbox.add_rlimit(rlimits::RLimit64::new_offsetted(rlimits::Resource::RLIMIT_CPU, limit));
        }
        if let Some(limit) = self.memory_limit {
            sandbox.add_rlimit(rlimits::RLimit64::new_offsetted(rlimits::Resource::RLIMIT_AS, limit));
        }
    }
}

fn main() {
    let config_file: File = File::open("confine.json").expect("Could not find confine.json!");
    let sandbox_config: SandboxConfig = serde_json::from_reader(config_file).expect("Failed to deserialize config!");

    let executor = ExecveExecutor::new(&[
        String::from("/usr/bin/java"),
        String::from("-XX:-UsePerfData"),
        String::from("-cp"),
        String::from("/tmp"),
        String::from("lol")
    ]);
    let mut sandbox = sandbox_config.get_sandbox(executor);
    println!("{:?}", sandbox.start());
}