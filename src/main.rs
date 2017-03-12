#![feature(box_syntax)]
#![feature(conservative_impl_trait)]
#![feature(custom_derive)]

extern crate clap;
extern crate fnv;
extern crate libc;
#[macro_use] extern crate log;
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

use clap::{Arg, App, SubCommand};
use executors::Executor;
use executors::execve::ExecveExecutor;
use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata};
use std::env;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::time::Duration;


struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Warn
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SandboxConfig {
    realtime_limit: Option<u64>, // Milliseconds
    cputime_limit: Option<u64>, // Seconds
    memory_limit: Option<u64>, // KB

    allowed_files: Option<Vec<String>>,
    allowed_prefixes: Option<Vec<String>>,

    stdin_file: Option<String>,
    stdout_file: Option<String>,
    stderr_file: Option<String>,

    json_report_file: Option<String>,
}

impl SandboxConfig {
    pub fn new() -> SandboxConfig {
        SandboxConfig {
            cputime_limit: None,
            realtime_limit: None,
            memory_limit: None,

            allowed_files: None,
            allowed_prefixes: None,

            stdin_file: None,
            stdout_file: None,
            stderr_file: None,

            json_report_file: None,
        }
    }

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

        if let Some(limit) = self.realtime_limit {
            sandbox.set_realtime_limit(Duration::from_millis(limit));
        }
        if let Some(limit) = self.cputime_limit {
            sandbox.add_rlimit(rlimits::RLimit64::new_offsetted(rlimits::Resource::RLIMIT_CPU, limit));
        }
        if let Some(limit) = self.memory_limit {
            sandbox.add_rlimit(rlimits::RLimit64::new(rlimits::Resource::RLIMIT_AS, limit * 1000, limit * 1000));
        }

        if let Some(ref stdin_file) = self.stdin_file {
            sandbox.stdin_redirect(File::open(stdin_file).expect("Cannot open stdin file!"));
        }
        if let Some(ref stdout_file) = self.stdout_file {
            sandbox.stdout_redirect(File::create(stdout_file).expect("Cannot create stdout file!"));
        }
        if let Some(ref stderr_file) = self.stderr_file {
            sandbox.stderr_redirect(File::create(stderr_file).expect("Cannot create stderr file!"));
        }

        if let Some(ref json_report_file) = self.json_report_file {
            sandbox.set_report_writer(File::create(json_report_file).expect("Cannot create JSON report file!"));
        }
    }
}

fn main() {
    log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Warn);
        Box::new(Logger)
    }).expect("Failed to set up logger!");

    let matches = App::new("My Super Program")
        .version("1.0")
        .author("Kevin K. <kbknapp@gmail.com>")
        .about("Does awesome things")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file")
            .takes_value(true))
        .arg(Arg::with_name("command")
            .required(true)
            .multiple(true)
            .takes_value(true))
        .get_matches();

    let sandbox_config: SandboxConfig = match matches.value_of("config") {
        Some(config_file_path) => {
            match File::open(config_file_path) {
                Ok(config_file) => serde_json::from_reader(config_file).expect("Failed to deserialize config!"),
                _ => panic!("Could not open sandbox config file!")
            }
        },
        None => SandboxConfig::new()
    };

    let args: Vec<&str> = matches.values_of("command").unwrap().collect();

    /*let executor = ExecveExecutor::new(&[
        String::from("/usr/bin/java"),
        String::from("-XX:-UsePerfData"),
        String::from("-XX:+DisableAttachMechanism"),
        String::from("-Xmx256m"),
        String::from("-Xrs"),
        String::from("-cp"),
        String::from("/tmp"),
        String::from("lol")
    ]);*/

    let executor = ExecveExecutor::new(args.as_slice());
    let mut sandbox = sandbox_config.get_sandbox(executor);
    info!("{:?}", sandbox.start());
}