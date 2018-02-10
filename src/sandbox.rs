use constants::*;
use executors;
use fnv::FnvHashMap;
use libc;
use log::LogLevel;
use nix::errno;
use nix::sys::signal;
use nix::sys::wait;
use nix::unistd;
use process::{Process, ProcessController};
use ptrace;
use rlimits;
use serde_json;
use std::collections::HashMap;
use std::io::{stderr, Write};
use std::mem;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::thread;
use std::time::{Duration, Instant};
use syscall::nr;
use syscall_handlers::ErrCode;
use syscall_handlers::OkCode;
use syscall_handlers::SyscallHandler;

pub struct Sandbox {
    executor: Box<executors::Executor>,
    syscall_handlers: Vec<Box<SyscallHandler>>,
    child_pid: libc::pid_t,

    // TODO: Handle PTRACE_EVENTs interrupting syscalls
    children: FnvHashMap<libc::pid_t, Process>,
    start_instant: Option<Instant>,

    rlimits: Vec<rlimits::RLimit64>,
    realtime_limit: Option<Duration>,

    stdin_fd: Option<RawFd>,
    stdout_fd: Option<RawFd>,
    stderr_fd: Option<RawFd>,

    execution_report: Option<ExecutionReport>,
    report_writer: Option<Box<Write>>,
}

impl Sandbox {
    pub fn new(executor: Box<executors::Executor>) -> Sandbox {
        Sandbox {
            executor: executor,
            syscall_handlers: Vec::new(),
            child_pid: -1,

            children: FnvHashMap::default(),
            start_instant: None,

            rlimits: Vec::new(),
            realtime_limit: None,

            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,

            execution_report: None,
            report_writer: None,
        }
    }

    pub fn add_syscall_handler<T>(&mut self, syscall_handler: T) where T : SyscallHandler + 'static {
        self.syscall_handlers.push(box syscall_handler);
    }

    pub fn add_rlimit(&mut self, rlimit: rlimits::RLimit64) {
        self.rlimits.push(rlimit);
    }

    pub fn set_realtime_limit(&mut self, time: Duration) {
        self.realtime_limit = Some(time);
    }

    pub fn stdin_redirect<T>(&mut self, fd: T) where T: IntoRawFd {
        self.stdin_fd = Some(fd.into_raw_fd());
    }

    pub fn stdout_redirect<T>(&mut self, fd: T) where T: IntoRawFd {
        self.stdout_fd = Some(fd.into_raw_fd());
    }

    pub fn stderr_redirect<T>(&mut self, fd: T) where T: IntoRawFd {
        self.stderr_fd = Some(fd.into_raw_fd());
    }

    pub fn set_report_writer<T>(&mut self, writer: T) where T: Write + 'static {
        self.report_writer = Some(box writer);
    }

    pub fn start(&mut self) -> Result<(), ErrCode> {
        match unistd::fork() {
            Ok(fork_result) => match fork_result {
                unistd::ForkResult::Parent { child } => {
                    info!("pid: {}", child);
                    self.child_pid = child;
                    self.children.insert(child, Process::new(child));
                    let result = self.monitor();
                    self.write_report();
                    result
                },
                unistd::ForkResult::Child => {
                    let result = self.start_program();
                    if result.is_ok() {
                        panic!("Program successfully started; but process did not end");
                    }
                    Err(ErrCode::InternalError)
                }
            },
            Err(_) => Err(ErrCode::InternalError)  // Failed to fork
        }
    }

    // TODO: Don't panic in the monitor; process errors instead.
    // TODO: Handle non-PTRACE_EVENT sources of SIGTRAPs, distinguishing with PTRACE_O_TRACESYSGOOD.
    fn monitor(&mut self) -> Result<(), ErrCode> {
        // Wait for initial SIGSTOP after PTRACE_TRACEME and set options.
        {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            if let wait::WaitStatus::Stopped(_, sig) = status {
                if let signal::Signal::SIGSTOP = sig {
                    info!("Got initial SIGSTOP, commencing with execution.");
                    let mut ptrace_options = 0;
                    ptrace_options |= ptrace::PTRACE_O_EXITKILL;
                    ptrace_options |= ptrace::PTRACE_O_TRACECLONE;
                    ptrace::setoptions(self.child_pid, ptrace_options).expect("Failed to set ptrace options!");
                    self.start_instant = Some(Instant::now());
                    ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");
                } else {
                    self.kill_program().expect("Failed to kill child!");
                    return Err(ErrCode::InternalError);
                }
            } else {
                self.kill_program().expect("Failed to kill child!");
                return Err(ErrCode::InternalError);
            }
        }

        // Ignore RT_SIGPROCMASK from signal::raise
        /*loop {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            info!("{:?}", status);
            if let wait::WaitStatus::Stopped(pid, sig) = status {
                assert_eq!(pid, self.child_pid);
                if let signal::Signal::SIGTRAP = sig {
                    let syscall = ptrace::Syscall::from_pid(self.child_pid).expect("Failed to get syscall");
                    if syscall.call != nr::RT_SIGPROCMASK && syscall.call != NOP_SYSCALL {
                        // Assume raise won't call RT_SIGPROCMASK
                        // TODO: make more robust
                        break;
                    }

                    let process = self.children.get_mut(&pid).unwrap();
                    if !process.in_syscall {
                        process.in_syscall = true;
                        ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");
                    } else {
                        process.in_syscall = false;
                        ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");
                        break;
                    }
                } else {
                    self.kill_program().expect("Failed to kill child!");
                    return Err(ErrCode::InternalError);
                }
            } else {
                self.kill_program().expect("Failed to kill child!");
                return Err(ErrCode::InternalError);
            }
        }*/

        if let Some(duration) = self.realtime_limit {
            let cloned_duration = duration.clone();
            let child_pid = self.child_pid;
            thread::spawn(move || {
                thread::sleep(cloned_duration);
                signal::kill(child_pid, signal::Signal::SIGXCPU);
            });
        }

        loop {
            let status = wait::waitpid(-1, None).expect("Failed to wait");
            info!("{:?}", status);

            match status {
                wait::WaitStatus::Exited(_, code) => {
                    info!("Exited with code {}", code);
                    let result = if code == 0 {
                        Ok(())
                    } else {
                        Err(ErrCode::RuntimeError)
                    };
                    self.build_execution_report(result);
                    return result;
                },
                wait::WaitStatus::Signaled(_, signal, _) => {
                    info!("Received signal {}", signal as i32);

                    let result = Err(ErrCode::RuntimeError);
                    self.build_execution_report(result);
                    self.kill_program().expect("Failed to kill child!");  // TODO: Process inbound signals
                    return result;
                }
                wait::WaitStatus::Stopped(pid, sig) => {
                    match sig {
                        signal::Signal::SIGTRAP => { // syscall
                            if let Err(code) = self.process_syscall(pid) {
                                let result = Err(code);
                                self.build_execution_report(result);
                                self.kill_program().expect("Failed to kill child!");
                                return result;
                            }
                        },
                        signal::Signal::SIGSEGV => {
                            let result = Err(ErrCode::RuntimeError);
                            self.build_execution_report(result);
                            self.kill_program().expect("Failed to kill child!");
                            return result;
                        }
                        signal::Signal::SIGXCPU => {
                            let result = Err(ErrCode::TimeLimitExceeded);
                            self.build_execution_report(result);
                            self.kill_program().expect("Failed to kill child!");
                            return result;
                        }
                        _ => ()
                    }
                    ptrace::cont_syscall(pid, None).expect("Failed to continue!");
                },
                wait::WaitStatus::PtraceEvent(pid, _, event) => {
                    match event {
                        ptrace::PTRACE_EVENT_CLONE => {
                            let new_pid = ptrace::geteventmsg(pid).unwrap() as libc::pid_t;
                            if !self.children.contains_key(&pid) {
                                self.children.insert(pid, Process::new(pid));
                            }
                            ptrace::cont_syscall(pid, None).expect("Failed to continue!");
                        },
                        _ => unreachable!()
                    }
                }
                _ => unreachable!()
            }
        }
        let result = Err(ErrCode::InternalError);
        self.build_execution_report(result);
        drop(self.kill_program());
        result
    }

    fn kill_program(&self) -> Result<(), ()> {
        match signal::kill(self.child_pid, signal::SIGKILL) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    fn process_syscall(&mut self, pid: libc::pid_t) -> Result<(), ErrCode> {
        let mut syscall = ptrace::Syscall::from_pid(pid).expect("Failed to get syscall");
        if !self.children.contains_key(&pid) {
            self.children.insert(pid, Process::new(pid));
        }

        let (in_syscall, controller) = {
            let process = self.children.get(&pid).unwrap();
            (process.in_syscall, process.get_controller())
        };

        if !in_syscall {
            info!("Syscall entry for pid {}: {:?}", pid, syscall);

            // Syscall entries always have a return_val of -ENOSYS
            if syscall.return_val == -libc::ENOSYS as isize {
                match self.process_syscall_entry(&controller, &mut syscall) {
                    Err(code) => {
                        return Err(code);
                    },
                    _ => ()
                }
                self.children.get_mut(&pid).unwrap().in_syscall = true;
            } else {
                // This can happen if a syscall exit notifies both a parent and a child in execve
                if syscall.call != nr::EXECVE {
                    error!("Syscall entry without return_val of -ENOSYS detected, and is not execve!");
                    return Err(ErrCode::InternalError);
                }
                // If it is execve, we're OK
            }
        } else {
            info!("Syscall exit for pid {}: {:?}", pid, syscall);

            match self.process_syscall_exit(&controller, &mut syscall) {
                Err(code) => {
                    return Err(code);
                },
                _ => ()
            }

            self.children.get_mut(&pid).unwrap().in_syscall = false;
        }
        Ok(())
    }

    fn process_syscall_entry(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<(), ErrCode> {
        if !self.syscall_handlers.iter()
            .map(|handler| handler.get_syscall_whitelist())
            .map(|whitelist| whitelist.contains(&syscall.call))
            .any(|x| x) {
            return Err(ErrCode::IllegalSyscall(syscall.call))
        }
        
        let entry_handler_result_fold = |prev: Result<OkCode, ErrCode>, mut handler: &mut Box<SyscallHandler>| {
            if prev.is_err() || prev.unwrap() == OkCode::Break {
                prev
            } else {
                match handler.handle_syscall_entry(process, syscall) {
                    Ok(OkCode::Passthrough) => prev,
                    x => x
                }
            }
        };

        match self.syscall_handlers.iter_mut().fold(Ok(OkCode::Passthrough) as Result<OkCode, ErrCode>, entry_handler_result_fold) {
            Ok(_) => Ok(()),
            Err(code) => Err(code)
        }
    }

    fn process_syscall_exit(&mut self, process: &ProcessController, syscall: &mut ptrace::Syscall) -> Result<(), ErrCode> {
        if !self.syscall_handlers.iter()
            .map(|handler| handler.get_syscall_whitelist())
            .map(|whitelist| whitelist.contains(&syscall.call))
            .any(|x| x) {
            // warn!("ILLEGAL {}", syscall.call);
            // return Ok(());
            return Err(ErrCode::IllegalSyscall(syscall.call))
        }

        let exit_handler_result_fold = |prev: Result<OkCode, ErrCode>, mut handler: &mut Box<SyscallHandler>| {
            if prev.is_err() || prev.unwrap() == OkCode::Break {
                prev
            } else {
                match handler.handle_syscall_exit(process, syscall) {
                    Ok(OkCode::Passthrough) => prev,
                    x => x
                }
            }
        };

        match self.syscall_handlers.iter_mut().fold(Ok(OkCode::Passthrough) as Result<OkCode, ErrCode>, exit_handler_result_fold) {
            Ok(_) => Ok(()),
            Err(code) => {
                /*if let ErrCode::IllegalSyscall(call) = code {
                    warn!("ILLEGAL {}", call);
                }
                Ok(()) */
                Err(code)
            }
        }
    }

    fn duration_since_start(&self) -> Duration {
        Instant::now().duration_since(self.start_instant.unwrap_or(Instant::now()))
    }

    fn build_execution_report(&mut self, result: Result<(), ErrCode>) {
        let usage = get_children_rusage().expect("Could not get usage statistics!");
        self.execution_report = Some(ExecutionReport::build(result, usage, self.duration_since_start()));
    }

    fn write_report(&mut self) {
        let report = match self.execution_report {
            Some(ref execution_report) => {
                if log_enabled!(LogLevel::Info) {
                    execution_report.write(&mut stderr());
                }
                serde_json::to_string(execution_report)
            },
            None => {
                let execution_report = ExecutionReport::error();
                if log_enabled!(LogLevel::Info) {
                    execution_report.write(&mut stderr());
                }
                serde_json::to_string(&execution_report)
            }
        }.unwrap();
        if let Some(ref mut report_writer) = self.report_writer {
            report_writer.write_all(report.into_bytes().as_slice());
        }
    }
}

impl Sandbox {
    fn start_program(&self) -> Result<(), ()> {
        self.set_rlimits().expect("Failed to set rlimits!");
        self.redirect_stdio().expect("Failed to redirect stdio!");

        ptrace::traceme().expect("Failed to traceme!");
        signal::raise(signal::SIGSTOP).expect("Failed to raise SIGSTOP!");
        self.executor.execute()
    }

    fn set_rlimits(&self) -> Result<(), ()> {
        self.rlimits.iter()
            .map(|rlimit| rlimit.set())
            .fold(Ok(()), |prev, result| prev.and(result))
            .map_err(drop)
    }

    fn redirect_stdio(&self) -> Result<(), ()> {
        if let Some(stdin_fd) = self.stdin_fd {
            unistd::dup2(stdin_fd, STDIN).map_err(drop)?;
        }
        if let Some(stdout_fd) = self.stdout_fd {
            unistd::dup2(stdout_fd, STDOUT).map_err(drop)?;
        }
        if let Some(stderr_fd) = self.stderr_fd {
            unistd::dup2(stderr_fd, STDERR).map_err(drop)?;
        }
        Ok(())
    }
}

// TODO: properly support timevals
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionReport {
    execution_ok: bool,
    execution_error_code: Option<ErrCode>,
    exitcode: i8,

    realtime: f64,
    cputime: f64,
    systemtime: f64,
    memory: u64,
}

impl ExecutionReport {
    pub fn error() -> ExecutionReport {
        ExecutionReport {
            execution_ok: false,
            execution_error_code: Some(ErrCode::InternalError),
            exitcode: -1i8, // TODO: get exitcode

            realtime: 0f64,
            cputime: 0f64,
            systemtime: 0f64,
            memory: 0u64,
        }
    }

    pub fn build(execution_result: Result<(), ErrCode>, usage: libc::rusage, realtime: Duration) -> ExecutionReport {
        ExecutionReport {
            execution_ok: execution_result.is_ok(),
            execution_error_code: execution_result.err(),
            exitcode: 0, // TODO: get exitcode

            realtime: realtime.as_secs() as f64 + (realtime.subsec_nanos() as f64) / 1000000000f64,
            cputime: usage.ru_utime.tv_sec as f64 + (usage.ru_utime.tv_usec as f64) / 1000000f64,
            systemtime: usage.ru_stime.tv_sec as f64 + (usage.ru_stime.tv_usec as f64) / 1000000f64,
            memory: usage.ru_maxrss as u64,
        }
    }

    pub fn write<T>(&self, writer: &mut T) where T: Write {
        writeln!(writer, "Real Time: {:.6}s", self.realtime);
        writeln!(writer, "User Time: {:.6}s", self.cputime);
        writeln!(writer, "System Time: {:.6}s", self.systemtime);
        writeln!(writer, "Memory: {}KB", self.memory / 1000);
    }
}

pub fn get_children_rusage() -> Result<libc::rusage, i32> {
    let mut usage: libc::rusage = unsafe { mem::uninitialized() };
    match unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) } {
        0 => Ok(usage),
        _ => Err(errno::errno()),
    }
}

pub fn get_pid_from_wait_status(wait_status: wait::WaitStatus) -> Option<libc::pid_t> {
    match wait_status {
        wait::WaitStatus::Exited(pid, _) => Some(pid),
        wait::WaitStatus::Signaled(pid, _, _) => Some(pid),
        wait::WaitStatus::Stopped(pid, _) => Some(pid),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        wait::WaitStatus::PtraceEvent(pid, _, _) => Some(pid),
        wait::WaitStatus::Continued(pid) => Some(pid),
        wait::WaitStatus::StillAlive => None,
    }
}
