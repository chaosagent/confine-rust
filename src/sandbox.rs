use constants::*;
use executors;
use fnv::FnvHashMap;
use libc;
use nix::errno;
use nix::sys::signal;
use nix::sys::wait;
use nix::unistd;
use process::{Process, ProcessController};
use ptrace;
use rlimits;
use std::collections::HashMap;
use std::mem;
use std::os::unix::io::{IntoRawFd, RawFd};
use syscall::nr;
use syscall_handlers::ErrCode;
use syscall_handlers::OkCode;
use syscall_handlers::SyscallHandler;

pub struct Sandbox {
    executor: Box<executors::Executor>,
    syscall_handlers: Vec<Box<SyscallHandler>>,
    child_pid: libc::pid_t,

    rlimits: Vec<rlimits::RLimit64>,

    // TODO: Handle PTRACE_EVENTs interrupting syscalls
    children: FnvHashMap<libc::pid_t, Process>,

    stdin_fd: Option<RawFd>,
    stdout_fd: Option<RawFd>,
    stderr_fd: Option<RawFd>,
}

impl Sandbox {
    pub fn new(executor: Box<executors::Executor>) -> Sandbox {
        Sandbox {
            executor: executor,
            syscall_handlers: Vec::new(),
            child_pid: -1,

            rlimits: Vec::new(),

            children: FnvHashMap::default(),

            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,

        }
    }

    pub fn add_syscall_handler<T>(&mut self, syscall_handler: T) where T : SyscallHandler + 'static {
        self.syscall_handlers.push(box syscall_handler);
    }

    pub fn add_rlimit(&mut self, rlimit: rlimits::RLimit64) {
        self.rlimits.push(rlimit);
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

    pub fn start(&mut self) -> Result<(), ErrCode> {
        match unistd::fork() {
            Ok(fork_result) => match fork_result {
                unistd::ForkResult::Parent { child } => {
                    println!("pid: {}", child);
                    self.child_pid = child;
                    self.children.insert(child, Process::new(child));
                    let result = self.monitor();
                    self.print_usage_statistics();
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
        let mut result = Ok(());

        // Wait for initial SIGSTOP after PTRACE_TRACEME and set options.
        {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            if let wait::WaitStatus::Stopped(_, sig) = status {
                if let signal::Signal::SIGSTOP = sig {
                    println!("Got initial SIGSTOP, commencing with execution.");
                    let mut ptrace_options = 0;
                    ptrace_options |= ptrace::PTRACE_O_EXITKILL;
                    ptrace_options |= ptrace::PTRACE_O_TRACECLONE;
                    ptrace::setoptions(self.child_pid, ptrace_options).expect("Failed to set ptrace options!");
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
        loop {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            println!("{:?}", status);
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
        }

        loop {
            let status = wait::waitpid(-1, None).expect("Failed to wait");
            println!("{:?}", status);

            match status {
                wait::WaitStatus::Exited(_, code) => {
                    println!("Exited with code {}", code);
                    break;
                },
                wait::WaitStatus::Signaled(_, signal, _) => {
                    println!("Received signal {}", signal as i32);
                    self.kill_program().expect("Failed to kill child!");  // TODO: Process inbound signals
                    break;
                }
                wait::WaitStatus::Stopped(pid, sig) => {
                    match sig {
                        signal::Signal::SIGTRAP => { // syscall
                            if let Err(code) = self.process_syscall(pid) {
                                self.kill_program().expect("Failed to kill child!");
                                result = Err(code);
                                break;
                            }
                        },
                        signal::Signal::SIGSEGV => {
                            result = Err(ErrCode::RuntimeError);
                            self.kill_program().expect("Failed to kill child!");
                            break;
                        }
                        signal::Signal::SIGXCPU => {
                            result = Err(ErrCode::TimeLimitExceeded);
                            self.kill_program().expect("Failed to kill child!");
                            break;
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
        result
    }

    fn kill_program(&self) -> Result<(), ()> {
        match signal::kill(self.child_pid, signal::SIGKILL) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    fn process_syscall(&mut self, pid: libc::pid_t) -> Result <(), ErrCode> {
        let mut syscall = ptrace::Syscall::from_pid(pid).expect("Failed to get syscall");
        if !self.children.contains_key(&pid) {
            self.children.insert(pid, Process::new(pid));
        }

        let (in_syscall, controller) = {
            let process = self.children.get(&pid).unwrap();
            (process.in_syscall, process.get_controller())
        };

        if !in_syscall {
            println!("Syscall entry for pid {}: {:?}", pid, syscall);

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
                    println!("Syscall entry without return_val of -ENOSYS detected, and is not execve!");
                    return Err(ErrCode::InternalError);
                }
                // If it is execve, we're OK
            }
        } else {
            println!("Syscall exit for pid {}: {:?}", pid, syscall);

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
            // println!("ILLEGAL {}", syscall.call);
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
                    println!("ILLEGAL {}", call);
                }
                Ok(()) */
                Err(code)
            }
        }
    }

    // TODO: Measure rusage before killing child process to allow for measurement of killed children
    fn print_usage_statistics(&self) {
        let usage = get_children_rusage().expect("Could not get usage statistics!");
        println!("User Time: {}.{:06}s", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        println!("System Time: {}.{:06}s", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
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
