use executors;
use libc;
use nix::errno;
use nix::sys::signal;
use nix::sys::wait;
use nix::unistd;
use ptrace;
use std::mem;
use syscall::nr;
use syscall_handlers::ErrCode;
use syscall_handlers::OkCode;
use syscall_handlers::SyscallHandler;

const NOP_SYSCALL: usize = 1024;  // Random invalid syscall number to cancel syscall

pub struct Sandbox {
    executor: Box<executors::Executor>,
    syscall_handlers: Vec<Box<SyscallHandler>>,
    child_pid: libc::c_int,
}

impl Sandbox {
    pub fn new(executor: Box<executors::Executor>, syscall_handlers: Vec<Box<SyscallHandler>>) -> Sandbox {
        Sandbox {
            executor: executor,
            syscall_handlers: syscall_handlers,
            child_pid: -1,
        }
    }

    pub fn start(&mut self) -> Result<(), ErrCode> {
        match unistd::fork() {
            Ok(fork_result) => match fork_result {
                unistd::ForkResult::Parent { child } => {
                    println!("pid: {}", child);
                    self.child_pid = child;
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
        let mut in_syscall = false;  // TODO: Handle PTRACE_EVENTs interrupting syscalls

        // Wait for initial SIGSTOP after PTRACE_TRACEME and set options.
        {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            if let wait::WaitStatus::Stopped(_, sig) = status {
                if sig == signal::Signal::SIGSTOP {
                    println!("Got initial SIGSTOP, commencing with execution.");
                    ptrace::setoptions(self.child_pid, ptrace::PTRACE_O_EXITKILL).expect("Failed to set ptrace options!");
                    ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");
                } else {
                    self.kill_program();
                    return Err(ErrCode::InternalError);
                }
            } else {
                self.kill_program();
                return Err(ErrCode::InternalError);
            }
        }

        // Intercept and cancel RT_SIGPROCMASK from signal::raise
        loop {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            if let wait::WaitStatus::Stopped(_, sig) = status {
                if sig == signal::Signal::SIGTRAP {
                    let mut syscall = ptrace::Syscall::from_pid(self.child_pid).expect("Failed to get syscall");
                    if syscall.call != nr::RT_SIGPROCMASK && syscall.call != NOP_SYSCALL {
                        self.kill_program().expect("Failed to kill child!");
                        return Err(ErrCode::InternalError);
                    }

                    if !in_syscall {
                        syscall.call = NOP_SYSCALL;
                        syscall.write().expect("Failed to overwrite syscall!");

                        in_syscall = true;
                        ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");
                    } else {
                        in_syscall = false;
                        ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");
                        break;
                    }
                }
            }
        }

        loop {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            println!("{:?}", status);
            match status {
                wait::WaitStatus::Exited(_, code) => {
                    println!("Exited with code {}", code);
                    break;
                },
                wait::WaitStatus::Signaled(_, signal, dumped_core) => {
                    println!("Received signal {}", signal as i32);
                    self.kill_program().expect("Failed to kill child!");  // TODO: Process inbound signals
                    break;
                }
                wait::WaitStatus::Stopped(_, sig) => {
                    match sig {
                        signal::Signal::SIGTRAP => {
                            let syscall = ptrace::Syscall::from_pid(self.child_pid).expect("Failed to get syscall");
                            if !in_syscall {
                                match self.process_syscall_entry(&syscall) {
                                    Err(code) => {
                                        result = Err(code);
                                        self.kill_program().expect("Failed to kill child!");
                                        break;
                                    },
                                    _ => ()
                                }
                                in_syscall = true;
                            } else {
                                in_syscall = false;
                            }
                        },
                        _ => ()
                    }
                },
                _ => ()
            }
            ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");
        }
        result
    }

    fn kill_program(&self) -> Result<(), ()> {
        match signal::kill(self.child_pid, signal::SIGKILL) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    fn process_syscall_entry(&mut self, syscall: &ptrace::Syscall) -> Result<(), ErrCode> {
        println!("Syscall entry: {:?}", syscall);

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
                match handler.handle_syscall_entry(syscall) {
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

    fn print_usage_statistics(&self) {
        let usage = get_children_rusage().expect("Could not get usage statistics!");
        println!("User Time: {}.{:06}s", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        println!("System Time: {}.{:06}s", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
    }
}

impl Sandbox {
    fn start_program(&self) -> Result<(), ()> {
        ptrace::traceme().expect("Failed to traceme!");
        signal::raise(signal::SIGSTOP).expect("Failed to raise SIGSTOP!");
        self.executor.execute()
    }
}

pub fn get_children_rusage() -> Result<libc::rusage, i32> {
    let mut usage: libc::rusage = unsafe { mem::uninitialized() };
    match unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) } {
        0 => Ok(usage),
        _ => Err(errno::errno()),
    }
}