mod cxx;

use syscall_handlers::SyscallHandler;

pub trait Executor {
    fn execute(&self) -> Result<(), ()>;  // TODO: error enum for execute
}

pub fn get_executor(executor_name: &str) -> Result<fn (args: &[String]) -> impl Executor, ()> {
    match executor_name {
        "cxx" => Ok(cxx::CXXExecutor::new),
        _ => Err(())
    }
}

pub fn get_syscall_handler(executor_name: &str) -> Result<fn () -> impl SyscallHandler, ()> {
    match executor_name {
        "cxx" => Ok(cxx::CXXSyscallHandler::new),
        _ => Err(())
    }
}