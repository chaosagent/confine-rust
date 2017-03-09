pub mod execve;

pub trait Executor {
    fn execute(&self) -> Result<(), ()>;  // TODO: error enum for execute
}
