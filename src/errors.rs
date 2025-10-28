use sea_orm::DbErr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RustiveError {
    #[error("Command {0} failed")]
    CommandExecutionFailed(String),
    #[error("Timeout")]
    Timeout,
    #[error("Database Connection Failed")]
    DatabaseError(DbErr),
    #[error("STD Error")]
    IO(#[from] std::io::Error),
}
