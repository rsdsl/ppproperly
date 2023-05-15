use thiserror::Error;

/// Any ppproperly or library error.
#[derive(Debug, Error)]
pub enum Error {}

/// Alias for `std::result::Result` that has `Error` as its error type.
pub type Result<T> = std::result::Result<T, Error>;
