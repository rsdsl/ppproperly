use std::{io, num};

use thiserror::Error;

/// Any ppproperly or library error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid PPPoE code: {0}")]
    InvalidPPPoECode(u8),
    #[error("invalid PPPoE tag: {0}")]
    InvalidPPPoETag(u16),

    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("integer type conversion: {0}")]
    TryFromInt(#[from] num::TryFromIntError),
}

/// Alias for `std::result::Result` that has `Error` as its error type.
pub type Result<T> = std::result::Result<T, Error>;
