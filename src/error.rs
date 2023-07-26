use std::{io, num, string};

use thiserror::Error;

/// Any ppproperly or library error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid EtherType: {0}")]
    InvalidEtherType(u16),
    #[error("invalid PPPoE code: {0}")]
    InvalidPPPoECode(u8),
    #[error("invalid PPPoE tag: {0}")]
    InvalidPPPoETag(u16),
    #[error("missing service name")]
    MissingServiceName,
    #[error("missing access concentrator name")]
    MissingACName,
    #[error("invalid number of tags: expected {0}, got {1}")]
    InvalidNumberOfTags(usize, usize),
    #[error("non-zero session ID: {0}")]
    NonZeroSessionID(u16),
    #[error("PADI size exceeds 1484 bytes")]
    PADITooBig(u16),

    #[error("invalid PPP protocol: {0}")]
    InvalidPPPProtocol(u16),

    #[error("invalid LCP code: {0}")]
    InvalidLCPCode(u8),
    #[error("invalid LCP option type: {0}")]
    InvalidLCPOptionType(u8),

    #[error("invalid authentication protocol: {0}")]
    InvalidAuthProtocol(u16),
    #[error("invalid quality protocol: {0}")]
    InvalidQualityProtocol(u16),

    #[error("invalid PAP code: {0}")]
    InvalidPAPCode(u8),

    #[error("invalid CHAP code: {0}")]
    InvalidCHAPCode(u8),
    #[error("invalid CHAP algorithm: {0}")]
    InvalidChapAlgorithm(u8),

    #[error("conversion from UTF-8: {0}")]
    FromUtf8(#[from] string::FromUtf8Error),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("integer type conversion: {0}")]
    TryFromInt(#[from] num::TryFromIntError),
}

/// Alias for `std::result::Result` that has `Error` as its error type.
pub type Result<T> = std::result::Result<T, Error>;
