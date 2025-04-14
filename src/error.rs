use std::{convert, io, num, string};

use thiserror::Error;

/// Any ppproperly or library error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid ethertype: {0}")]
    InvalidEtherType(u16),
    #[error("invalid pppoe code: {0}")]
    InvalidPppoeCode(u8),
    #[error("invalid pppoe tag: {0}")]
    InvalidPppoeTag(u16),

    #[error("invalid ppp protocol: {0}")]
    InvalidPppProtocol(u16),

    #[error("invalid lcp code: {0}")]
    InvalidLcpCode(u8),

    #[error("invalid authentication protocol: {0}")]
    InvalidAuthProtocol(u16),
    #[error("invalid quality protocol: {0}")]
    InvalidQualityProtocol(u16),

    #[error("invalid pap code: {0}")]
    InvalidPapCode(u8),

    #[error("invalid chap code: {0}")]
    InvalidChapCode(u8),
    #[error("invalid chap algorithm: {0}")]
    InvalidChapAlgorithm(u8),

    #[error("invalid ipcp code: {0}")]
    InvalidIpcpCode(u8),
    #[error("invalid ipcp option type: {0}")]
    InvalidIpcpOptionType(u8),

    #[error("invalid ip compression protocol: {0}")]
    InvalidIpCompressionProtocol(u16),

    #[error("invalid ipv6cp code: {0}")]
    InvalidIpv6cpCode(u8),
    #[error("invalid ipv6cp option type: {0}")]
    InvalidIpv6cpOptionType(u8),

    #[error("conversion from utf8: {0}")]
    FromUtf8(#[from] string::FromUtf8Error),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("convert infallible: {0}")]
    ConvertInfallible(#[from] convert::Infallible),
    #[error("integer type conversion: {0}")]
    TryFromInt(#[from] num::TryFromIntError),
}

/// Alias for `std::result::Result` that has `Error` as its error type.
pub type Result<T> = std::result::Result<T, Error>;
