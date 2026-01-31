//! Error types for the Bluebox DNS server.

use std::io;
use std::net::AddrParseError;

use thiserror::Error;

/// Main error type for Bluebox operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    #[error("DNS protocol error: {0}")]
    Protocol(#[from] hickory_proto::error::ProtoError),

    #[error("resolver error: {0}")]
    Resolver(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("metrics error: {0}")]
    Metrics(String),
}

/// Configuration-related errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadFile(#[source] io::Error),

    #[error("failed to parse config: {0}")]
    Parse(#[source] toml::de::Error),

    #[error("invalid upstream resolver address: {0}")]
    InvalidResolver(#[source] AddrParseError),

    #[error("validation failed: {0}")]
    Validation(#[from] ValidationError),
}

/// Validation errors for configuration values.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("cache_ttl_seconds must be greater than 0")]
    ZeroCacheTtl,

    #[error("buffer_pool_size must be greater than 0")]
    ZeroBufferPoolSize,

    #[error("channel_capacity must be greater than 0")]
    ZeroChannelCapacity,

    #[error("arp_spoof.spoof_interval_secs must be greater than 0")]
    ZeroSpoofInterval,

    #[error("blocklist pattern cannot be empty")]
    EmptyBlocklistPattern,

    #[error("invalid wildcard pattern: {pattern:?}")]
    InvalidWildcardPattern { pattern: String },

    #[error("blocklist source name cannot be empty")]
    EmptyBlocklistSourceName,

    #[error("duplicate blocklist source name: {name:?}")]
    DuplicateBlocklistSourceName { name: String },

    #[error("blocklist source {name:?} has empty file path")]
    EmptyBlocklistSourcePath { name: String },

    #[error("blocklist source {name:?} has empty URL")]
    EmptyBlocklistSourceUrl { name: String },

    #[error(
        "blocklist source {name:?} has invalid URL (must start with http:// or https://): {url:?}"
    )]
    InvalidBlocklistSourceUrl { name: String, url: String },
}

/// Network-related errors.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("no suitable network interface found")]
    NoInterface,

    #[error("failed to open datalink channel: {0}")]
    ChannelOpen(String),

    #[error("unsupported channel type")]
    UnsupportedChannel,

    #[error("failed to send packet: {0}")]
    SendFailed(String),

    #[error("packet construction failed: {0}")]
    PacketConstruction(String),
}

/// Result type alias using our Error.
pub type Result<T> = std::result::Result<T, Error>;
