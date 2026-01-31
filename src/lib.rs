//! Bluebox - A fast DNS interceptor and cache.
//!
//! Bluebox is a DNS server that intercepts DNS queries on the local network,
//! caches responses, and blocks configured domains. It's designed to be faster
//! than your router's DNS resolver.
//!
//! # Architecture
//!
//! The crate is organized into several modules:
//!
//! - [`config`]: Configuration loading and validation
//! - [`dns`]: DNS protocol handling, blocking, and resolution
//! - [`cache`]: Response caching with TTL support
//! - [`network`]: Packet capture and construction
//! - [`server`]: Server orchestration
//! - [`error`]: Error types
//!
//! # Testing
//!
//! All components are designed with trait-based abstractions to enable
//! comprehensive testing without network access:
//!
//! ```rust
//! use bluebox::dns::{Blocker, DnsResolver};
//! use bluebox::cache::DnsCache;
//!
//! // Components can be tested with mock implementations
//! let blocker = Blocker::new(["*.ads.com"]);
//! assert!(blocker.is_blocked(&"tracking.ads.com".parse().unwrap()));
//! ```

pub mod blocklist;
pub mod cache;
pub mod config;
pub mod dns;
pub mod error;
pub mod metrics;
pub mod network;
pub mod server;

pub use config::Config;
pub use error::{Error, Result};
