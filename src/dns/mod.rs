//! DNS-related modules.

pub mod blocker;
pub mod resolver;

pub use blocker::Blocker;
pub use resolver::{DnsResolver, UpstreamResolver};
