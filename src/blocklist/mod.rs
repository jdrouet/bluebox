//! Blocklist format parsers.
//!
//! This module provides parsers for common blocklist formats used by various
//! ad-blocking and privacy tools.
//!
//! # Supported Formats
//!
//! - **Domain List**: Simple format with one domain per line, supports wildcards
//! - **Hosts File**: Standard `/etc/hosts` format used by Steven Black, Dan Pollock, etc.
//! - **`AdBlock`**: Basic `AdBlock` Plus filter syntax (domain extraction only)
//!
//! # Example
//!
//! ```
//! use bluebox::blocklist::{BlocklistParser, DomainListParser};
//! use std::io::BufReader;
//!
//! let content = "# Comment\nexample.com\n*.ads.com";
//! let parser = DomainListParser;
//! let domains = parser.parse(&mut BufReader::new(content.as_bytes())).unwrap();
//! assert_eq!(domains, vec!["example.com", "*.ads.com"]);
//! ```

mod adblock;
mod domains;
mod hosts;
pub mod loader;
pub mod manager;
pub mod remote;

use std::io::BufRead;

pub use adblock::AdBlockParser;
pub use domains::DomainListParser;
pub use hosts::HostsFileParser;

use crate::config::BlocklistFormat;

/// Error type for blocklist parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// I/O error during reading.
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    /// Invalid line encountered during parsing.
    #[error("invalid line {line}: {reason}")]
    InvalidLine {
        /// Line number (1-indexed).
        line: usize,
        /// Reason for the error.
        reason: String,
    },
}

/// Trait for blocklist parsers.
///
/// Each parser implementation handles a specific blocklist format and extracts
/// domain patterns that can be used by the [`Blocker`](crate::dns::Blocker).
pub trait BlocklistParser: Send + Sync {
    /// Parse blocklist content and return domain patterns.
    ///
    /// # Arguments
    ///
    /// * `reader` - A mutable reference to a buffered reader over the blocklist content
    ///
    /// # Returns
    ///
    /// A vector of domain patterns (e.g., `"example.com"`, `"*.ads.com"`).
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if reading fails.
    fn parse(&self, reader: &mut dyn BufRead) -> Result<Vec<String>, ParseError>;
}

/// Returns a boxed parser for the given blocklist format.
///
/// # Example
///
/// ```
/// use bluebox::blocklist::parser_for_format;
/// use bluebox::config::BlocklistFormat;
/// use std::io::BufReader;
///
/// let parser = parser_for_format(BlocklistFormat::Hosts);
/// let content = "0.0.0.0 ads.example.com";
/// let domains = parser.parse(&mut BufReader::new(content.as_bytes())).unwrap();
/// assert_eq!(domains, vec!["ads.example.com"]);
/// ```
#[must_use]
pub fn parser_for_format(format: BlocklistFormat) -> Box<dyn BlocklistParser> {
    match format {
        BlocklistFormat::Domains => Box::new(DomainListParser),
        BlocklistFormat::Hosts => Box::new(HostsFileParser),
        BlocklistFormat::Adblock => Box::new(AdBlockParser),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn should_return_domain_parser_when_format_is_domains() {
        let parser = parser_for_format(BlocklistFormat::Domains);
        let content = "example.com\n*.test.com";
        let domains = parser
            .parse(&mut BufReader::new(content.as_bytes()))
            .unwrap();
        assert_eq!(domains, vec!["example.com", "*.test.com"]);
    }

    #[test]
    fn should_return_hosts_parser_when_format_is_hosts() {
        let parser = parser_for_format(BlocklistFormat::Hosts);
        let content = "0.0.0.0 ads.example.com";
        let domains = parser
            .parse(&mut BufReader::new(content.as_bytes()))
            .unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_return_adblock_parser_when_format_is_adblock() {
        let parser = parser_for_format(BlocklistFormat::Adblock);
        let content = "||ads.example.com^";
        let domains = parser
            .parse(&mut BufReader::new(content.as_bytes()))
            .unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }
}
