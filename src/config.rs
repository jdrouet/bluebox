//! Configuration loading and validation.

use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

use crate::error::{ConfigError, Result};

/// Main configuration for the Bluebox DNS server.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Network interface to listen on. If None, auto-detect.
    pub interface: Option<String>,

    /// Upstream DNS resolver address (e.g., "1.1.1.1:53").
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub upstream_resolver: SocketAddr,

    /// Cache TTL in seconds.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,

    /// List of blocked domain patterns.
    /// Supports exact matches ("example.com") and wildcards ("*.example.com").
    #[serde(default)]
    pub blocklist: Vec<String>,

    /// Size of the packet buffer pool.
    #[serde(default = "default_buffer_pool_size")]
    pub buffer_pool_size: usize,

    /// Channel capacity for packet queue.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
}

const fn default_cache_ttl() -> u64 {
    300
}

const fn default_buffer_pool_size() -> usize {
    64
}

const fn default_channel_capacity() -> usize {
    1000
}

fn deserialize_socket_addr<'de, D>(deserializer: D) -> std::result::Result<SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        Self::parse(&content)
    }

    /// Parse configuration from a TOML string.
    pub fn parse(content: &str) -> Result<Self> {
        let config: Self = toml::from_str(content).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    fn validate(&self) -> Result<()> {
        if self.cache_ttl_seconds == 0 {
            return Err(ConfigError::Validation("cache_ttl_seconds must be > 0".into()).into());
        }

        if self.buffer_pool_size == 0 {
            return Err(ConfigError::Validation("buffer_pool_size must be > 0".into()).into());
        }

        if self.channel_capacity == 0 {
            return Err(ConfigError::Validation("channel_capacity must be > 0".into()).into());
        }

        // Validate blocklist patterns
        for pattern in &self.blocklist {
            if pattern.is_empty() {
                return Err(ConfigError::Validation("empty blocklist pattern".into()).into());
            }
            if pattern.starts_with("*.") && pattern.len() <= 2 {
                return Err(ConfigError::Validation(format!(
                    "invalid wildcard pattern: {pattern}"
                ))
                .into());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_config() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"
            cache_ttl_seconds = 600
            blocklist = ["example.com", "*.ads.com"]
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.upstream_resolver.to_string(), "1.1.1.1:53");
        assert_eq!(config.cache_ttl_seconds, 600);
        assert_eq!(config.blocklist.len(), 2);
        assert!(config.interface.is_none());
    }

    #[test]
    fn test_parse_with_interface() {
        let toml = r#"
            interface = "eth0"
            upstream_resolver = "8.8.8.8:53"
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_default_values() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.cache_ttl_seconds, 300);
        assert_eq!(config.buffer_pool_size, 64);
        assert_eq!(config.channel_capacity, 1000);
        assert!(config.blocklist.is_empty());
    }

    #[test]
    fn test_invalid_resolver_address() {
        let toml = r#"
            upstream_resolver = "not-an-address"
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_zero_cache_ttl_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"
            cache_ttl_seconds = 0
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_empty_blocklist_pattern_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"
            blocklist = ["example.com", ""]
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_unknown_field_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"
            unknown_field = "value"
        "#;

        assert!(Config::parse(toml).is_err());
    }
}
