//! Configuration loading and validation.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{ConfigError, Result, ValidationError};

/// Supported blocklist file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// One domain per line.
    #[default]
    Domains,
    /// Standard hosts file format (e.g., `0.0.0.0 example.com`).
    Hosts,
    /// `AdBlock` filter syntax (future support).
    Adblock,
}

/// Source type for a blocklist.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BlocklistSourceType {
    /// Load blocklist from a local file.
    File {
        /// Path to the blocklist file.
        path: PathBuf,
    },
    /// Fetch blocklist from a remote URL.
    Remote {
        /// URL to fetch the blocklist from.
        url: String,
    },
}

/// Configuration for a blocklist source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistSourceConfig {
    /// Unique name for this blocklist source.
    pub name: String,
    /// Whether this source is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Source location (file or remote URL).
    pub source: BlocklistSourceType,
    /// Format of the blocklist file.
    #[serde(default)]
    pub format: BlocklistFormat,
    /// Refresh interval in hours (only applicable for remote sources).
    pub refresh_interval_hours: Option<u64>,
}

const fn default_enabled() -> bool {
    true
}

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

    /// Legacy inline blocklist (backwards compatible).
    /// Supports exact matches ("example.com") and wildcards ("*.example.com").
    #[serde(default)]
    pub blocklist: Vec<String>,

    /// External blocklist sources.
    #[serde(default)]
    pub blocklist_sources: Vec<BlocklistSourceConfig>,

    /// Size of the packet buffer pool.
    #[serde(default = "default_buffer_pool_size")]
    pub buffer_pool_size: usize,

    /// Channel capacity for packet queue.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,

    /// ARP spoofing configuration for transparent DNS interception.
    #[serde(default)]
    pub arp_spoof: ArpSpoofSettings,
}

/// ARP spoofing settings for transparent DNS interception.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArpSpoofSettings {
    /// Enable ARP spoofing for transparent interception.
    /// When enabled, the server will impersonate the gateway to intercept DNS queries.
    #[serde(default)]
    pub enabled: bool,

    /// Gateway IP address to impersonate. If None, auto-detect.
    pub gateway_ip: Option<Ipv4Addr>,

    /// Interval in seconds between ARP spoof packets.
    #[serde(default = "default_spoof_interval")]
    pub spoof_interval_secs: u64,

    /// Whether to restore ARP tables when shutting down.
    #[serde(default = "default_restore_on_shutdown")]
    pub restore_on_shutdown: bool,

    /// Forward non-DNS traffic to the real gateway.
    #[serde(default = "default_forward_traffic")]
    pub forward_traffic: bool,
}

impl Default for ArpSpoofSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_ip: None,
            spoof_interval_secs: default_spoof_interval(),
            restore_on_shutdown: default_restore_on_shutdown(),
            forward_traffic: default_forward_traffic(),
        }
    }
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

const fn default_spoof_interval() -> u64 {
    2
}

const fn default_restore_on_shutdown() -> bool {
    true
}

const fn default_forward_traffic() -> bool {
    true
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
            return Err(ConfigError::from(ValidationError::ZeroCacheTtl).into());
        }

        if self.buffer_pool_size == 0 {
            return Err(ConfigError::from(ValidationError::ZeroBufferPoolSize).into());
        }

        if self.channel_capacity == 0 {
            return Err(ConfigError::from(ValidationError::ZeroChannelCapacity).into());
        }

        if self.arp_spoof.spoof_interval_secs == 0 {
            return Err(ConfigError::from(ValidationError::ZeroSpoofInterval).into());
        }

        // Validate blocklist patterns
        for pattern in &self.blocklist {
            if pattern.is_empty() {
                return Err(ConfigError::from(ValidationError::EmptyBlocklistPattern).into());
            }
            if pattern.starts_with("*.") && pattern.len() <= 2 {
                return Err(ConfigError::from(ValidationError::InvalidWildcardPattern {
                    pattern: pattern.clone(),
                })
                .into());
            }
        }

        // Validate blocklist sources
        self.validate_blocklist_sources()?;

        Ok(())
    }

    /// Validate blocklist source configurations.
    fn validate_blocklist_sources(&self) -> Result<()> {
        let mut seen_names = HashSet::new();

        for source in &self.blocklist_sources {
            // Validate name is not empty
            if source.name.is_empty() {
                return Err(ConfigError::from(ValidationError::EmptyBlocklistSourceName).into());
            }

            // Validate name is unique
            if !seen_names.insert(&source.name) {
                return Err(
                    ConfigError::from(ValidationError::DuplicateBlocklistSourceName {
                        name: source.name.clone(),
                    })
                    .into(),
                );
            }

            // Validate source-specific constraints
            match &source.source {
                BlocklistSourceType::File { path } => {
                    // Validate path is not empty
                    if path.as_os_str().is_empty() {
                        return Err(
                            ConfigError::from(ValidationError::EmptyBlocklistSourcePath {
                                name: source.name.clone(),
                            })
                            .into(),
                        );
                    }

                    // Warn if refresh_interval is set for file sources (it's ignored)
                    if source.refresh_interval_hours.is_some() {
                        tracing::warn!(
                            name = ?source.name,
                            "refresh_interval_hours is ignored for file sources"
                        );
                    }
                }
                BlocklistSourceType::Remote { url } => {
                    // Validate URL is not empty
                    if url.is_empty() {
                        return Err(ConfigError::from(ValidationError::EmptyBlocklistSourceUrl {
                            name: source.name.clone(),
                        })
                        .into());
                    }

                    // Validate URL format (basic check for http/https scheme)
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        return Err(ConfigError::from(
                            ValidationError::InvalidBlocklistSourceUrl {
                                name: source.name.clone(),
                                url: url.clone(),
                            },
                        )
                        .into());
                    }
                }
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
        assert!(!config.arp_spoof.enabled);
    }

    #[test]
    fn test_arp_spoof_config() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [arp_spoof]
            enabled = true
            gateway_ip = "192.168.1.1"
            spoof_interval_secs = 5
            restore_on_shutdown = true
            forward_traffic = true
        "#;

        let config = Config::parse(toml).unwrap();
        assert!(config.arp_spoof.enabled);
        assert_eq!(
            config.arp_spoof.gateway_ip,
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(config.arp_spoof.spoof_interval_secs, 5);
        assert!(config.arp_spoof.restore_on_shutdown);
        assert!(config.arp_spoof.forward_traffic);
    }

    #[test]
    fn test_arp_spoof_defaults() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [arp_spoof]
            enabled = true
        "#;

        let config = Config::parse(toml).unwrap();
        assert!(config.arp_spoof.enabled);
        assert!(config.arp_spoof.gateway_ip.is_none());
        assert_eq!(config.arp_spoof.spoof_interval_secs, 2);
        assert!(config.arp_spoof.restore_on_shutdown);
        assert!(config.arp_spoof.forward_traffic);
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

    #[test]
    fn test_zero_spoof_interval_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [arp_spoof]
            enabled = true
            spoof_interval_secs = 0
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_blocklist_source_file() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "local-custom"
            enabled = true
            source = { type = "file", path = "/etc/bluebox/custom-blocklist.txt" }
            format = "domains"
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.blocklist_sources.len(), 1);

        let source = &config.blocklist_sources[0];
        assert_eq!(source.name, "local-custom");
        assert!(source.enabled);
        assert_eq!(source.format, BlocklistFormat::Domains);
        assert!(source.refresh_interval_hours.is_none());

        match &source.source {
            BlocklistSourceType::File { path } => {
                assert_eq!(path.to_str().unwrap(), "/etc/bluebox/custom-blocklist.txt");
            }
            BlocklistSourceType::Remote { .. } => panic!("expected file source"),
        }
    }

    #[test]
    fn test_blocklist_source_remote() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "steven-black-hosts"
            enabled = true
            source = { type = "remote", url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" }
            format = "hosts"
            refresh_interval_hours = 24
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.blocklist_sources.len(), 1);

        let source = &config.blocklist_sources[0];
        assert_eq!(source.name, "steven-black-hosts");
        assert!(source.enabled);
        assert_eq!(source.format, BlocklistFormat::Hosts);
        assert_eq!(source.refresh_interval_hours, Some(24));

        match &source.source {
            BlocklistSourceType::Remote { url } => {
                assert_eq!(
                    url,
                    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
                );
            }
            BlocklistSourceType::File { .. } => panic!("expected remote source"),
        }
    }

    #[test]
    fn test_blocklist_source_defaults() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "test"
            source = { type = "file", path = "/path/to/file.txt" }
        "#;

        let config = Config::parse(toml).unwrap();
        let source = &config.blocklist_sources[0];

        // Default enabled is true
        assert!(source.enabled);
        // Default format is domains
        assert_eq!(source.format, BlocklistFormat::Domains);
    }

    #[test]
    fn test_blocklist_source_disabled() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "disabled-source"
            enabled = false
            source = { type = "remote", url = "https://example.com/blocklist.txt" }
        "#;

        let config = Config::parse(toml).unwrap();
        assert!(!config.blocklist_sources[0].enabled);
    }

    #[test]
    fn test_blocklist_source_adblock_format() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "adguard"
            source = { type = "remote", url = "https://example.com/filter.txt" }
            format = "adblock"
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.blocklist_sources[0].format, BlocklistFormat::Adblock);
    }

    #[test]
    fn test_multiple_blocklist_sources() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "source-1"
            source = { type = "file", path = "/path/1.txt" }

            [[blocklist_sources]]
            name = "source-2"
            source = { type = "remote", url = "https://example.com/list.txt" }
            format = "hosts"
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.blocklist_sources.len(), 2);
        assert_eq!(config.blocklist_sources[0].name, "source-1");
        assert_eq!(config.blocklist_sources[1].name, "source-2");
    }

    #[test]
    fn test_blocklist_sources_with_legacy_blocklist() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"
            blocklist = ["custom-domain.com"]

            [[blocklist_sources]]
            name = "remote-list"
            source = { type = "remote", url = "https://example.com/list.txt" }
        "#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.blocklist.len(), 1);
        assert_eq!(config.blocklist[0], "custom-domain.com");
        assert_eq!(config.blocklist_sources.len(), 1);
    }

    #[test]
    fn test_blocklist_source_duplicate_name_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "same-name"
            source = { type = "file", path = "/path/1.txt" }

            [[blocklist_sources]]
            name = "same-name"
            source = { type = "file", path = "/path/2.txt" }
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_blocklist_source_empty_name_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = ""
            source = { type = "file", path = "/path/file.txt" }
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_blocklist_source_empty_path_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "test"
            source = { type = "file", path = "" }
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_blocklist_source_empty_url_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "test"
            source = { type = "remote", url = "" }
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_blocklist_source_invalid_url_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "test"
            source = { type = "remote", url = "ftp://example.com/list.txt" }
        "#;

        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn test_blocklist_source_unknown_field_rejected() {
        let toml = r#"
            upstream_resolver = "1.1.1.1:53"

            [[blocklist_sources]]
            name = "test"
            source = { type = "file", path = "/path/file.txt" }
            unknown_field = "value"
        "#;

        assert!(Config::parse(toml).is_err());
    }
}
