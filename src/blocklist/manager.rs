//! Blocklist manager with hot-reload support.
//!
//! This module provides a central manager that coordinates multiple blocklist sources,
//! merges patterns, and supports hot-reloading without service restart.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use super::loader::{FileLoader, LoadError};
use super::remote::RemoteLoader;
use crate::config::{BlocklistSourceConfig, BlocklistSourceType, Config};
use crate::dns::Blocker;

/// Error type for blocklist manager operations.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// Source with the given name was not found.
    #[error("unknown blocklist source: {0:?}")]
    UnknownSource(String),

    /// Failed to load blocklist from file.
    #[error("failed to load file blocklist")]
    FileLoad(#[from] LoadError),

    /// Failed to load blocklist from remote URL.
    #[error("failed to load remote blocklist")]
    RemoteLoad(#[from] super::remote::RemoteLoadError),
}

/// Statistics for a single blocklist source.
#[derive(Debug, Clone)]
pub struct SourceStats {
    /// Number of patterns loaded from this source.
    pub pattern_count: usize,
}

/// Manages multiple blocklist sources with hot-reload support.
///
/// The `BlocklistManager` coordinates loading from all configured sources,
/// merges patterns, and provides atomic updates to the [`Blocker`] without
/// interrupting query handling.
///
/// # Example
///
/// ```no_run
/// use std::path::PathBuf;
/// use bluebox::blocklist::manager::BlocklistManager;
/// use bluebox::config::Config;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::load("config.toml")?;
/// let manager = BlocklistManager::new(&config)?;
/// manager.initialize().await?;
///
/// // Get the blocker for query handling
/// let blocker = manager.blocker();
///
/// // Later, refresh a specific source
/// manager.refresh_source("steven-black").await?;
/// # Ok(())
/// # }
/// ```
pub struct BlocklistManager {
    /// Current merged blocker, shared with query handlers.
    blocker: Arc<RwLock<Blocker>>,

    /// Patterns per source for incremental updates.
    source_patterns: RwLock<HashMap<String, Vec<String>>>,

    /// Source configurations.
    sources: Vec<BlocklistSourceConfig>,

    /// Inline patterns from config (always loaded).
    inline_patterns: Vec<String>,

    /// Loader for remote URLs.
    remote_loader: Option<RemoteLoader>,
}

impl BlocklistManager {
    /// Name used for inline patterns in the source map.
    const INLINE_SOURCE_NAME: &'static str = "__inline__";

    /// Create a new blocklist manager from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the remote loader cannot be created (only when
    /// remote sources are configured).
    pub fn new(config: &Config) -> Result<Self, ManagerError> {
        let cache_dir = config.blocklist_cache_dir();

        // Create remote loader only if there are remote sources
        let has_remote_sources = config
            .blocklist_sources
            .iter()
            .any(|s| matches!(s.source, BlocklistSourceType::Remote { .. }));

        let remote_loader = if has_remote_sources {
            Some(RemoteLoader::new(cache_dir).map_err(ManagerError::RemoteLoad)?)
        } else {
            None
        };

        Ok(Self {
            blocker: Arc::new(RwLock::new(Blocker::default())),
            source_patterns: RwLock::new(HashMap::new()),
            sources: config.blocklist_sources.clone(),
            inline_patterns: config.blocklist.clone(),
            remote_loader,
        })
    }

    /// Create a new blocklist manager with a custom cache directory.
    ///
    /// This is useful for testing or when you need to override the cache location.
    pub fn with_cache_dir(config: &Config, cache_dir: PathBuf) -> Result<Self, ManagerError> {
        let has_remote_sources = config
            .blocklist_sources
            .iter()
            .any(|s| matches!(s.source, BlocklistSourceType::Remote { .. }));

        let remote_loader = if has_remote_sources {
            Some(RemoteLoader::new(cache_dir).map_err(ManagerError::RemoteLoad)?)
        } else {
            None
        };

        Ok(Self {
            blocker: Arc::new(RwLock::new(Blocker::default())),
            source_patterns: RwLock::new(HashMap::new()),
            sources: config.blocklist_sources.clone(),
            inline_patterns: config.blocklist.clone(),
            remote_loader,
        })
    }

    /// Get a shared reference to the blocker for query handling.
    ///
    /// The returned `Arc<RwLock<Blocker>>` can be shared with multiple
    /// `QueryHandler` instances. When the blocker is updated via
    /// [`refresh_source`](Self::refresh_source) or
    /// [`set_source_enabled`](Self::set_source_enabled), all handlers
    /// will automatically use the new blocker.
    #[must_use]
    pub fn blocker(&self) -> Arc<RwLock<Blocker>> {
        Arc::clone(&self.blocker)
    }

    /// Load all blocklists and build the initial blocker.
    ///
    /// This method loads patterns from:
    /// 1. Inline patterns from the configuration
    /// 2. Each enabled blocklist source (file or remote)
    ///
    /// Failed sources are logged but don't cause the initialization to fail.
    /// This ensures the server can start even if some sources are temporarily
    /// unavailable.
    pub async fn initialize(&self) -> Result<(), ManagerError> {
        // Load inline patterns first
        {
            let mut patterns = self.source_patterns.write();
            patterns.insert(
                Self::INLINE_SOURCE_NAME.to_string(),
                self.inline_patterns.clone(),
            );
        }

        tracing::info!(
            count = self.inline_patterns.len(),
            "loaded inline blocklist patterns"
        );

        // Load each configured source
        for source in &self.sources {
            if !source.enabled {
                tracing::debug!(name = ?source.name, "skipping disabled blocklist source");
                continue;
            }

            match self.load_source(source).await {
                Ok(patterns) => {
                    tracing::info!(
                        name = ?source.name,
                        count = patterns.len(),
                        "loaded blocklist source"
                    );
                    self.source_patterns
                        .write()
                        .insert(source.name.clone(), patterns);
                }
                Err(err) => {
                    tracing::error!(
                        name = ?source.name,
                        error = ?err,
                        "failed to load blocklist source"
                    );
                }
            }
        }

        self.rebuild_blocker();
        Ok(())
    }

    /// Rebuild the blocker from all source patterns.
    ///
    /// This method collects all patterns from all sources, deduplicates them,
    /// and atomically replaces the current blocker.
    fn rebuild_blocker(&self) {
        // Collect patterns while holding the read lock, then release it
        let all_patterns: Vec<String> = self
            .source_patterns
            .read()
            .values()
            .flatten()
            .cloned()
            .collect();
        let total_raw = all_patterns.len();

        let new_blocker = Blocker::new(all_patterns);
        let deduped_count = new_blocker.len();

        tracing::info!(
            raw_patterns = total_raw,
            unique_patterns = deduped_count,
            "rebuilt blocker"
        );

        *self.blocker.write() = new_blocker;
    }

    /// Load patterns from a single source.
    async fn load_source(
        &self,
        source: &BlocklistSourceConfig,
    ) -> Result<Vec<String>, ManagerError> {
        match &source.source {
            BlocklistSourceType::File { path } => {
                tracing::debug!(name = ?source.name, path = ?path, "loading file blocklist");
                let patterns = FileLoader::load(path, source.format).await?;
                Ok(patterns)
            }
            BlocklistSourceType::Remote { url } => {
                let loader = self.remote_loader.as_ref().ok_or_else(|| {
                    ManagerError::UnknownSource(format!(
                        "remote loader not available for source {0:?}",
                        source.name
                    ))
                })?;

                tracing::debug!(name = ?source.name, url = %url, "loading remote blocklist");
                let patterns = loader.load_cached(&source.name, url, source.format).await?;
                Ok(patterns)
            }
        }
    }

    /// Refresh a specific source by name.
    ///
    /// This reloads the patterns from the source and rebuilds the blocker
    /// atomically. Query handling continues uninterrupted during the refresh.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::UnknownSource`] if no source with the given
    /// name exists.
    pub async fn refresh_source(&self, name: &str) -> Result<(), ManagerError> {
        let source = self
            .sources
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ManagerError::UnknownSource(name.to_string()))?;

        tracing::info!(name = ?name, "refreshing blocklist source");

        let patterns = self.load_source(source).await?;
        let count = patterns.len();

        self.source_patterns
            .write()
            .insert(name.to_string(), patterns);
        self.rebuild_blocker();

        tracing::info!(name = ?name, count, "refreshed blocklist source");
        Ok(())
    }

    /// Enable or disable a source at runtime.
    ///
    /// When enabling a source, its patterns are loaded and added to the blocker.
    /// When disabling, its patterns are removed from the blocker.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::UnknownSource`] if no source with the given
    /// name exists.
    pub async fn set_source_enabled(&self, name: &str, enabled: bool) -> Result<(), ManagerError> {
        let source = self
            .sources
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ManagerError::UnknownSource(name.to_string()))?;

        if enabled {
            tracing::info!(name = ?name, "enabling blocklist source");
            let patterns = self.load_source(source).await?;
            let count = patterns.len();
            self.source_patterns
                .write()
                .insert(name.to_string(), patterns);
            tracing::info!(name = ?name, count, "enabled blocklist source");
        } else {
            tracing::info!(name = ?name, "disabling blocklist source");
            self.source_patterns.write().remove(name);
        }

        self.rebuild_blocker();
        Ok(())
    }

    /// Get statistics for all loaded sources.
    ///
    /// Returns a map of source names to their statistics, including the
    /// number of patterns loaded from each source.
    #[must_use]
    pub fn stats(&self) -> HashMap<String, SourceStats> {
        self.source_patterns
            .read()
            .iter()
            .map(|(name, patterns)| {
                (
                    name.clone(),
                    SourceStats {
                        pattern_count: patterns.len(),
                    },
                )
            })
            .collect()
    }

    /// Get the total number of unique patterns across all sources.
    #[must_use]
    pub fn total_patterns(&self) -> usize {
        self.blocker.read().len()
    }

    /// Check if a source is currently loaded (has patterns in the manager).
    #[must_use]
    pub fn is_source_loaded(&self, name: &str) -> bool {
        self.source_patterns.read().contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlocklistFormat;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn create_test_config(sources: Vec<BlocklistSourceConfig>) -> Config {
        Config {
            interface: None,
            upstream_resolver: "1.1.1.1:53".parse().unwrap(),
            cache_ttl_seconds: 300,
            blocklist: vec!["inline.example.com".to_string()],
            blocklist_sources: sources,
            blocklist_cache_dir: None,
            buffer_pool_size: 64,
            channel_capacity: 1000,
            arp_spoof: crate::config::ArpSpoofSettings::default(),
            metrics: crate::config::MetricsConfig::default(),
        }
    }

    fn create_file_source(name: &str, path: &std::path::Path) -> BlocklistSourceConfig {
        BlocklistSourceConfig {
            name: name.to_string(),
            enabled: true,
            source: BlocklistSourceType::File {
                path: path.to_path_buf(),
            },
            format: BlocklistFormat::Domains,
            refresh_interval_hours: None,
        }
    }

    #[tokio::test]
    async fn should_load_inline_patterns_on_initialize() {
        let config = create_test_config(vec![]);
        let manager = BlocklistManager::new(&config).unwrap();

        manager.initialize().await.unwrap();

        let stats = manager.stats();
        assert!(stats.contains_key(BlocklistManager::INLINE_SOURCE_NAME));
        assert_eq!(stats[BlocklistManager::INLINE_SOURCE_NAME].pattern_count, 1);
        assert_eq!(manager.total_patterns(), 1);
    }

    #[tokio::test]
    async fn should_load_file_source_on_initialize() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "file1.example.com").unwrap();
        writeln!(file, "file2.example.com").unwrap();
        file.flush().unwrap();

        let source = create_file_source("test-file", file.path());
        let config = create_test_config(vec![source]);
        let manager = BlocklistManager::new(&config).unwrap();

        manager.initialize().await.unwrap();

        let stats = manager.stats();
        assert!(stats.contains_key("test-file"));
        assert_eq!(stats["test-file"].pattern_count, 2);
        // 1 inline + 2 from file
        assert_eq!(manager.total_patterns(), 3);
    }

    #[tokio::test]
    async fn should_skip_disabled_sources() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "disabled.example.com").unwrap();
        file.flush().unwrap();

        let mut source = create_file_source("disabled-source", file.path());
        source.enabled = false;

        let config = create_test_config(vec![source]);
        let manager = BlocklistManager::new(&config).unwrap();

        manager.initialize().await.unwrap();

        let stats = manager.stats();
        assert!(!stats.contains_key("disabled-source"));
        // Only inline pattern
        assert_eq!(manager.total_patterns(), 1);
    }

    #[tokio::test]
    async fn should_refresh_source() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.txt");

        // Create initial file
        fs::write(&file_path, "original.example.com\n").unwrap();

        let source = create_file_source("refreshable", &file_path);
        let config = create_test_config(vec![source]);
        let manager = BlocklistManager::new(&config).unwrap();

        manager.initialize().await.unwrap();
        assert_eq!(manager.stats()["refreshable"].pattern_count, 1);

        // Update the file
        fs::write(
            &file_path,
            "updated1.example.com\nupdated2.example.com\nupdated3.example.com\n",
        )
        .unwrap();

        // Refresh
        manager.refresh_source("refreshable").await.unwrap();

        assert_eq!(manager.stats()["refreshable"].pattern_count, 3);
    }

    #[tokio::test]
    async fn should_return_error_for_unknown_source_on_refresh() {
        let config = create_test_config(vec![]);
        let manager = BlocklistManager::new(&config).unwrap();
        manager.initialize().await.unwrap();

        let result = manager.refresh_source("nonexistent").await;
        assert!(matches!(result, Err(ManagerError::UnknownSource(_))));
    }

    #[tokio::test]
    async fn should_disable_source_at_runtime() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "removable.example.com").unwrap();
        file.flush().unwrap();

        let source = create_file_source("removable", file.path());
        let config = create_test_config(vec![source]);
        let manager = BlocklistManager::new(&config).unwrap();

        manager.initialize().await.unwrap();
        assert!(manager.is_source_loaded("removable"));
        // 1 inline + 1 from file
        assert_eq!(manager.total_patterns(), 2);

        // Disable the source
        manager
            .set_source_enabled("removable", false)
            .await
            .unwrap();

        assert!(!manager.is_source_loaded("removable"));
        // Only inline remains
        assert_eq!(manager.total_patterns(), 1);
    }

    #[tokio::test]
    async fn should_enable_source_at_runtime() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "addable.example.com").unwrap();
        file.flush().unwrap();

        let mut source = create_file_source("addable", file.path());
        source.enabled = false; // Start disabled

        let config = create_test_config(vec![source]);
        let manager = BlocklistManager::new(&config).unwrap();

        manager.initialize().await.unwrap();
        assert!(!manager.is_source_loaded("addable"));
        assert_eq!(manager.total_patterns(), 1);

        // Enable the source
        manager.set_source_enabled("addable", true).await.unwrap();

        assert!(manager.is_source_loaded("addable"));
        assert_eq!(manager.total_patterns(), 2);
    }

    #[tokio::test]
    async fn should_share_blocker_across_clones() {
        let config = create_test_config(vec![]);
        let manager = BlocklistManager::new(&config).unwrap();
        manager.initialize().await.unwrap();

        let blocker1 = manager.blocker();
        let blocker2 = manager.blocker();

        // Both should point to the same blocker
        assert!(Arc::ptr_eq(&blocker1, &blocker2));
    }

    #[tokio::test]
    async fn should_update_shared_blocker_on_refresh() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.txt");

        // Create initial file
        fs::write(&file_path, "domain1.example.com\n").unwrap();

        let source = create_file_source("test", &file_path);
        let config = create_test_config(vec![source]);
        let manager = BlocklistManager::new(&config).unwrap();

        manager.initialize().await.unwrap();

        let blocker = manager.blocker();
        let initial_count = blocker.read().len();

        // Update the file and refresh
        fs::write(&file_path, "domain1.example.com\ndomain2.example.com\n").unwrap();

        manager.refresh_source("test").await.unwrap();

        // The shared blocker should be updated
        let new_count = blocker.read().len();
        assert!(new_count > initial_count);
    }

    #[tokio::test]
    async fn should_continue_after_source_load_failure() {
        // Create one valid file
        let mut valid_file = NamedTempFile::new().unwrap();
        writeln!(valid_file, "valid.example.com").unwrap();
        valid_file.flush().unwrap();

        // Create sources - one valid, one pointing to nonexistent file
        let valid_source = create_file_source("valid", valid_file.path());
        let invalid_source = BlocklistSourceConfig {
            name: "invalid".to_string(),
            enabled: true,
            source: BlocklistSourceType::File {
                path: "/nonexistent/path/blocklist.txt".into(),
            },
            format: BlocklistFormat::Domains,
            refresh_interval_hours: None,
        };

        let config = create_test_config(vec![invalid_source, valid_source]);
        let manager = BlocklistManager::new(&config).unwrap();

        // Should not fail, just log error for invalid source
        manager.initialize().await.unwrap();

        let stats = manager.stats();
        assert!(stats.contains_key("valid"));
        assert!(!stats.contains_key("invalid"));
    }

    #[tokio::test]
    async fn should_deduplicate_patterns_across_sources() {
        let mut file1 = NamedTempFile::new().unwrap();
        writeln!(file1, "duplicate.example.com").unwrap();
        writeln!(file1, "unique1.example.com").unwrap();
        file1.flush().unwrap();

        let mut file2 = NamedTempFile::new().unwrap();
        writeln!(file2, "duplicate.example.com").unwrap();
        writeln!(file2, "unique2.example.com").unwrap();
        file2.flush().unwrap();

        let source1 = create_file_source("source1", file1.path());
        let source2 = create_file_source("source2", file2.path());

        // Config with no inline patterns
        let mut config = create_test_config(vec![source1, source2]);
        config.blocklist.clear();

        let manager = BlocklistManager::new(&config).unwrap();
        manager.initialize().await.unwrap();

        // Raw count: 2 + 2 = 4, but unique should be 3
        // Note: Blocker handles deduplication internally
        let stats = manager.stats();
        assert_eq!(stats["source1"].pattern_count, 2);
        assert_eq!(stats["source2"].pattern_count, 2);

        // The blocker should have deduplicated
        // duplicate.example.com, unique1.example.com, unique2.example.com = 3
        assert_eq!(manager.total_patterns(), 3);
    }

    #[tokio::test]
    async fn should_create_manager_with_custom_cache_dir() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(vec![]);

        let manager =
            BlocklistManager::with_cache_dir(&config, temp_dir.path().to_path_buf()).unwrap();
        manager.initialize().await.unwrap();

        assert_eq!(manager.total_patterns(), 1); // Just inline
    }
}
