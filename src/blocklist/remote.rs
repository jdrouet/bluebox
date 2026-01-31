//! Remote URL blocklist loader.
//!
//! This module provides functionality to load blocklists from remote URLs
//! with caching support for offline fallback.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Client;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ParseError, parser_for_format};
use crate::config::BlocklistFormat;

/// Default timeout for HTTP requests in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// User-Agent header value for HTTP requests.
const USER_AGENT: &str = concat!("bluebox/", env!("CARGO_PKG_VERSION"));

/// Error type for remote blocklist loading operations.
#[derive(Debug, thiserror::Error)]
pub enum RemoteLoadError {
    /// HTTP request failed with a non-success status code.
    #[error("HTTP request failed for {url}: status {status}")]
    HttpStatus {
        /// URL that was requested.
        url: String,
        /// HTTP status code returned.
        status: u16,
    },

    /// Network error during HTTP request.
    #[error("network error fetching {url}: {source}")]
    Network {
        /// URL that was requested.
        url: String,
        /// Underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },

    /// Timeout fetching the remote URL.
    #[error("timeout fetching {url}")]
    Timeout {
        /// URL that timed out.
        url: String,
    },

    /// Error parsing the blocklist content.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// Task join error from spawning a blocking task.
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// Cache not available for fallback.
    #[error("cache not available: {0:?}")]
    CacheUnavailable(PathBuf),

    /// I/O error during cache operations.
    #[error("cache I/O error for {path:?}: {source}")]
    CacheIo {
        /// Path to the cache file.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to create HTTP client.
    #[error("failed to create HTTP client: {0}")]
    ClientBuild(#[source] reqwest::Error),
}

/// Loads blocklists from remote URLs.
pub struct RemoteLoader {
    client: Client,
    cache_dir: PathBuf,
}

impl RemoteLoader {
    /// Create a new remote loader with the specified cache directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(cache_dir: PathBuf) -> Result<Self, RemoteLoadError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .gzip(true)
            .build()
            .map_err(RemoteLoadError::ClientBuild)?;

        Ok(Self { client, cache_dir })
    }

    /// Load a blocklist from a remote URL.
    ///
    /// This function fetches the content from the URL and parses it using the
    /// appropriate parser for the given format. Large responses are parsed in
    /// a blocking task to avoid blocking the async runtime.
    ///
    /// # Arguments
    ///
    /// * `url` - URL to fetch the blocklist from
    /// * `format` - Format of the blocklist content
    ///
    /// # Returns
    ///
    /// A vector of domain patterns extracted from the response.
    ///
    /// # Errors
    ///
    /// Returns a [`RemoteLoadError`] if:
    /// - The HTTP request fails ([`RemoteLoadError::Network`])
    /// - The server returns a non-success status ([`RemoteLoadError::HttpStatus`])
    /// - The request times out ([`RemoteLoadError::Timeout`])
    /// - The content cannot be parsed ([`RemoteLoadError::Parse`])
    pub async fn load(
        &self,
        url: &str,
        format: BlocklistFormat,
    ) -> Result<Vec<String>, RemoteLoadError> {
        let response = self.client.get(url).send().await.map_err(|err| {
            if err.is_timeout() {
                RemoteLoadError::Timeout {
                    url: url.to_string(),
                }
            } else {
                RemoteLoadError::Network {
                    url: url.to_string(),
                    source: err,
                }
            }
        })?;

        if !response.status().is_success() {
            return Err(RemoteLoadError::HttpStatus {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }

        let content = response
            .text()
            .await
            .map_err(|err| RemoteLoadError::Network {
                url: url.to_string(),
                source: err,
            })?;

        // Parse in a blocking task to avoid blocking the async runtime
        let domains = tokio::task::spawn_blocking(move || {
            let parser = parser_for_format(format);
            let mut reader = BufReader::new(content.as_bytes());
            parser.parse(&mut reader)
        })
        .await??;

        Ok(domains)
    }

    /// Load a blocklist from a remote URL with caching support.
    ///
    /// This function attempts to fetch from the remote URL first. If successful,
    /// it caches the content for future offline use. If the fetch fails, it
    /// attempts to load from the cache as a fallback.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for this blocklist (used for cache filename)
    /// * `url` - URL to fetch the blocklist from
    /// * `format` - Format of the blocklist content
    ///
    /// # Returns
    ///
    /// A vector of domain patterns extracted from the response or cache.
    ///
    /// # Errors
    ///
    /// Returns a [`RemoteLoadError`] if both the remote fetch and cache
    /// fallback fail.
    pub async fn load_cached(
        &self,
        name: &str,
        url: &str,
        format: BlocklistFormat,
    ) -> Result<Vec<String>, RemoteLoadError> {
        let cache_path = self.cache_path(name);

        // Try to load from remote
        match self.load_and_cache(url, format, &cache_path).await {
            Ok(patterns) => Ok(patterns),
            Err(err) => {
                tracing::warn!(
                    url = %url,
                    error = ?err,
                    "failed to fetch remote blocklist, trying cache"
                );
                self.load_from_cache(&cache_path, format).await
            }
        }
    }

    /// Load from remote and save to cache.
    async fn load_and_cache(
        &self,
        url: &str,
        format: BlocklistFormat,
        cache_path: &Path,
    ) -> Result<Vec<String>, RemoteLoadError> {
        let response = self.client.get(url).send().await.map_err(|err| {
            if err.is_timeout() {
                RemoteLoadError::Timeout {
                    url: url.to_string(),
                }
            } else {
                RemoteLoadError::Network {
                    url: url.to_string(),
                    source: err,
                }
            }
        })?;

        if !response.status().is_success() {
            return Err(RemoteLoadError::HttpStatus {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }

        let content = response
            .text()
            .await
            .map_err(|err| RemoteLoadError::Network {
                url: url.to_string(),
                source: err,
            })?;

        // Save to cache (best effort, don't fail if cache write fails)
        if let Err(err) = self.save_cache(cache_path, &content).await {
            tracing::warn!(
                path = ?cache_path,
                error = ?err,
                "failed to save blocklist to cache"
            );
        }

        // Parse in a blocking task
        let domains = tokio::task::spawn_blocking(move || {
            let parser = parser_for_format(format);
            let mut reader = BufReader::new(content.as_bytes());
            parser.parse(&mut reader)
        })
        .await??;

        Ok(domains)
    }

    /// Save content to the cache file.
    async fn save_cache(&self, cache_path: &Path, content: &str) -> Result<(), RemoteLoadError> {
        // Ensure cache directory exists
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|err| RemoteLoadError::CacheIo {
                    path: parent.to_path_buf(),
                    source: err,
                })?;
        }

        let mut file = File::create(cache_path)
            .await
            .map_err(|err| RemoteLoadError::CacheIo {
                path: cache_path.to_path_buf(),
                source: err,
            })?;

        file.write_all(content.as_bytes())
            .await
            .map_err(|err| RemoteLoadError::CacheIo {
                path: cache_path.to_path_buf(),
                source: err,
            })?;

        file.flush().await.map_err(|err| RemoteLoadError::CacheIo {
            path: cache_path.to_path_buf(),
            source: err,
        })?;

        tracing::debug!(path = ?cache_path, "saved blocklist to cache");
        Ok(())
    }

    /// Load content from the cache file.
    async fn load_from_cache(
        &self,
        cache_path: &Path,
        format: BlocklistFormat,
    ) -> Result<Vec<String>, RemoteLoadError> {
        let mut file = File::open(cache_path).await.map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                RemoteLoadError::CacheUnavailable(cache_path.to_path_buf())
            } else {
                RemoteLoadError::CacheIo {
                    path: cache_path.to_path_buf(),
                    source: err,
                }
            }
        })?;

        let mut content = String::new();
        file.read_to_string(&mut content)
            .await
            .map_err(|err| RemoteLoadError::CacheIo {
                path: cache_path.to_path_buf(),
                source: err,
            })?;

        tracing::info!(path = ?cache_path, "loaded blocklist from cache");

        // Parse in a blocking task
        let domains = tokio::task::spawn_blocking(move || {
            let parser = parser_for_format(format);
            let mut reader = BufReader::new(content.as_bytes());
            parser.parse(&mut reader)
        })
        .await??;

        Ok(domains)
    }

    /// Get the cache file path for a blocklist name.
    fn cache_path(&self, name: &str) -> PathBuf {
        self.cache_dir.join(format!("{name}.cache"))
    }
}

/// Returns the default cache directory for blocklists.
///
/// - Linux: `~/.cache/bluebox/blocklists/`
/// - macOS: `~/Library/Caches/bluebox/blocklists/`
/// - Windows: `{FOLDERID_LocalAppData}\bluebox\blocklists\`
///
/// Falls back to `./cache/blocklists` if the cache directory cannot be determined.
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    dirs::cache_dir().map_or_else(
        || PathBuf::from("./cache/blocklists"),
        |p| p.join("bluebox").join("blocklists"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_loader() -> (RemoteLoader, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let loader = RemoteLoader::new(temp_dir.path().to_path_buf()).unwrap();
        (loader, temp_dir)
    }

    #[tokio::test]
    async fn should_load_domains_format_from_url() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/blocklist.txt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("# Comment\nexample.com\n*.ads.com"),
            )
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/blocklist.txt", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Domains).await.unwrap();

        assert_eq!(domains, vec!["example.com", "*.ads.com"]);
    }

    #[tokio::test]
    async fn should_load_hosts_format_from_url() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/hosts"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "# Hosts file\n0.0.0.0 ads.example.com\n127.0.0.1 tracking.example.com",
            ))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/hosts", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Hosts).await.unwrap();

        assert_eq!(domains, vec!["ads.example.com", "tracking.example.com"]);
    }

    #[tokio::test]
    async fn should_load_adblock_format_from_url() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/filter.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "! AdBlock comment\n||ads.example.com^\n||tracking.example.com^$third-party",
            ))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/filter.txt", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Adblock).await.unwrap();

        assert_eq!(domains, vec!["ads.example.com", "tracking.example.com"]);
    }

    #[tokio::test]
    async fn should_return_http_status_error_when_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/notfound.txt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/notfound.txt", mock_server.uri());

        let result = loader.load(&url, BlocklistFormat::Domains).await;

        assert!(matches!(
            result,
            Err(RemoteLoadError::HttpStatus { status: 404, .. })
        ));
    }

    #[tokio::test]
    async fn should_return_http_status_error_when_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/error.txt"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/error.txt", mock_server.uri());

        let result = loader.load(&url, BlocklistFormat::Domains).await;

        assert!(matches!(
            result,
            Err(RemoteLoadError::HttpStatus { status: 500, .. })
        ));
    }

    #[tokio::test]
    async fn should_return_network_error_when_connection_refused() {
        let (loader, _temp) = create_loader();
        // Use a port that's unlikely to be in use
        let url = "http://127.0.0.1:1/blocklist.txt";

        let result = loader.load(url, BlocklistFormat::Domains).await;

        assert!(matches!(result, Err(RemoteLoadError::Network { .. })));
    }

    #[tokio::test]
    async fn should_cache_response_on_successful_load() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/blocklist.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string("example.com"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (loader, temp_dir) = create_loader();
        let url = format!("{}/blocklist.txt", mock_server.uri());

        let domains = loader
            .load_cached("test", &url, BlocklistFormat::Domains)
            .await
            .unwrap();

        assert_eq!(domains, vec!["example.com"]);

        // Verify cache file was created
        let cache_path = temp_dir.path().join("test.cache");
        assert!(cache_path.exists());

        let cached_content = std::fs::read_to_string(&cache_path).unwrap();
        assert_eq!(cached_content, "example.com");
    }

    #[tokio::test]
    async fn should_fallback_to_cache_when_remote_fails() {
        let mock_server = MockServer::start().await;

        // First request succeeds
        Mock::given(method("GET"))
            .and(path("/blocklist.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string("example.com"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/blocklist.txt", mock_server.uri());

        // First load populates cache
        let domains = loader
            .load_cached("test", &url, BlocklistFormat::Domains)
            .await
            .unwrap();
        assert_eq!(domains, vec!["example.com"]);

        // Clear mocks and set up failure
        mock_server.reset().await;

        Mock::given(method("GET"))
            .and(path("/blocklist.txt"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Second load should fall back to cache
        let domains = loader
            .load_cached("test", &url, BlocklistFormat::Domains)
            .await
            .unwrap();
        assert_eq!(domains, vec!["example.com"]);
    }

    #[tokio::test]
    async fn should_return_cache_unavailable_when_no_cache_exists() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/blocklist.txt"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/blocklist.txt", mock_server.uri());

        let result = loader
            .load_cached("nonexistent", &url, BlocklistFormat::Domains)
            .await;

        assert!(matches!(result, Err(RemoteLoadError::CacheUnavailable(_))));
    }

    #[tokio::test]
    async fn should_handle_empty_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/empty.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/empty.txt", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Domains).await.unwrap();

        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn should_handle_comments_only_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/comments.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string("# Comment 1\n# Comment 2\n"))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/comments.txt", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Domains).await.unwrap();

        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn should_include_user_agent_header() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/blocklist.txt"))
            .and(wiremock::matchers::header("User-Agent", USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_string("example.com"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/blocklist.txt", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Domains).await.unwrap();

        assert_eq!(domains, vec!["example.com"]);
    }

    #[tokio::test]
    async fn should_handle_redirect_responses() {
        let mock_server = MockServer::start().await;

        // First request redirects
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302)
                    .append_header("Location", format!("{}/actual", mock_server.uri())),
            )
            .mount(&mock_server)
            .await;

        // Actual location
        Mock::given(method("GET"))
            .and(path("/actual"))
            .respond_with(ResponseTemplate::new(200).set_body_string("example.com"))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/redirect", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Domains).await.unwrap();

        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn should_return_default_cache_dir() {
        let cache_dir = default_cache_dir();
        assert!(cache_dir.ends_with("bluebox/blocklists") || cache_dir.ends_with("blocklists"));
    }

    #[tokio::test]
    async fn should_handle_large_response() {
        use std::fmt::Write;

        let mock_server = MockServer::start().await;

        // Generate a large blocklist
        let mut content = String::new();
        for i in 0..10_000 {
            writeln!(content, "domain{i}.example.com").unwrap();
        }

        Mock::given(method("GET"))
            .and(path("/large.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string(content))
            .mount(&mock_server)
            .await;

        let (loader, _temp) = create_loader();
        let url = format!("{}/large.txt", mock_server.uri());

        let domains = loader.load(&url, BlocklistFormat::Domains).await.unwrap();

        assert_eq!(domains.len(), 10_000);
        assert_eq!(domains[0], "domain0.example.com");
        assert_eq!(domains[9999], "domain9999.example.com");
    }
}
