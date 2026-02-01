//! File-based blocklist loader.
//!
//! This module provides functionality to load blocklists from local files
//! on the filesystem.

use std::io::BufReader;
use std::path::{Path, PathBuf};

use tokio::fs::File;
use tokio::io::AsyncReadExt;

use super::{ParseError, parser_for_format};
use crate::config::BlocklistFormat;

/// Error type for blocklist file loading operations.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// File was not found at the specified path.
    #[error("file not found: {0:?}")]
    NotFound(PathBuf),

    /// Permission denied when accessing the file.
    #[error("permission denied: {0:?}")]
    PermissionDenied(PathBuf),

    /// I/O error while reading the file.
    #[error("I/O error reading {path:?}")]
    Io {
        /// Path to the file that caused the error.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Error parsing the blocklist content.
    #[error("parse error")]
    Parse(#[from] ParseError),

    /// Task join error from spawning a blocking task.
    #[error("task join error")]
    Join(#[from] tokio::task::JoinError),
}

/// Loads blocklists from local files.
pub struct FileLoader;

impl FileLoader {
    /// Load a blocklist from a local file.
    ///
    /// This function reads the file asynchronously and parses it using the
    /// appropriate parser for the given format. Large files are parsed in
    /// a blocking task to avoid blocking the async runtime.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the blocklist file
    /// * `format` - Format of the blocklist file
    ///
    /// # Returns
    ///
    /// A vector of domain patterns extracted from the file.
    ///
    /// # Errors
    ///
    /// Returns a [`LoadError`] if:
    /// - The file does not exist ([`LoadError::NotFound`])
    /// - Permission is denied ([`LoadError::PermissionDenied`])
    /// - An I/O error occurs ([`LoadError::Io`])
    /// - The file content cannot be parsed ([`LoadError::Parse`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use bluebox::blocklist::loader::FileLoader;
    /// use bluebox::config::BlocklistFormat;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let domains = FileLoader::load(
    ///     Path::new("/etc/bluebox/blocklist.txt"),
    ///     BlocklistFormat::Domains,
    /// ).await?;
    /// println!("Loaded {} domains", domains.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load(path: &Path, format: BlocklistFormat) -> Result<Vec<String>, LoadError> {
        let path_buf = path.to_path_buf();

        // Open the file asynchronously
        let mut file = File::open(path).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => LoadError::NotFound(path_buf.clone()),
            std::io::ErrorKind::PermissionDenied => LoadError::PermissionDenied(path_buf.clone()),
            _ => LoadError::Io {
                path: path_buf.clone(),
                source: e,
            },
        })?;

        // Read the entire file content
        let mut content = String::new();
        file.read_to_string(&mut content)
            .await
            .map_err(|e| LoadError::Io {
                path: path_buf.clone(),
                source: e,
            })?;

        // Parse in a blocking task to avoid blocking the async runtime
        // This is especially important for large files (1M+ lines)
        let domains = tokio::task::spawn_blocking(move || {
            let parser = parser_for_format(format);
            let mut reader = BufReader::new(content.as_bytes());
            parser.parse(&mut reader)
        })
        .await??;

        Ok(domains)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn should_load_domains_format_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Comment").unwrap();
        writeln!(file, "example.com").unwrap();
        writeln!(file, "*.ads.com").unwrap();
        file.flush().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
            .await
            .unwrap();

        assert_eq!(domains, vec!["example.com", "*.ads.com"]);
    }

    #[tokio::test]
    async fn should_load_hosts_format_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Hosts file").unwrap();
        writeln!(file, "0.0.0.0 ads.example.com").unwrap();
        writeln!(file, "127.0.0.1 tracking.example.com").unwrap();
        file.flush().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Hosts)
            .await
            .unwrap();

        assert_eq!(domains, vec!["ads.example.com", "tracking.example.com"]);
    }

    #[tokio::test]
    async fn should_load_adblock_format_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "! AdBlock comment").unwrap();
        writeln!(file, "||ads.example.com^").unwrap();
        writeln!(file, "||tracking.example.com^$third-party").unwrap();
        file.flush().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Adblock)
            .await
            .unwrap();

        assert_eq!(domains, vec!["ads.example.com", "tracking.example.com"]);
    }

    #[tokio::test]
    async fn should_return_empty_vec_when_file_is_empty() {
        let file = NamedTempFile::new().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
            .await
            .unwrap();

        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn should_return_empty_vec_when_file_has_only_comments() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file, "# Another comment").unwrap();
        file.flush().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
            .await
            .unwrap();

        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn should_return_not_found_error_when_file_does_not_exist() {
        let result = FileLoader::load(
            Path::new("/nonexistent/path/to/blocklist.txt"),
            BlocklistFormat::Domains,
        )
        .await;

        assert!(matches!(result, Err(LoadError::NotFound(_))));
    }

    #[tokio::test]
    async fn should_handle_file_with_mixed_line_endings() {
        let mut file = NamedTempFile::new().unwrap();
        // Write with explicit CRLF line endings
        file.write_all(b"example.com\r\ntest.com\n*.ads.com\r\n")
            .unwrap();
        file.flush().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
            .await
            .unwrap();

        assert_eq!(domains, vec!["example.com", "test.com", "*.ads.com"]);
    }

    #[tokio::test]
    async fn should_handle_large_file() {
        let mut file = NamedTempFile::new().unwrap();

        // Write 10,000 domains
        for i in 0..10_000 {
            writeln!(file, "domain{i}.example.com").unwrap();
        }
        file.flush().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
            .await
            .unwrap();

        assert_eq!(domains.len(), 10_000);
        assert_eq!(domains[0], "domain0.example.com");
        assert_eq!(domains[9999], "domain9999.example.com");
    }

    #[tokio::test]
    async fn should_trim_whitespace_from_domains() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  example.com  ").unwrap();
        writeln!(file, "\ttest.com\t").unwrap();
        file.flush().unwrap();

        let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
            .await
            .unwrap();

        assert_eq!(domains, vec!["example.com", "test.com"]);
    }
}
