//! Domain list format parser.
//!
//! Parses simple blocklist files with one domain per line.
//! Comments start with `#` and are ignored.

use std::io::BufRead;

use super::{BlocklistParser, ParseError};

/// Parser for simple domain list format.
///
/// # Format
///
/// - One domain per line
/// - Comments start with `#`
/// - Empty lines are ignored
/// - Whitespace is trimmed
/// - Wildcards are supported (e.g., `*.example.com`)
///
/// # Example
///
/// ```text
/// # This is a comment
/// example.com
/// *.ads.example.com
/// another-domain.org
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainListParser;

impl BlocklistParser for DomainListParser {
    fn parse(&self, reader: &mut dyn BufRead) -> Result<Vec<String>, ParseError> {
        let mut domains = Vec::new();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break;
            }

            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Skip comments
            if trimmed.starts_with('#') {
                continue;
            }

            // Add the domain
            domains.push(trimmed.to_string());
        }

        Ok(domains)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn parse(content: &str) -> Result<Vec<String>, ParseError> {
        DomainListParser.parse(&mut BufReader::new(content.as_bytes()))
    }

    #[test]
    fn test_simple_domains() {
        let content = "example.com\ntest.org\nanother.net";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["example.com", "test.org", "another.net"]);
    }

    #[test]
    fn test_with_comments() {
        let content = "# Comment line\nexample.com\n# Another comment\ntest.org";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["example.com", "test.org"]);
    }

    #[test]
    fn test_empty_lines() {
        let content = "example.com\n\n\ntest.org\n\n";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["example.com", "test.org"]);
    }

    #[test]
    fn test_whitespace_trimming() {
        let content = "  example.com  \n\ttest.org\t\n  another.net";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["example.com", "test.org", "another.net"]);
    }

    #[test]
    fn test_wildcard_domains() {
        let content = "*.example.com\n*.ads.test.org";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["*.example.com", "*.ads.test.org"]);
    }

    #[test]
    fn test_mixed_content() {
        let content = r"
# Blocklist for ads
example.com
*.ads.example.com

# Trackers
tracker.example.org
";
        let domains = parse(content).unwrap();
        assert_eq!(
            domains,
            vec!["example.com", "*.ads.example.com", "tracker.example.org"]
        );
    }

    #[test]
    fn test_empty_file() {
        let content = "";
        let domains = parse(content).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_only_comments() {
        let content = "# Comment 1\n# Comment 2\n# Comment 3";
        let domains = parse(content).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_only_empty_lines() {
        let content = "\n\n\n\n";
        let domains = parse(content).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_comment_with_space() {
        let content = "  # Indented comment\nexample.com";
        let domains = parse(content).unwrap();
        // Trimmed line starts with #, so it's a comment
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_inline_content_preserved() {
        // Domain with hash that's not at the start (not treated as comment)
        let content = "example.com#not-a-comment";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["example.com#not-a-comment"]);
    }

    #[test]
    fn test_subdomain_patterns() {
        let content = "ads.facebook.com\ntrack.google.com\n*.doubleclick.net";
        let domains = parse(content).unwrap();
        assert_eq!(
            domains,
            vec!["ads.facebook.com", "track.google.com", "*.doubleclick.net"]
        );
    }

    #[test]
    fn test_real_world_sample() {
        // Sample from common blocklists
        let content = r"
# Title: Personal blocklist
# Last updated: 2024-01-01

# Ads
ads.example.com
*.advertising.com

# Trackers
tracker1.example.org
tracker2.example.org

# Social media trackers
*.facebook.net
pixel.facebook.com
";
        let domains = parse(content).unwrap();
        assert_eq!(domains.len(), 6);
        assert!(domains.contains(&"ads.example.com".to_string()));
        assert!(domains.contains(&"*.advertising.com".to_string()));
        assert!(domains.contains(&"*.facebook.net".to_string()));
    }

    #[test]
    fn test_windows_line_endings() {
        let content = "example.com\r\ntest.org\r\n";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["example.com", "test.org"]);
    }

    #[test]
    fn test_mixed_line_endings() {
        let content = "example.com\ntest.org\r\nanother.net\r";
        let domains = parse(content).unwrap();
        // Note: \r alone doesn't create a new line in BufRead, it becomes part of the string
        // The last entry will have \r attached
        assert!(domains.len() >= 2);
        assert_eq!(domains[0], "example.com");
        assert_eq!(domains[1], "test.org");
    }
}
