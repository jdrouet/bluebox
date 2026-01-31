//! Hosts file format parser.
//!
//! Parses standard `/etc/hosts` format files commonly used by blocklists
//! like Steven Black's hosts file.

use std::io::BufRead;

use super::{BlocklistParser, ParseError};

/// Parser for hosts file format.
///
/// # Format
///
/// Standard `/etc/hosts` format:
/// - `<ip> <domain1> [domain2] [domain3]...`
/// - Comments start with `#`
/// - Empty lines are ignored
///
/// # Extraction Rules
///
/// - Only extracts domains from lines with `0.0.0.0` or `127.0.0.1` IP
/// - Handles multiple domains per line
/// - Ignores `localhost`, `localhost.localdomain`, `local`, `broadcasthost`
/// - Ignores entries that look like IP addresses (e.g., `0.0.0.0`)
///
/// # Example
///
/// ```text
/// # Comment line
/// 127.0.0.1 localhost
/// 0.0.0.0 ads.example.com tracker.example.com
/// 0.0.0.0 bad-site.org
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HostsFileParser;

/// Domains to ignore (system entries).
const IGNORED_DOMAINS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// IP addresses that indicate a blocked domain.
const BLOCK_IPS: &[&str] = &["0.0.0.0", "127.0.0.1"];

impl BlocklistParser for HostsFileParser {
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

            // Remove inline comments
            let line_without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
            if line_without_comment.is_empty() {
                continue;
            }

            // Parse the line: <ip> <domain1> [domain2] ...
            let parts: Vec<&str> = line_without_comment.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let ip = parts[0];

            // Only process lines with blocking IPs
            if !BLOCK_IPS.contains(&ip) {
                continue;
            }

            // Extract domains (skip the IP)
            for domain in &parts[1..] {
                let domain = *domain;

                // Skip ignored system domains
                if IGNORED_DOMAINS.contains(&domain.to_lowercase().as_str()) {
                    continue;
                }

                // Skip entries that look like IP addresses
                if is_ip_like(domain) {
                    continue;
                }

                domains.push(domain.to_string());
            }
        }

        Ok(domains)
    }
}

/// Check if a string looks like an IP address.
fn is_ip_like(s: &str) -> bool {
    // Simple check: all parts are numeric and separated by dots
    if s.is_empty() {
        return false;
    }

    // Check for IPv6-like pattern (contains colons)
    if s.contains(':') {
        return true;
    }

    // Check for IP-like pattern: all parts are numeric
    // This covers IPv4 (4 parts) and malformed entries like "0.0.0.0.0.0.0.0"
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() >= 2 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn parse(content: &str) -> Result<Vec<String>, ParseError> {
        HostsFileParser.parse(&mut BufReader::new(content.as_bytes()))
    }

    #[test]
    fn test_simple_hosts() {
        let content = "0.0.0.0 ads.example.com";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_multiple_domains_per_line() {
        let content = "0.0.0.0 ads.example.com tracker.example.com";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_127_ip() {
        let content = "127.0.0.1 ads.example.com";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_comments() {
        let content = "# Comment\n0.0.0.0 ads.example.com\n# Another comment";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_inline_comments() {
        let content = "0.0.0.0 ads.example.com # This is an inline comment";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_ignores_localhost() {
        let content = "127.0.0.1 localhost\n0.0.0.0 ads.example.com";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_ignores_all_system_domains() {
        let content = r"
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
0.0.0.0 broadcasthost
127.0.0.1 ip6-localhost
127.0.0.1 ip6-loopback
0.0.0.0 ads.example.com
";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_ignores_non_blocking_ips() {
        let content = r"
192.168.1.1 router.local
10.0.0.1 server.local
0.0.0.0 ads.example.com
";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_ignores_ip_like_entries() {
        let content = r"
0.0.0.0 0.0.0.0
0.0.0.0 0.0.0.0.0.0.0.0
0.0.0.0 ads.example.com
";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_empty_file() {
        let content = "";
        let domains = parse(content).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_only_comments() {
        let content = "# Comment 1\n# Comment 2";
        let domains = parse(content).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_empty_lines() {
        let content = "0.0.0.0 ads.example.com\n\n\n0.0.0.0 tracker.example.com";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_whitespace_variations() {
        let content = "  0.0.0.0   ads.example.com   tracker.example.com  ";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_tabs() {
        let content = "0.0.0.0\tads.example.com\ttracker.example.com";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_steven_black_sample() {
        let content = r"
# Title: StevenBlack/hosts
# Date: 2024-01-01
# Number of unique domains: 1000000
#
# This hosts file is a merged collection
# ==========================================

127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 localhost ip6-localhost ip6-loopback
fe80::1%lo0 localhost
ff00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

# Start of blocklist
0.0.0.0 0.0.0.0
0.0.0.0 0.0.0.0.0.0.0.0
0.0.0.0 1-1ads.com
0.0.0.0 101com.com 101order.com
0.0.0.0 123found.com
";
        let domains = parse(content).unwrap();
        assert!(domains.contains(&"1-1ads.com".to_string()));
        assert!(domains.contains(&"101com.com".to_string()));
        assert!(domains.contains(&"101order.com".to_string()));
        assert!(domains.contains(&"123found.com".to_string()));
        assert!(!domains.contains(&"0.0.0.0".to_string()));
        assert!(!domains.contains(&"localhost".to_string()));
        assert_eq!(domains.len(), 4);
    }

    #[test]
    fn test_malformed_lines() {
        let content = r"
0.0.0.0
just-a-domain.com
0.0.0.0 ads.example.com
incomplete
";
        let domains = parse(content).unwrap();
        // Only the valid line should be parsed
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_case_insensitive_localhost() {
        let content = "127.0.0.1 LOCALHOST\n127.0.0.1 LocalHost\n0.0.0.0 ads.example.com";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_windows_line_endings() {
        let content = "0.0.0.0 ads.example.com\r\n0.0.0.0 tracker.example.com\r\n";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_is_ip_like() {
        assert!(is_ip_like("0.0.0.0"));
        assert!(is_ip_like("127.0.0.1"));
        assert!(is_ip_like("192.168.1.1"));
        assert!(is_ip_like("::1"));
        assert!(is_ip_like("fe80::1"));
        assert!(!is_ip_like("example.com"));
        assert!(!is_ip_like("ads.example.com"));
        assert!(!is_ip_like("1-1ads.com"));
        assert!(!is_ip_like(""));
    }

    #[test]
    fn test_real_world_dan_pollock() {
        // Sample from Dan Pollock's hosts file format
        let content = r"
# This hosts file is brought to you by Dan Pollock
# site: http://someonewhocares.org/hosts/
# Use this file to prevent your computer from connecting to selected
# internet hosts.

127.0.0.1  localhost
127.0.0.1  localhost.localdomain

# [ad sites]
127.0.0.1  ads.example.com
127.0.0.1  banner.example.com  popup.example.com

# [tracking sites]
127.0.0.1  tracker.example.org
";
        let domains = parse(content).unwrap();
        assert_eq!(
            domains,
            vec![
                "ads.example.com",
                "banner.example.com",
                "popup.example.com",
                "tracker.example.org"
            ]
        );
    }

    #[test]
    fn test_ipv6_entries_ignored() {
        let content = r"
::1 localhost
fe80::1%lo0 localhost
0.0.0.0 ads.example.com
";
        let domains = parse(content).unwrap();
        // IPv6 entries are not in BLOCK_IPS so they're ignored
        assert_eq!(domains, vec!["ads.example.com"]);
    }
}
