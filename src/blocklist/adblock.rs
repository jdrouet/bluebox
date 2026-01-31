//! `AdBlock` filter syntax parser.
//!
//! Parses basic `AdBlock` Plus filter syntax to extract domain patterns.
//! This is a simplified implementation that focuses on domain-level blocking.

use std::io::BufRead;

use super::{BlocklistParser, ParseError};

/// Parser for `AdBlock` filter syntax.
///
/// # Supported Syntax
///
/// - `||domain.com^` - Block domain and all subdomains
/// - Comments starting with `!`
/// - Empty lines
///
/// # Unsupported (Ignored)
///
/// - Exception rules (`@@||domain^`)
/// - Complex rules with modifiers (`||domain^$third-party`)
/// - Element hiding rules (`##.ad-class`)
/// - URL pattern rules (`/ads/*`)
///
/// # Example
///
/// ```text
/// ! Comment
/// ||ads.example.com^
/// ||tracker.example.com^$third-party
/// @@||allowed.example.com^
/// ```
///
/// Only `ads.example.com` would be extracted from the above.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdBlockParser;

impl BlocklistParser for AdBlockParser {
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

            // Skip comments (AdBlock uses ! for comments)
            if trimmed.starts_with('!') {
                continue;
            }

            // Skip exception rules
            if trimmed.starts_with("@@") {
                continue;
            }

            // Skip element hiding rules
            if trimmed.contains("##") || trimmed.contains("#@#") || trimmed.contains("#?#") {
                continue;
            }

            // Parse domain blocking rules: ||domain^
            if let Some(domain) = parse_domain_rule(trimmed) {
                domains.push(domain);
            }
        }

        Ok(domains)
    }
}

/// Parse a domain blocking rule and extract the domain.
///
/// Handles rules like:
/// - `||example.com^`
/// - `||example.com^$third-party`
/// - `||example.com^|`
fn parse_domain_rule(rule: &str) -> Option<String> {
    // Must start with ||
    let rest = rule.strip_prefix("||")?;

    // Find the domain part (ends at ^ or $ or | or end of string)
    let domain_end = rest.find(['^', '$', '|', '/']).unwrap_or(rest.len());

    let domain = &rest[..domain_end];

    // Validate: must have at least one dot (to filter out invalid entries)
    // and not be empty
    if domain.is_empty() || !domain.contains('.') {
        return None;
    }

    // Skip domains that contain invalid characters for our use case
    // (we only want pure domain names, not regex patterns)
    if domain.contains('*') && !domain.starts_with("*.") {
        return None;
    }

    // Handle wildcard subdomains (||*.example.com^)
    // Convert to our wildcard format
    if let Some(stripped) = domain.strip_prefix("*.") {
        return Some(format!("*.{stripped}"));
    }

    Some(domain.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn parse(content: &str) -> Result<Vec<String>, ParseError> {
        AdBlockParser.parse(&mut BufReader::new(content.as_bytes()))
    }

    #[test]
    fn should_parse_simple_domain_rule() {
        let content = "||ads.example.com^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_parse_multiple_rules() {
        let content = "||ads.example.com^\n||tracker.example.org^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.org"]);
    }

    #[test]
    fn should_skip_comments_starting_with_exclamation() {
        let content = "! This is a comment\n||ads.example.com^\n! Another comment";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_skip_exception_rules() {
        let content = "||ads.example.com^\n@@||allowed.example.com^\n||tracker.example.com^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn should_extract_domain_from_rules_with_modifiers() {
        let content = "||ads.example.com^$third-party\n||tracker.example.com^$script,image";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn should_handle_rules_with_pipe_ending() {
        let content = "||ads.example.com^|";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_return_empty_vec_when_file_is_empty() {
        let content = "";
        let domains = parse(content).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn should_return_empty_vec_when_file_contains_only_comments() {
        let content = "! Comment 1\n! Comment 2\n! Title: Some Filter List";
        let domains = parse(content).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn should_skip_empty_lines() {
        let content = "||ads.example.com^\n\n\n||tracker.example.com^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn should_skip_element_hiding_rules() {
        let content = "||ads.example.com^\nexample.com##.ad-banner\n##.ad-class";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_skip_element_hiding_exceptions() {
        let content = "||ads.example.com^\nexample.com#@#.ad-banner";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_skip_extended_css_rules() {
        let content = "||ads.example.com^\nexample.com#?#.ad-banner:-abp-has(.sponsor)";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_skip_url_pattern_rules() {
        let content = "||ads.example.com^\n/ads/*\n|http://example.com/ads";
        let domains = parse(content).unwrap();
        // URL patterns without || are not parsed
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_skip_invalid_domain_rules() {
        let content = "||^\n||\n||nodot^\n||ads.example.com^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_preserve_wildcard_subdomains() {
        let content = "||*.ads.example.com^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["*.ads.example.com"]);
    }

    #[test]
    fn should_skip_complex_wildcards_in_middle() {
        // Wildcards in the middle are not supported
        let content = "||ads*.example.com^\n||ads.example.com^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_parse_adguard_dns_filter_format() {
        let content = r"
! Title: AdGuard DNS filter
! Description: Filter composed of several other filters
! Homepage: https://github.com/AdguardTeam/AdGuardSDNSFilter
! License: https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE

||ads.example.com^
||tracker.example.net^$important
||analytics.example.org^$third-party,important
@@||stats.example.com^
||malware.example.com^
";
        let domains = parse(content).unwrap();
        assert_eq!(
            domains,
            vec![
                "ads.example.com",
                "tracker.example.net",
                "analytics.example.org",
                "malware.example.com"
            ]
        );
    }

    #[test]
    fn should_parse_easylist_format() {
        let content = r"
[Adblock Plus 2.0]
! Title: EasyList
! Last modified: 01 Jan 2024
! Homepage: https://easylist.to/

||pagead2.googlesyndication.com^
||securepubads.g.doubleclick.net^
||ad.doubleclick.net^
||googleads.g.doubleclick.net^$third-party
";
        let domains = parse(content).unwrap();
        assert_eq!(
            domains,
            vec![
                "pagead2.googlesyndication.com",
                "securepubads.g.doubleclick.net",
                "ad.doubleclick.net",
                "googleads.g.doubleclick.net"
            ]
        );
    }

    #[test]
    fn should_trim_whitespace_from_rules() {
        let content = "  ||ads.example.com^  \n\t||tracker.example.com^\t";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn should_handle_windows_line_endings() {
        let content = "||ads.example.com^\r\n||tracker.example.com^\r\n";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn should_extract_domain_from_various_rule_formats() {
        assert_eq!(
            parse_domain_rule("||example.com^"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_domain_rule("||example.com^$third-party"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_domain_rule("||example.com^|"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_domain_rule("||example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(parse_domain_rule("||^"), None);
        assert_eq!(parse_domain_rule("||nodot^"), None);
        assert_eq!(parse_domain_rule("example.com"), None);
        assert_eq!(parse_domain_rule(""), None);
    }

    #[test]
    fn should_extract_domain_from_rules_with_path() {
        // Rules with paths should extract just the domain
        let content = "||ads.example.com/tracking/pixel.gif^";
        let domains = parse(content).unwrap();
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn should_skip_header_lines() {
        // Various header formats used by different lists
        let content = r"
[Adblock Plus 2.0]
[uBlock Origin]
! Checksum: abc123
||ads.example.com^
";
        let domains = parse(content).unwrap();
        // Header lines starting with [ are not valid rules
        assert_eq!(domains, vec!["ads.example.com"]);
    }
}
