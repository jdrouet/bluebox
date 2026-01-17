//! Domain blocking with optimized pattern matching.
//!
//! Supports exact domain matches and wildcard patterns (*.example.com).
//! Uses pre-compiled data structures to minimize allocations during lookups.

use std::collections::HashSet;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use std::net::{Ipv4Addr, Ipv6Addr};

/// A compiled blocklist for efficient domain lookups.
///
/// Patterns are pre-processed at construction time to avoid
/// string allocations during the hot path.
#[derive(Debug, Clone)]
pub struct Blocker {
    /// Exact domain matches (stored lowercase, without trailing dot).
    exact: HashSet<String>,
    /// Wildcard suffixes (the part after "*", e.g., ".ads.com").
    wildcard_suffixes: Vec<String>,
}

impl Blocker {
    /// Create a new blocker from a list of patterns.
    ///
    /// Patterns can be:
    /// - Exact matches: "example.com"
    /// - Wildcard matches: "*.example.com" (matches any subdomain)
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut exact = HashSet::new();
        let mut wildcard_suffixes = Vec::new();

        for pattern in patterns {
            let pattern = pattern.as_ref().to_lowercase();
            let pattern = pattern.trim_end_matches('.');

            if let Some(suffix) = pattern.strip_prefix('*') {
                // Wildcard pattern: store the suffix (including the leading dot)
                wildcard_suffixes.push(suffix.to_string());
            } else {
                // Exact match
                exact.insert(pattern.to_string());
            }
        }

        Self {
            exact,
            wildcard_suffixes,
        }
    }

    /// Check if a domain name is blocked.
    ///
    /// This method is designed to minimize allocations:
    /// - Converts the Name to a string once
    /// - Uses string slicing for suffix checks
    #[inline]
    pub fn is_blocked(&self, name: &Name) -> bool {
        let name_str = name.to_utf8().to_lowercase();
        let name_str = name_str.trim_end_matches('.');

        // Check exact match first (O(1) hash lookup)
        if self.exact.contains(name_str) {
            return true;
        }

        // Check wildcard suffixes
        for suffix in &self.wildcard_suffixes {
            if name_str.ends_with(suffix.as_str()) {
                return true;
            }
        }

        false
    }

    /// Check if the blocker has any patterns.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard_suffixes.is_empty()
    }

    /// Returns the total number of patterns.
    #[inline]
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard_suffixes.len()
    }

    /// Create a blocked response for a DNS query.
    ///
    /// Returns localhost addresses:
    /// - A records → 127.0.0.1
    /// - AAAA records → `::1`
    pub fn blocked_response(query: &Message) -> Message {
        let mut response = Message::new();
        response
            .set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);

        // Copy the query section
        for q in query.queries() {
            response.add_query(q.clone());
        }

        // Add answer based on query type
        if let Some(query_record) = query.queries().first() {
            let name = query_record.name().clone();
            let record = match query_record.query_type() {
                RecordType::AAAA => {
                    Record::from_rdata(name, 300, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)))
                }
                _ => Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::LOCALHOST))),
            };
            response.add_answer(record);
        }

        response
    }
}

impl Default for Blocker {
    fn default() -> Self {
        Self::new(std::iter::empty::<&str>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn test_exact_match() {
        let blocker = Blocker::new(["google.com", "facebook.com"]);

        assert!(blocker.is_blocked(&name("google.com")));
        assert!(blocker.is_blocked(&name("facebook.com")));
        assert!(!blocker.is_blocked(&name("twitter.com")));
    }

    #[test]
    fn test_exact_match_case_insensitive() {
        let blocker = Blocker::new(["Google.COM"]);

        assert!(blocker.is_blocked(&name("google.com")));
        assert!(blocker.is_blocked(&name("GOOGLE.COM")));
        assert!(blocker.is_blocked(&name("GoOgLe.CoM")));
    }

    #[test]
    fn test_wildcard_match() {
        let blocker = Blocker::new(["*.ads.com"]);

        assert!(blocker.is_blocked(&name("tracking.ads.com")));
        assert!(blocker.is_blocked(&name("sub.tracking.ads.com")));
        assert!(blocker.is_blocked(&name("a.b.c.ads.com")));
        // Base domain should NOT match wildcard
        assert!(!blocker.is_blocked(&name("ads.com")));
    }

    #[test]
    fn test_wildcard_case_insensitive() {
        let blocker = Blocker::new(["*.ADS.COM"]);

        assert!(blocker.is_blocked(&name("tracking.ads.com")));
        assert!(blocker.is_blocked(&name("TRACKING.ADS.COM")));
    }

    #[test]
    fn test_combined_patterns() {
        let blocker = Blocker::new(["facebook.com", "*.facebook.com", "*.ads.net"]);

        assert!(blocker.is_blocked(&name("facebook.com")));
        assert!(blocker.is_blocked(&name("www.facebook.com")));
        assert!(blocker.is_blocked(&name("api.facebook.com")));
        assert!(blocker.is_blocked(&name("tracking.ads.net")));
        assert!(!blocker.is_blocked(&name("ads.net")));
        assert!(!blocker.is_blocked(&name("google.com")));
    }

    #[test]
    fn test_trailing_dot_handling() {
        let blocker = Blocker::new(["google.com."]);

        assert!(blocker.is_blocked(&name("google.com")));
        assert!(blocker.is_blocked(&name("google.com.")));
    }

    #[test]
    fn test_empty_blocker() {
        let blocker = Blocker::default();

        assert!(blocker.is_empty());
        assert_eq!(blocker.len(), 0);
        assert!(!blocker.is_blocked(&name("google.com")));
    }

    #[test]
    fn test_len() {
        let blocker = Blocker::new(["a.com", "b.com", "*.c.com"]);
        assert_eq!(blocker.len(), 3);
        assert!(!blocker.is_empty());
    }

    #[test]
    fn test_blocked_response_ipv4() {
        let mut query = Message::new();
        query.set_id(1234);
        query.add_query({
            let mut q = hickory_proto::op::Query::new();
            q.set_name(name("blocked.com"));
            q.set_query_type(RecordType::A);
            q
        });

        let response = Blocker::blocked_response(&query);

        assert_eq!(response.id(), 1234);
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        let answer = &response.answers()[0];
        match answer.data() {
            Some(RData::A(a)) => assert_eq!(a.0, Ipv4Addr::LOCALHOST),
            _ => panic!("Expected A record"),
        }
    }

    #[test]
    fn test_blocked_response_ipv6() {
        let mut query = Message::new();
        query.set_id(5678);
        query.add_query({
            let mut q = hickory_proto::op::Query::new();
            q.set_name(name("blocked.com"));
            q.set_query_type(RecordType::AAAA);
            q
        });

        let response = Blocker::blocked_response(&query);

        assert_eq!(response.answers().len(), 1);
        let answer = &response.answers()[0];
        match answer.data() {
            Some(RData::AAAA(aaaa)) => assert_eq!(aaaa.0, Ipv6Addr::LOCALHOST),
            _ => panic!("Expected AAAA record"),
        }
    }
}
