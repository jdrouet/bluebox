//! Integration tests for the DNS server.
//!
//! These tests verify the complete query handling flow using mock components.

use std::io::Write;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use bluebox::blocklist::loader::FileLoader;
use bluebox::cache::{DnsCache, MokaCache};
use bluebox::config::BlocklistFormat;
use bluebox::dns::{Blocker, DnsResolver};
use bluebox::network::BufferPool;
use bluebox::server::QueryHandler;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tempfile::NamedTempFile;

/// Helper to create a DNS query message.
fn create_query(domain: &str, query_type: RecordType, id: u16) -> Message {
    let name = Name::from_str(domain).unwrap();
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(query_type);

    let mut message = Message::new();
    message.set_id(id);
    message.add_query(query);
    message
}

/// Mock resolver that returns configurable responses.
#[derive(Clone)]
struct TestResolver {
    default_ip: Ipv4Addr,
}

impl TestResolver {
    const fn new(ip: Ipv4Addr) -> Self {
        Self { default_ip: ip }
    }
}

impl DnsResolver for TestResolver {
    async fn resolve(&self, query: &Message) -> bluebox::Result<Message> {
        let q = query.queries().first().unwrap();
        let name = q.name();

        let mut response = Message::new();
        response
            .set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);

        let record = Record::from_rdata(name.clone(), 300, RData::A(A(self.default_ip)));
        response.add_answer(record);

        Ok(response)
    }
}

#[tokio::test]
async fn should_resolve_allowed_domain_from_upstream() {
    let cache = MokaCache::new(Duration::from_secs(60));
    let resolver = TestResolver::new(Ipv4Addr::new(93, 184, 216, 34));
    let blocker = Blocker::new(["blocked.com"]);

    let handler = QueryHandler::new(cache, resolver, blocker);

    let query = create_query("example.com", RecordType::A, 1234);
    let response = handler.handle_query(query).await.unwrap();

    assert_eq!(response.id(), 1234);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers().len(), 1);

    let answer = &response.answers()[0];
    if let Some(a) = answer.data().as_a() {
        assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34));
    } else {
        panic!("Expected A record");
    }
}

#[tokio::test]
async fn should_return_localhost_for_blocked_domains() {
    let cache = MokaCache::new(Duration::from_secs(60));
    let resolver = TestResolver::new(Ipv4Addr::new(1, 2, 3, 4));
    let blocker = Blocker::new(["blocked.com", "*.ads.net"]);

    let handler = QueryHandler::new(cache, resolver, blocker);

    // Test exact block
    let query = create_query("blocked.com", RecordType::A, 100);
    let response = handler.handle_query(query).await.unwrap();

    assert_eq!(response.response_code(), ResponseCode::NoError);
    let answer = &response.answers()[0];
    if let Some(a) = answer.data().as_a() {
        assert_eq!(a.0, Ipv4Addr::LOCALHOST);
    } else {
        panic!("Expected A record pointing to localhost")
    }

    // Test wildcard block
    let query = create_query("tracking.ads.net", RecordType::A, 101);
    let response = handler.handle_query(query).await.unwrap();

    let answer = &response.answers()[0];
    if let Some(a) = answer.data().as_a() {
        assert_eq!(a.0, Ipv4Addr::LOCALHOST);
    } else {
        panic!("Expected A record pointing to localhost")
    }
}

#[tokio::test]
async fn should_cache_responses_and_update_query_id() {
    let cache = MokaCache::new(Duration::from_secs(60));
    let resolver = TestResolver::new(Ipv4Addr::new(1, 2, 3, 4));
    let blocker = Blocker::default();

    let handler = QueryHandler::new(cache.clone(), resolver, blocker);

    // First query - cache miss
    let query1 = create_query("example.com", RecordType::A, 1);
    let response1 = handler.handle_query(query1).await.unwrap();
    assert_eq!(response1.id(), 1);

    // Second query - should be cache hit with different ID
    let query2 = create_query("example.com", RecordType::A, 2);
    let response2 = handler.handle_query(query2).await.unwrap();
    assert_eq!(response2.id(), 2); // ID should match the query, not the cached response

    // Verify cache hit by checking we can get the cached value directly
    let name = Name::from_str("example.com").unwrap();
    let cached = cache.get(&name).await;
    assert!(cached.is_some(), "Cache should contain the entry");
}

#[tokio::test]
async fn should_return_correct_localhost_for_each_query_type() {
    let cache = MokaCache::new(Duration::from_secs(60));
    let resolver = TestResolver::new(Ipv4Addr::new(1, 2, 3, 4));
    let blocker = Blocker::new(["blocked.com"]);

    let handler = QueryHandler::new(cache, resolver, blocker);

    // A record for blocked domain
    let query_a = create_query("blocked.com", RecordType::A, 1);
    let response_a = handler.handle_query(query_a).await.unwrap();
    if let Some(a) = response_a.answers()[0].data().as_a() {
        assert_eq!(a.0, Ipv4Addr::LOCALHOST);
    } else {
        panic!("Expected A record");
    }

    // AAAA record for blocked domain
    let query_aaaa = create_query("blocked.com", RecordType::AAAA, 2);
    let response_aaaa = handler.handle_query(query_aaaa).await.unwrap();
    if let Some(aaaa) = response_aaaa.answers()[0].data().as_aaaa() {
        assert_eq!(aaaa.0, std::net::Ipv6Addr::LOCALHOST);
    } else {
        panic!("Expected AAAA record")
    }
}

#[tokio::test]
async fn should_manage_buffer_pool_correctly() {
    let pool = BufferPool::new(4);

    // Get multiple buffers
    let mut buf1 = pool.get_zeroed(100);
    let mut buf2 = pool.get_zeroed(200);

    assert_eq!(pool.available(), 2);

    // Use the buffers
    buf1.as_mut_slice()[0] = 42;
    buf2.as_mut_slice()[0] = 43;

    // Return buffers
    drop(buf1);
    assert_eq!(pool.available(), 3);

    drop(buf2);
    assert_eq!(pool.available(), 4);
}

#[tokio::test]
async fn should_load_blocklist_file_and_block_domains() {
    // Create a temporary blocklist file
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "# My custom blocklist").unwrap();
    writeln!(file, "ads.example.com").unwrap();
    writeln!(file, "tracking.example.com").unwrap();
    writeln!(file, "*.malware.net").unwrap();
    file.flush().unwrap();

    // Load the blocklist using FileLoader
    let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
        .await
        .unwrap();

    // Create a blocker with the loaded domains
    let blocker = Blocker::new(&domains);

    // Verify exact matches are blocked
    assert!(blocker.is_blocked(&Name::from_str("ads.example.com").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("tracking.example.com").unwrap()));

    // Verify wildcard matches work
    assert!(blocker.is_blocked(&Name::from_str("test.malware.net").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("deep.nested.malware.net").unwrap()));

    // Verify non-blocked domains are allowed
    assert!(!blocker.is_blocked(&Name::from_str("example.com").unwrap()));
    assert!(!blocker.is_blocked(&Name::from_str("safe.example.org").unwrap()));
}

#[tokio::test]
async fn should_load_hosts_file_and_block_domains() {
    // Create a temporary hosts-style blocklist file
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "# Steven Black style hosts file").unwrap();
    writeln!(file, "127.0.0.1 localhost").unwrap();
    writeln!(file, "0.0.0.0 ads.doubleclick.net").unwrap();
    writeln!(file, "0.0.0.0 tracking.google-analytics.com").unwrap();
    writeln!(file, "127.0.0.1 facebook-ads.com # inline comment").unwrap();
    file.flush().unwrap();

    // Load the blocklist using FileLoader
    let domains = FileLoader::load(file.path(), BlocklistFormat::Hosts)
        .await
        .unwrap();

    // Create a blocker with the loaded domains
    let blocker = Blocker::new(&domains);

    // Verify blocked domains
    assert!(blocker.is_blocked(&Name::from_str("ads.doubleclick.net").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("tracking.google-analytics.com").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("facebook-ads.com").unwrap()));

    // Verify localhost is not included (system domain)
    assert!(!blocker.is_blocked(&Name::from_str("localhost").unwrap()));
}

#[tokio::test]
async fn should_merge_multiple_blocklist_sources() {
    // Simulate loading multiple blocklist files and merging them
    let mut file1 = NamedTempFile::new().unwrap();
    writeln!(file1, "ads.example1.com").unwrap();
    writeln!(file1, "tracking.example1.com").unwrap();
    file1.flush().unwrap();

    let mut file2 = NamedTempFile::new().unwrap();
    writeln!(file2, "0.0.0.0 ads.example2.com").unwrap();
    writeln!(file2, "0.0.0.0 tracking.example2.com").unwrap();
    file2.flush().unwrap();

    let mut file3 = NamedTempFile::new().unwrap();
    writeln!(file3, "||ads.example3.com^").unwrap();
    writeln!(file3, "||tracking.example3.com^").unwrap();
    file3.flush().unwrap();

    // Load all blocklists
    let domains1 = FileLoader::load(file1.path(), BlocklistFormat::Domains)
        .await
        .unwrap();
    let domains2 = FileLoader::load(file2.path(), BlocklistFormat::Hosts)
        .await
        .unwrap();
    let domains3 = FileLoader::load(file3.path(), BlocklistFormat::Adblock)
        .await
        .unwrap();

    // Merge all domains (simulating what main.rs does)
    let mut all_domains = Vec::new();
    all_domains.extend(domains1);
    all_domains.extend(domains2);
    all_domains.extend(domains3);

    // Create a blocker with all merged domains
    let blocker = Blocker::new(&all_domains);

    // Verify domains from all sources are blocked
    assert!(blocker.is_blocked(&Name::from_str("ads.example1.com").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("tracking.example1.com").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("ads.example2.com").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("tracking.example2.com").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("ads.example3.com").unwrap()));
    assert!(blocker.is_blocked(&Name::from_str("tracking.example3.com").unwrap()));

    // Verify the total count
    assert_eq!(blocker.len(), 6);
}

#[tokio::test]
async fn should_handle_query_with_file_loaded_blocklist() {
    // Create a blocklist file
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "blocked-from-file.example.com").unwrap();
    writeln!(file, "*.ads-from-file.net").unwrap();
    file.flush().unwrap();

    // Load the blocklist
    let domains = FileLoader::load(file.path(), BlocklistFormat::Domains)
        .await
        .unwrap();

    // Set up the query handler with the loaded blocklist
    let cache = MokaCache::new(Duration::from_secs(60));
    let resolver = TestResolver::new(Ipv4Addr::new(93, 184, 216, 34));
    let blocker = Blocker::new(&domains);

    let handler = QueryHandler::new(cache, resolver, blocker);

    // Query a blocked domain - should return localhost
    let query = create_query("blocked-from-file.example.com", RecordType::A, 1);
    let response = handler.handle_query(query).await.unwrap();

    assert_eq!(response.response_code(), ResponseCode::NoError);
    if let Some(a) = response.answers()[0].data().as_a() {
        assert_eq!(a.0, Ipv4Addr::LOCALHOST);
    } else {
        panic!("Expected A record pointing to localhost");
    }

    // Query a wildcard-blocked domain - should return localhost
    let query = create_query("tracking.ads-from-file.net", RecordType::A, 2);
    let response = handler.handle_query(query).await.unwrap();

    if let Some(a) = response.answers()[0].data().as_a() {
        assert_eq!(a.0, Ipv4Addr::LOCALHOST);
    } else {
        panic!("Expected A record pointing to localhost");
    }

    // Query an allowed domain - should return the resolved IP
    let query = create_query("allowed.example.com", RecordType::A, 3);
    let response = handler.handle_query(query).await.unwrap();

    if let Some(a) = response.answers()[0].data().as_a() {
        assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34));
    } else {
        panic!("Expected A record from resolver");
    }
}
