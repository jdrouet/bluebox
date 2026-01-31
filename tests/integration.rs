//! Integration tests for the DNS server.
//!
//! These tests verify the complete query handling flow using mock components.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use bluebox::cache::{DnsCache, MokaCache};
use bluebox::dns::{Blocker, DnsResolver};
use bluebox::network::BufferPool;
use bluebox::server::QueryHandler;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

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
    match answer.data() {
        Some(RData::A(a)) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        _ => panic!("Expected A record"),
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
    match answer.data() {
        Some(RData::A(a)) => assert_eq!(a.0, Ipv4Addr::LOCALHOST),
        _ => panic!("Expected A record pointing to localhost"),
    }

    // Test wildcard block
    let query = create_query("tracking.ads.net", RecordType::A, 101);
    let response = handler.handle_query(query).await.unwrap();

    let answer = &response.answers()[0];
    match answer.data() {
        Some(RData::A(a)) => assert_eq!(a.0, Ipv4Addr::LOCALHOST),
        _ => panic!("Expected A record pointing to localhost"),
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
    match response_a.answers()[0].data() {
        Some(RData::A(a)) => assert_eq!(a.0, Ipv4Addr::LOCALHOST),
        _ => panic!("Expected A record"),
    }

    // AAAA record for blocked domain
    let query_aaaa = create_query("blocked.com", RecordType::AAAA, 2);
    let response_aaaa = handler.handle_query(query_aaaa).await.unwrap();
    match response_aaaa.answers()[0].data() {
        Some(RData::AAAA(aaaa)) => assert_eq!(aaaa.0, std::net::Ipv6Addr::LOCALHOST),
        _ => panic!("Expected AAAA record"),
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
