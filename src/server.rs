//! DNS server orchestration.
//!
//! Coordinates packet capture, DNS resolution, caching, and response sending.
//! Designed with trait-based dependencies for testability.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use metrics::counter;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{info, instrument, warn};

use crate::cache::DnsCache;
use crate::dns::{Blocker, DnsResolver};
use crate::error::Result;
use crate::network::{BufferPool, PacketBuilder, PacketInfo, PacketSender, extract_dns_query};

/// Statistics for server operations.
#[derive(Debug, Default)]
pub struct ServerStats {
    pub queries_received: u64,
    pub queries_blocked: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub responses_sent: u64,
    pub errors: u64,
}

/// DNS query handler that processes queries using the provided dependencies.
///
/// This struct encapsulates the core DNS handling logic, separated from
/// the network capture layer for easier testing.
///
/// The blocker is wrapped in `Arc<RwLock<Blocker>>` to support hot-reloading
/// of blocklists without restarting the server.
pub struct QueryHandler<C, R>
where
    C: DnsCache,
    R: DnsResolver,
{
    cache: C,
    resolver: R,
    blocker: Arc<RwLock<Blocker>>,
}

impl<C, R> QueryHandler<C, R>
where
    C: DnsCache,
    R: DnsResolver,
{
    /// Create a new query handler with an owned blocker.
    ///
    /// This is convenient for testing or when you don't need hot-reloading.
    pub fn new(cache: C, resolver: R, blocker: Blocker) -> Self {
        Self {
            cache,
            resolver,
            blocker: Arc::new(RwLock::new(blocker)),
        }
    }

    /// Create a new query handler with a shared blocker.
    ///
    /// Use this when integrating with [`BlocklistManager`](crate::blocklist::manager::BlocklistManager)
    /// to enable hot-reloading of blocklists.
    #[must_use]
    pub const fn with_shared_blocker(cache: C, resolver: R, blocker: Arc<RwLock<Blocker>>) -> Self {
        Self {
            cache,
            resolver,
            blocker,
        }
    }

    /// Handle a DNS query and return the response.
    #[instrument(skip(self, query), fields(domain))]
    pub async fn handle_query(&self, query: Message) -> Result<Message> {
        let Some(query_record) = query.queries().first() else {
            warn!("Query has no questions");
            return Ok(query);
        };

        let name = query_record.name();
        let query_type = query_record.query_type().to_string();
        tracing::Span::current().record("domain", name.to_string());
        info!("Handling query for {name}");

        // Check blocklist (read lock is held briefly)
        if self.blocker.read().is_blocked(name) {
            info!("Domain {name} is blocked");
            counter!("dns.queries", "status" => "blocked", "query_type" => query_type).increment(1);
            return Ok(Blocker::blocked_response(&query));
        }

        // Check cache
        if let Some(mut cached) = self.cache.get(name).await {
            info!("Cache hit for {name}");
            counter!("dns.queries", "status" => "cache_hit", "query_type" => query_type)
                .increment(1);
            // Update the ID to match the query
            cached.set_id(query.id());
            return Ok(cached);
        }

        info!("Cache miss for {name}, forwarding to upstream");
        counter!("dns.queries", "status" => "cache_miss", "query_type" => query_type).increment(1);

        // Forward to upstream resolver
        let response = self.resolver.resolve(&query).await?;

        // Cache the response
        self.cache.insert(name.clone(), response.clone()).await;

        Ok(response)
    }
}

impl<C, R> Clone for QueryHandler<C, R>
where
    C: DnsCache + Clone,
    R: DnsResolver + Clone,
{
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
            resolver: self.resolver.clone(),
            blocker: Arc::clone(&self.blocker),
        }
    }
}

/// Configuration for the DNS server.
pub struct ServerConfig {
    pub channel_capacity: usize,
    pub buffer_pool_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1000,
            buffer_pool_size: 64,
        }
    }
}

/// Run the DNS server event loop.
///
/// This function coordinates:
/// 1. Receiving packets from the capture channel
/// 2. Processing DNS queries
/// 3. Sending responses
pub async fn run_server<C, R, S>(
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    handler: QueryHandler<C, R>,
    mut sender: S,
    buffer_pool: BufferPool,
    running: Arc<AtomicBool>,
) -> Result<()>
where
    C: DnsCache,
    R: DnsResolver,
    S: PacketSender,
{
    let packet_builder = PacketBuilder::new(buffer_pool);

    while running.load(Ordering::SeqCst) {
        let Some(packet) = packet_rx.recv().await else {
            break;
        };

        // Extract DNS query from packet
        let Some((packet_info, dns_payload)) = extract_dns_query(&packet) else {
            continue;
        };

        // Parse DNS message
        let query = match Message::from_bytes(&dns_payload) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse DNS message: {}", e);
                continue;
            }
        };

        // Handle the query
        let response = match handler.handle_query(query).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to handle query: {}", e);
                continue;
            }
        };

        // Build and send response
        match packet_builder.build_response(&response, &packet_info) {
            Ok(response_packet) => {
                if let Err(e) = sender.send(&response_packet) {
                    warn!("Failed to send response: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to build response packet: {}", e);
            }
        }
    }

    Ok(())
}

/// Process a single DNS query (useful for testing).
pub async fn process_query<C, R>(
    dns_payload: &[u8],
    packet_info: &PacketInfo,
    handler: &QueryHandler<C, R>,
    packet_builder: &PacketBuilder,
) -> Result<Vec<u8>>
where
    C: DnsCache,
    R: DnsResolver,
{
    let query = Message::from_bytes(dns_payload)?;
    let response = handler.handle_query(query).await?;
    packet_builder.build_response(&response, packet_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::dns_cache::tests::MockCache;
    use crate::dns::resolver::tests::MockResolver;
    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    fn create_query(domain: &str, id: u16) -> Message {
        let name = Name::from_str(domain).unwrap();
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(RecordType::A);

        let mut message = Message::new();
        message.set_id(id);
        message.add_query(query);
        message
    }

    fn create_response(id: u16) -> Message {
        let mut response = Message::new();
        response
            .set_id(id)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);
        response
    }

    #[tokio::test]
    async fn should_return_blocked_response_for_blocked_domain() {
        let cache = MockCache::new();
        let resolver = MockResolver::new();
        let blocker = Blocker::new(["blocked.com", "*.ads.net"]);

        let handler = QueryHandler::new(cache, resolver.clone(), blocker);

        // Test exact match
        let query = create_query("blocked.com", 1);
        let response = handler.handle_query(query).await.unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        // Resolver should not be called for blocked domains
        assert_eq!(resolver.resolve_count(), 0);

        // Test wildcard match
        let query = create_query("tracking.ads.net", 2);
        let response = handler.handle_query(query).await.unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(resolver.resolve_count(), 0);
    }

    #[tokio::test]
    async fn should_return_cached_response_on_cache_hit() {
        let cache = MockCache::new();
        let resolver = MockResolver::new();
        let blocker = Blocker::default();

        // Pre-populate cache
        let name = Name::from_str("cached.com").unwrap();
        let cached_response = create_response(999);
        cache.insert(name, cached_response).await;

        let handler = QueryHandler::new(cache.clone(), resolver.clone(), blocker);

        let query = create_query("cached.com", 123);
        let response = handler.handle_query(query).await.unwrap();

        // Response should have the query's ID, not the cached ID
        assert_eq!(response.id(), 123);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        // Resolver should not be called for cache hits
        assert_eq!(resolver.resolve_count(), 0);
        // Cache get should be called
        assert_eq!(cache.get_call_count(), 1);
    }

    #[tokio::test]
    async fn should_resolve_and_cache_on_cache_miss() {
        let cache = MockCache::new();
        let resolver = MockResolver::new();

        // Configure resolver to return a response
        let name = Name::from_str("example.com").unwrap();
        let upstream_response = create_response(0);
        resolver.add_response(name, upstream_response).await;

        let blocker = Blocker::default();
        let handler = QueryHandler::new(cache.clone(), resolver.clone(), blocker);

        let query = create_query("example.com", 456);
        let response = handler.handle_query(query).await.unwrap();

        assert_eq!(response.id(), 456);
        // Resolver should be called
        assert_eq!(resolver.resolve_count(), 1);
        // Response should be cached
        assert_eq!(cache.insert_call_count(), 1);
    }

    #[tokio::test]
    async fn should_return_error_when_resolver_fails() {
        let cache = MockCache::new();
        let resolver = MockResolver::new();
        resolver.set_error("connection refused").await;

        let blocker = Blocker::default();
        let handler = QueryHandler::new(cache, resolver, blocker);

        let query = create_query("example.com", 789);
        let result = handler.handle_query(query).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_share_blocker_when_cloned() {
        let cache = MockCache::new();
        let resolver = MockResolver::new();
        let blocker = Blocker::new(["blocked.com"]);

        let handler1 = QueryHandler::new(cache, resolver, blocker);
        let handler2 = handler1.clone();

        // Both handlers should share the same blocker
        let query = create_query("blocked.com", 1);
        let response = handler2.handle_query(query).await.unwrap();
        assert_eq!(response.answers().len(), 1);
    }

    #[test]
    fn should_use_default_server_config_values() {
        let config = ServerConfig::default();
        assert_eq!(config.channel_capacity, 1000);
        assert_eq!(config.buffer_pool_size, 64);
    }

    #[tokio::test]
    async fn should_return_same_message_when_query_is_empty() {
        let cache = MockCache::new();
        let resolver = MockResolver::new();
        let blocker = Blocker::default();

        let handler = QueryHandler::new(cache, resolver, blocker);

        // Create a message with no queries
        let empty_query = Message::new();
        let response = handler.handle_query(empty_query.clone()).await.unwrap();

        // Should return the same message since there's no query to process
        assert_eq!(response.id(), empty_query.id());
    }

    #[tokio::test]
    async fn should_use_shared_blocker_with_hot_reload() {
        let cache = MockCache::new();
        let resolver = MockResolver::new();

        // Create a shared blocker (simulating BlocklistManager)
        let shared_blocker = Arc::new(RwLock::new(Blocker::default()));

        let handler =
            QueryHandler::with_shared_blocker(cache, resolver.clone(), Arc::clone(&shared_blocker));

        // Domain should not be blocked initially
        let query = create_query("newblocked.com", 1);
        let _response = handler.handle_query(query).await.unwrap();
        // Resolver was called because domain wasn't blocked
        assert_eq!(resolver.resolve_count(), 1);

        // Now update the shared blocker (simulating hot-reload)
        *shared_blocker.write() = Blocker::new(["newblocked.com"]);

        // Same domain should now be blocked
        let query = create_query("newblocked.com", 2);
        let response = handler.handle_query(query).await.unwrap();

        // Should get a blocked response (localhost)
        assert_eq!(response.answers().len(), 1);
        // Resolver should NOT be called again
        assert_eq!(resolver.resolve_count(), 1);
    }
}
