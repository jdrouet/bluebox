//! DNS cache trait and implementations.
//!
//! Provides a trait-based abstraction over caching to enable:
//! - Easy testing with mock implementations
//! - Swappable cache backends
//! - Clear interface boundaries

use std::future::Future;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::Name;
use moka::future::Cache;

/// Trait for DNS response caching.
///
/// This trait abstracts the caching mechanism, allowing for different
/// implementations (production Moka cache, test mocks, etc.).
pub trait DnsCache: Send + Sync + Clone + 'static {
    /// Get a cached response for the given domain name.
    fn get(&self, name: &Name) -> impl Future<Output = Option<Message>> + Send;

    /// Insert a response into the cache.
    fn insert(&self, name: Name, message: Message) -> impl Future<Output = ()> + Send;

    /// Returns the number of entries in the cache.
    fn entry_count(&self) -> u64;
}

/// Production cache implementation using Moka.
///
/// Moka provides a high-performance, concurrent cache with:
/// - Time-based expiration (TTL)
/// - Bounded size (optional)
/// - Thread-safe operations
#[derive(Clone)]
pub struct MokaCache {
    inner: Cache<Name, Message>,
}

impl MokaCache {
    /// Create a new cache with the specified TTL.
    pub fn new(ttl: Duration) -> Self {
        let cache = Cache::builder().time_to_live(ttl).build();

        Self { inner: cache }
    }

    /// Create a new cache with TTL and maximum capacity.
    pub fn with_capacity(ttl: Duration, max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(ttl)
            .max_capacity(max_capacity)
            .build();

        Self { inner: cache }
    }
}

impl DnsCache for MokaCache {
    async fn get(&self, name: &Name) -> Option<Message> {
        self.inner.get(name).await
    }

    async fn insert(&self, name: Name, message: Message) {
        self.inner.insert(name, message).await;
    }

    fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, ResponseCode};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::RwLock;

    /// Mock cache for testing.
    #[derive(Clone, Default)]
    pub struct MockCache {
        pub entries: Arc<RwLock<std::collections::HashMap<Name, Message>>>,
        pub get_count: Arc<AtomicU64>,
        pub insert_count: Arc<AtomicU64>,
    }

    impl MockCache {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn get_call_count(&self) -> u64 {
            self.get_count.load(Ordering::SeqCst)
        }

        pub fn insert_call_count(&self) -> u64 {
            self.insert_count.load(Ordering::SeqCst)
        }
    }

    impl DnsCache for MockCache {
        async fn get(&self, name: &Name) -> Option<Message> {
            self.get_count.fetch_add(1, Ordering::SeqCst);
            self.entries.read().await.get(name).cloned()
        }

        async fn insert(&self, name: Name, message: Message) {
            self.insert_count.fetch_add(1, Ordering::SeqCst);
            self.entries.write().await.insert(name, message);
        }

        fn entry_count(&self) -> u64 {
            // This is a rough estimate; for tests it's fine
            0
        }
    }

    fn create_test_message(id: u16) -> Message {
        let mut msg = Message::new();
        msg.set_id(id)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);
        msg
    }

    #[tokio::test]
    async fn should_insert_and_retrieve_cached_entries() {
        let cache = MokaCache::new(Duration::from_secs(60));
        let name = Name::from_str("example.com").unwrap();
        let message = create_test_message(1234);

        // Initially empty
        assert!(cache.get(&name).await.is_none());

        // Insert and retrieve
        cache.insert(name.clone(), message.clone()).await;
        let cached = cache.get(&name).await.unwrap();
        assert_eq!(cached.id(), 1234);
    }

    #[tokio::test]
    async fn should_track_get_and_insert_call_counts() {
        let cache = MockCache::new();
        let name = Name::from_str("example.com").unwrap();
        let message = create_test_message(1);

        assert_eq!(cache.get_call_count(), 0);
        assert_eq!(cache.insert_call_count(), 0);

        cache.get(&name).await;
        assert_eq!(cache.get_call_count(), 1);

        cache.insert(name.clone(), message).await;
        assert_eq!(cache.insert_call_count(), 1);

        cache.get(&name).await;
        assert_eq!(cache.get_call_count(), 2);
    }

    #[tokio::test]
    async fn should_work_with_capacity_limit() {
        let cache = MokaCache::with_capacity(Duration::from_secs(60), 10);
        let name = Name::from_str("example.com").unwrap();
        let message = create_test_message(1);

        cache.insert(name.clone(), message).await;
        assert!(cache.get(&name).await.is_some());
    }
}
