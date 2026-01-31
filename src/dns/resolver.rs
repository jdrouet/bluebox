//! DNS resolver trait and implementations.
//!
//! Provides abstraction over DNS resolution to enable:
//! - Testing with mock resolvers
//! - Different resolution strategies (upstream, `DoH`, `DoT`, etc.)

use std::future::Future;
use std::net::SocketAddr;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;

use crate::error::Result;

/// Maximum DNS message size over UDP.
pub const MAX_UDP_DNS_SIZE: usize = 512;

/// Trait for DNS resolution.
///
/// Implementations can resolve DNS queries through various mechanisms:
/// - Upstream UDP resolver
/// - DNS-over-HTTPS
/// - DNS-over-TLS
/// - Mock responses for testing
pub trait DnsResolver: Send + Sync + Clone + 'static {
    /// Resolve a DNS query and return the response.
    fn resolve(&self, query: &Message) -> impl Future<Output = Result<Message>> + Send;
}

/// Upstream DNS resolver using UDP.
///
/// Forwards queries to a configured upstream DNS server (e.g., 1.1.1.1).
#[derive(Clone)]
pub struct UpstreamResolver {
    upstream_addr: SocketAddr,
}

impl UpstreamResolver {
    /// Create a new upstream resolver.
    pub const fn new(upstream_addr: SocketAddr) -> Self {
        Self { upstream_addr }
    }
}

impl DnsResolver for UpstreamResolver {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.upstream_addr).await?;

        let query_bytes = query.to_bytes()?;
        socket.send(&query_bytes).await?;

        let mut response_buf = [0u8; MAX_UDP_DNS_SIZE];
        let len = socket.recv(&mut response_buf).await?;

        let response = Message::from_bytes(&response_buf[..len])?;
        Ok(response)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::error::Error;
    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::RwLock;

    /// Mock resolver for testing.
    ///
    /// Allows pre-configuring responses and tracking resolve calls.
    #[derive(Clone, Default)]
    pub struct MockResolver {
        /// Pre-configured responses by domain name.
        pub responses: Arc<RwLock<HashMap<Name, Message>>>,
        /// Default response for unconfigured domains.
        pub default_response: Arc<RwLock<Option<Message>>>,
        /// Count of resolve calls.
        pub resolve_count: Arc<AtomicU64>,
        /// If set, resolve will return this error.
        pub error: Arc<RwLock<Option<String>>>,
    }

    impl MockResolver {
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a pre-configured response for a domain.
        pub async fn add_response(&self, name: Name, response: Message) {
            self.responses.write().await.insert(name, response);
        }

        /// Set a default response for unconfigured domains.
        pub async fn set_default_response(&self, response: Message) {
            *self.default_response.write().await = Some(response);
        }

        /// Configure the resolver to return an error.
        pub async fn set_error(&self, error: &str) {
            *self.error.write().await = Some(error.to_string());
        }

        /// Get the number of resolve calls.
        pub fn resolve_count(&self) -> u64 {
            self.resolve_count.load(Ordering::SeqCst)
        }
    }

    impl DnsResolver for MockResolver {
        async fn resolve(&self, query: &Message) -> Result<Message> {
            self.resolve_count.fetch_add(1, Ordering::SeqCst);

            // Check for configured error
            if let Some(error) = self.error.read().await.as_ref() {
                return Err(Error::Resolver(error.clone()));
            }

            // Try to find a pre-configured response
            if let Some(q) = query.queries().first() {
                let name = q.name();
                if let Some(response) = self.responses.read().await.get(name) {
                    let mut resp = response.clone();
                    resp.set_id(query.id()); // Match query ID
                    return Ok(resp);
                }
            }

            // Return default response if configured
            if let Some(response) = self.default_response.read().await.as_ref() {
                let mut resp = response.clone();
                resp.set_id(query.id());
                return Ok(resp);
            }

            // Return NXDOMAIN if no response configured
            let mut response = Message::new();
            response
                .set_id(query.id())
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_response_code(ResponseCode::NXDomain);
            Ok(response)
        }
    }

    fn create_query(domain: &str) -> Message {
        let name = Name::from_str(domain).unwrap();
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(RecordType::A);

        let mut message = Message::new();
        message.set_id(1234);
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
    async fn should_return_nxdomain_when_no_response_configured() {
        let resolver = MockResolver::new();
        let query = create_query("example.com");

        let response = resolver.resolve(&query).await.unwrap();

        assert_eq!(response.id(), query.id());
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert_eq!(resolver.resolve_count(), 1);
    }

    #[tokio::test]
    async fn should_return_configured_response_for_domain() {
        let resolver = MockResolver::new();
        let name = Name::from_str("example.com").unwrap();
        let response = create_response(0);
        resolver.add_response(name, response).await;

        let query = create_query("example.com");
        let result = resolver.resolve(&query).await.unwrap();

        assert_eq!(result.id(), query.id());
        assert_eq!(result.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn should_return_default_response_when_domain_not_configured() {
        let resolver = MockResolver::new();
        let response = create_response(0);
        resolver.set_default_response(response).await;

        let query = create_query("any-domain.com");
        let result = resolver.resolve(&query).await.unwrap();

        assert_eq!(result.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn should_return_error_when_resolver_configured_to_fail() {
        let resolver = MockResolver::new();
        resolver.set_error("connection refused").await;

        let query = create_query("example.com");
        let result = resolver.resolve(&query).await;

        assert!(result.is_err());
    }
}
