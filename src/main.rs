//! Bluebox DNS Server - Entry point.
//!
//! This binary captures DNS queries on the local network, applies blocking rules,
//! caches responses, and forwards non-cached queries to an upstream resolver.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::task;
use tracing::info;

use bluebox::cache::MokaCache;
use bluebox::config::Config;
use bluebox::dns::{Blocker, UpstreamResolver};
use bluebox::network::{BufferPool, PacketCapture, PnetCapture, find_interface};
use bluebox::server::{QueryHandler, run_server};

async fn run() -> Result<()> {
    let config = Config::load("config.toml").context("Failed to load configuration")?;

    info!("Starting Bluebox DNS interceptor...");
    info!("Upstream resolver: {}", config.upstream_resolver);
    info!("Cache TTL: {} seconds", config.cache_ttl_seconds);
    info!("Blocklist entries: {}", config.blocklist.len());

    // Find network interface
    let interface =
        find_interface(config.interface.as_deref()).context("Failed to find network interface")?;
    info!("Listening on interface: {}", interface.name);

    // Initialize components
    let cache = MokaCache::new(Duration::from_secs(config.cache_ttl_seconds));
    let resolver = UpstreamResolver::new(config.upstream_resolver);
    let blocker = Blocker::new(&config.blocklist);
    let buffer_pool = BufferPool::new(config.buffer_pool_size);

    info!("Blocker initialized with {} patterns", blocker.len());

    // Create packet capture
    let (capture, sender) =
        PnetCapture::new(&interface).context("Failed to create packet capture")?;

    // Create query handler
    let handler = QueryHandler::new(cache, resolver, blocker);

    // Set up packet channel
    let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(config.channel_capacity);
    let running = Arc::new(AtomicBool::new(true));
    let capture_running = Arc::clone(&running);

    // Spawn packet capture thread (blocking I/O)
    let capture_handle = task::spawn_blocking(move || {
        let mut capture = capture;
        while capture_running.load(Ordering::SeqCst) {
            if let Some(packet) = capture.next_packet()
                && packet_tx.blocking_send(packet).is_err() {
                    break;
                }
        }
    });

    // Spawn server task
    let server_running = Arc::clone(&running);
    let server_handle = tokio::spawn(async move {
        run_server(packet_rx, handler, sender, buffer_pool, server_running).await
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down...");
            running.store(false, Ordering::SeqCst);
        }
        result = server_handle => {
            if let Err(e) = result {
                tracing::error!("Server task failed: {}", e);
            }
        }
    }

    // Wait for capture thread to finish
    let _ = capture_handle.await;

    info!("Shutdown complete.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run().await
}
