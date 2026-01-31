//! Bluebox DNS Server - Entry point.
//!
//! This binary captures DNS queries on the local network, applies blocking rules,
//! caches responses, and forwards non-cached queries to an upstream resolver.
//!
//! When ARP spoofing is enabled, it transparently intercepts DNS queries from
//! all devices on the network without requiring client configuration.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task;
use tracing::{info, warn};

use bluebox::cache::MokaCache;
use bluebox::config::Config;
use bluebox::dns::{Blocker, UpstreamResolver};
use bluebox::network::arp::{ArpSpoofConfig, ArpSpoofer};
use bluebox::network::forward;
use bluebox::network::{
    BufferPool, PacketCapture, PnetCapture, PnetSender, detect_gateway, find_interface,
    get_interface_info,
};
use bluebox::server::{QueryHandler, run_server};

#[allow(clippy::too_many_lines, reason = "will split later")]
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

    // Get our interface info
    let (our_ip, our_mac) =
        get_interface_info(&interface).context("Failed to get interface info")?;
    info!("Our IP: {}, MAC: {}", our_ip, our_mac);

    // Initialize components
    let cache = MokaCache::new(Duration::from_secs(config.cache_ttl_seconds));
    let resolver = UpstreamResolver::new(config.upstream_resolver);
    let blocker = Blocker::new(&config.blocklist);
    let buffer_pool = BufferPool::new(config.buffer_pool_size);

    info!("Blocker initialized with {} patterns", blocker.len());

    // Create packet capture
    let (capture, sender) =
        PnetCapture::new(&interface).context("Failed to create packet capture")?;

    // Set up ARP spoofing if enabled
    let arp_spoofer: Option<Arc<Mutex<ArpSpoofer<PnetSender>>>> = if config.arp_spoof.enabled {
        info!("ARP spoofing enabled - configuring transparent interception");

        // Detect or use configured gateway
        let gateway_ip = if let Some(ip) = config.arp_spoof.gateway_ip {
            info!("Using configured gateway IP: {}", ip);
            ip
        } else {
            let detected = detect_gateway().context("Failed to detect gateway")?;
            info!("Auto-detected gateway IP: {}", detected);
            detected
        };

        // Create a second sender for ARP spoofing
        let (_, arp_sender) =
            PnetCapture::new(&interface).context("Failed to create ARP sender")?;

        let arp_config = ArpSpoofConfig {
            gateway_ip,
            our_ip,
            our_mac,
            spoof_interval: Duration::from_secs(config.arp_spoof.spoof_interval_secs),
            restore_on_shutdown: config.arp_spoof.restore_on_shutdown,
        };

        let mut spoofer = ArpSpoofer::new(arp_config, arp_sender);

        // Discover the gateway's MAC address
        spoofer
            .discover_gateway()
            .context("Failed to send gateway discovery")?;

        Some(Arc::new(Mutex::new(spoofer)))
    } else {
        info!("ARP spoofing disabled - running in passive mode");
        info!("Note: Devices must be configured to use this server as their DNS");
        None
    };

    // Create query handler
    let handler = QueryHandler::new(cache, resolver, blocker);

    // Set up packet channel
    let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(config.channel_capacity);
    let running = Arc::new(AtomicBool::new(true));

    // Clone for ARP spoofer task
    let arp_spoofer_for_task = arp_spoofer.clone();
    let arp_running = Arc::clone(&running);
    let spoof_interval = Duration::from_secs(config.arp_spoof.spoof_interval_secs);

    // Spawn ARP spoofing task if enabled
    let arp_handle = arp_spoofer_for_task.map(|spoofer| {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(spoof_interval);
            while arp_running.load(Ordering::SeqCst) {
                interval.tick().await;
                let mut guard = spoofer.lock();
                if let Err(e) = guard.spoof_all() {
                    warn!("Failed to send ARP spoof packets: {}", e);
                }
            }
        })
    });

    // Spawn packet capture thread (blocking I/O)
    let capture_running = Arc::clone(&running);
    let arp_spoofer_for_capture = arp_spoofer.clone();
    let forward_traffic = config.arp_spoof.enabled && config.arp_spoof.forward_traffic;

    // We need a separate sender for forwarding
    let forward_sender = if forward_traffic {
        let (_, fwd_sender) =
            PnetCapture::new(&interface).context("Failed to create forward sender")?;
        Some(Arc::new(Mutex::new(fwd_sender)))
    } else {
        None
    };

    let capture_handle = task::spawn_blocking(move || {
        let mut capture = capture;
        while capture_running.load(Ordering::SeqCst) {
            if let Some(packet) = capture.next_packet() {
                // Process ARP packets to learn network topology
                if let Some(ref spoofer) = arp_spoofer_for_capture {
                    let mut guard = spoofer.lock();
                    guard.process_arp_packet(&packet);
                }

                // Check if we should forward non-DNS traffic
                if forward_traffic && forward::should_forward(&packet, our_ip) {
                    if let Some(ref sender) = forward_sender
                        && let Some(ref spoofer) = arp_spoofer_for_capture
                    {
                        let guard = spoofer.lock();
                        if let Some(gateway_mac) = guard.gateway_mac() {
                            let mut sender_guard = sender.lock();
                            let _ = forward::forward_to_gateway(
                                &packet,
                                gateway_mac,
                                our_mac,
                                &mut *sender_guard,
                            );
                        }
                    }
                    continue; // Don't process as DNS
                }

                // Send DNS packets for processing
                if packet_tx.blocking_send(packet).is_err() {
                    break;
                }
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

    // Restore ARP tables if configured
    if let Some(ref spoofer) = arp_spoofer
        && config.arp_spoof.restore_on_shutdown
    {
        info!("Restoring ARP tables...");
        let mut guard = spoofer.lock();
        if let Err(e) = guard.restore_all() {
            warn!("Failed to restore ARP tables: {}", e);
        }
    }

    // Wait for tasks to finish
    if let Some(handle) = arp_handle {
        let _ = handle.await;
    }
    let _ = capture_handle.await;

    info!("Shutdown complete.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run().await
}
