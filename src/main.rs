//! Bluebox DNS Server - Entry point.
//!
//! This binary captures DNS queries on the local network, applies blocking rules,
//! caches responses, and forwards non-cached queries to an upstream resolver.
//!
//! When ARP spoofing is enabled, it transparently intercepts DNS queries from
//! all devices on the network without requiring client configuration.

use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use pnet::util::MacAddr;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use bluebox::blocklist::manager::BlocklistManager;
use bluebox::cache::MokaCache;
use bluebox::config::Config;
use bluebox::dns::UpstreamResolver;
use bluebox::network::arp::{ArpSpoofConfig, ArpSpoofer};
use bluebox::network::forward;
use bluebox::network::{
    BufferPool, PacketCapture, PnetCapture, PnetSender, detect_gateway, find_interface,
    get_interface_info,
};
use bluebox::server::{QueryHandler, run_server};

/// Set up ARP spoofing if enabled in configuration.
fn setup_arp_spoofer(
    config: &Config,
    interface: &pnet::datalink::NetworkInterface,
    our_ip: Ipv4Addr,
    our_mac: MacAddr,
) -> Result<Option<Arc<Mutex<ArpSpoofer<PnetSender>>>>> {
    if !config.arp_spoof.enabled {
        info!("ARP spoofing disabled - running in passive mode");
        info!("Note: Devices must be configured to use this server as their DNS");
        return Ok(None);
    }

    info!("ARP spoofing enabled - configuring transparent interception");

    let gateway_ip = if let Some(ip) = config.arp_spoof.gateway_ip {
        info!("Using configured gateway IP: {ip}");
        ip
    } else {
        let detected = detect_gateway().context("Failed to detect gateway")?;
        info!("Auto-detected gateway IP: {detected}");
        detected
    };

    let (_, arp_sender) = PnetCapture::new(interface).context("Failed to create ARP sender")?;

    let arp_config = ArpSpoofConfig {
        gateway_ip,
        our_ip,
        our_mac,
        spoof_interval: Duration::from_secs(config.arp_spoof.spoof_interval_secs),
        restore_on_shutdown: config.arp_spoof.restore_on_shutdown,
    };

    let mut spoofer = ArpSpoofer::new(arp_config, arp_sender);
    spoofer
        .discover_gateway()
        .context("Failed to send gateway discovery")?;

    Ok(Some(Arc::new(Mutex::new(spoofer))))
}

/// Spawn the ARP spoofing task that periodically sends spoof packets.
fn spawn_arp_spoof_task(
    spoofer: Arc<Mutex<ArpSpoofer<PnetSender>>>,
    running: Arc<AtomicBool>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        while running.load(Ordering::SeqCst) {
            ticker.tick().await;
            let mut guard = spoofer.lock();
            if let Err(err) = guard.spoof_all() {
                warn!("Failed to send ARP spoof packets: {err}");
            }
        }
    })
}

/// Configuration for the packet capture task.
struct CaptureTaskConfig {
    capture: PnetCapture,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
    arp_spoofer: Option<Arc<Mutex<ArpSpoofer<PnetSender>>>>,
    forward_sender: Option<Arc<Mutex<PnetSender>>>,
    our_ip: Ipv4Addr,
    our_mac: MacAddr,
    forward_traffic: bool,
}

/// Spawn the packet capture thread that processes incoming packets.
fn spawn_capture_task(config: CaptureTaskConfig) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut capture = config.capture;
        while config.running.load(Ordering::SeqCst) {
            let Some(packet) = capture.next_packet() else {
                continue;
            };

            // Process ARP packets to learn network topology
            if let Some(ref spoofer) = config.arp_spoofer {
                let mut guard = spoofer.lock();
                guard.process_arp_packet(&packet);
            }

            // Forward non-DNS traffic if configured
            if config.forward_traffic && forward::should_forward(&packet, config.our_ip) {
                if let Some(ref sender) = config.forward_sender
                    && let Some(ref spoofer) = config.arp_spoofer
                {
                    let guard = spoofer.lock();
                    let target = forward::resolve_forward_target(
                        &packet,
                        config.our_ip,
                        guard.gateway_ip(),
                        guard.arp_table(),
                    );

                    if let Some(target) = target {
                        let mut sender_guard = sender.lock();
                        match target {
                            forward::ForwardTarget::Gateway => {
                                if let Some(gateway_mac) = guard.gateway_mac() {
                                    let _ = forward::forward_to_gateway(
                                        &packet,
                                        gateway_mac,
                                        config.our_mac,
                                        &mut *sender_guard,
                                    );
                                }
                            }
                            forward::ForwardTarget::Client(client_mac) => {
                                let _ = forward::forward_to_client(
                                    &packet,
                                    client_mac,
                                    config.our_mac,
                                    &mut *sender_guard,
                                );
                            }
                        }
                    }
                }
                continue;
            }

            // Send DNS packets for processing
            if config.packet_tx.blocking_send(packet).is_err() {
                break;
            }
        }
    })
}

/// Wait for shutdown signal and handle graceful termination.
async fn wait_for_shutdown(
    running: Arc<AtomicBool>,
    server_handle: JoinHandle<()>,
    arp_handle: Option<JoinHandle<()>>,
    capture_handle: JoinHandle<()>,
    arp_spoofer: Option<Arc<Mutex<ArpSpoofer<PnetSender>>>>,
    restore_on_shutdown: bool,
) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down...");
            running.store(false, Ordering::SeqCst);
        }
        result = server_handle => {
            if let Err(err) = result {
                tracing::error!("Server task failed: {err}");
            }
        }
    }

    // Restore ARP tables if configured
    if let Some(ref spoofer) = arp_spoofer
        && restore_on_shutdown
    {
        info!("Restoring ARP tables...");
        let mut guard = spoofer.lock();
        if let Err(err) = guard.restore_all() {
            warn!("Failed to restore ARP tables: {err}");
        }
    }

    // Wait for tasks to finish
    if let Some(handle) = arp_handle {
        let _ = handle.await;
    }
    let _ = capture_handle.await;

    info!("Shutdown complete.");
}

async fn run() -> Result<()> {
    let config_path = std::env::var("CONFIG_PATH")
        .map(Cow::Owned)
        .unwrap_or(Cow::Borrowed("config.toml"));
    let config = Config::load(config_path.as_ref()).context("Failed to load configuration")?;

    // Initialize metrics (must be done early, before any metrics are recorded)
    bluebox::metrics::init(&config.metrics).context("Failed to initialize metrics")?;
    if config.metrics.enabled {
        info!("Metrics enabled on {}", config.metrics.listen);
    }

    info!("Starting Bluebox DNS interceptor...");
    info!("Upstream resolver: {}", config.upstream_resolver);
    info!("Cache TTL: {} seconds", config.cache_ttl_seconds);
    info!("Inline blocklist entries: {}", config.blocklist.len());
    info!(
        "Blocklist sources configured: {}",
        config.blocklist_sources.len()
    );

    // Create and initialize blocklist manager
    let blocklist_manager =
        BlocklistManager::new(&config).context("Failed to create blocklist manager")?;
    blocklist_manager
        .initialize()
        .await
        .context("Failed to initialize blocklist manager")?;

    info!(
        "Blocklist manager initialized with {} unique patterns",
        blocklist_manager.total_patterns()
    );

    // Log per-source statistics
    for (name, stats) in blocklist_manager.stats() {
        debug!(name = %name, patterns = stats.pattern_count, "blocklist source loaded");
    }

    // Find network interface
    let interface =
        find_interface(config.interface.as_deref()).context("Failed to find network interface")?;
    info!("Listening on interface: {}", interface.name);

    // Get our interface info
    let (our_ip, our_mac) =
        get_interface_info(&interface).context("Failed to get interface info")?;
    info!("Our IP: {our_ip}, MAC: {our_mac}");

    // Initialize components
    let cache = MokaCache::new(Duration::from_secs(config.cache_ttl_seconds));
    let resolver = UpstreamResolver::new(config.upstream_resolver);
    let buffer_pool = BufferPool::new(config.buffer_pool_size);

    // Create packet capture
    let (capture, sender) =
        PnetCapture::new(&interface).context("Failed to create packet capture")?;

    // Set up ARP spoofing
    let arp_spoofer = setup_arp_spoofer(&config, &interface, our_ip, our_mac)?;

    // Create query handler with shared blocker for hot-reload support
    let handler = QueryHandler::with_shared_blocker(cache, resolver, blocklist_manager.blocker());

    // Set up packet channel and running flag
    let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(config.channel_capacity);
    let running = Arc::new(AtomicBool::new(true));

    // Spawn ARP spoofing task if enabled
    let arp_handle = arp_spoofer.clone().map(|spoofer| {
        spawn_arp_spoof_task(
            spoofer,
            Arc::clone(&running),
            Duration::from_secs(config.arp_spoof.spoof_interval_secs),
        )
    });

    // Create forward sender if traffic forwarding is enabled
    let forward_traffic = config.arp_spoof.enabled && config.arp_spoof.forward_traffic;
    let forward_sender = if forward_traffic {
        let (_, fwd_sender) =
            PnetCapture::new(&interface).context("Failed to create forward sender")?;
        Some(Arc::new(Mutex::new(fwd_sender)))
    } else {
        None
    };

    // Spawn packet capture task
    let capture_handle = spawn_capture_task(CaptureTaskConfig {
        capture,
        packet_tx,
        running: Arc::clone(&running),
        arp_spoofer: arp_spoofer.clone(),
        forward_sender,
        our_ip,
        our_mac,
        forward_traffic,
    });

    // Spawn server task
    let server_running = Arc::clone(&running);
    let server_handle = tokio::spawn(async move {
        if let Err(err) = run_server(packet_rx, handler, sender, buffer_pool, server_running).await
        {
            error!("Server error: {err:?}");
        }
    });

    // Wait for shutdown
    wait_for_shutdown(
        running,
        server_handle,
        arp_handle,
        capture_handle,
        arp_spoofer,
        config.arp_spoof.restore_on_shutdown,
    )
    .await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run().await
}
