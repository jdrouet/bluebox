# Bluebox

A fast, transparent DNS interceptor for local networks. Bluebox acts as a parental control / ad-blocking DNS filter that works **without requiring any client configuration**.

## Features

- **Transparent DNS Interception**: Uses ARP spoofing to intercept DNS queries from all devices on the network
- **Domain Blocking**: Block domains by exact match or wildcard patterns (e.g., `*.ads.com`)
- **Response Caching**: Caches DNS responses to improve performance
- **Zero Client Configuration**: Devices don't need any DNS settings changed
- **Traffic Forwarding**: Non-DNS traffic is forwarded to the real gateway transparently
- **Graceful Shutdown**: Restores ARP tables when stopping to avoid network disruption

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        Local Network                            │
│                                                                 │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐                │
│  │  Phone   │     │  Laptop  │     │  Tablet  │                │
│  └────┬─────┘     └────┬─────┘     └────┬─────┘                │
│       │                │                │                       │
│       │    DNS queries (port 53)        │                       │
│       └────────────────┼────────────────┘                       │
│                        │                                        │
│                        ▼                                        │
│              ┌─────────────────┐                                │
│              │    Bluebox      │◄─── ARP: "I am the gateway"   │
│              │  (Raspberry Pi) │                                │
│              └────────┬────────┘                                │
│                       │                                         │
│         ┌─────────────┴─────────────┐                          │
│         │                           │                          │
│         ▼                           ▼                          │
│  ┌─────────────┐           ┌───────────────┐                   │
│  │ DNS blocked │           │ Forward other │                   │
│  │ → localhost │           │ traffic to    │                   │
│  │             │           │ real gateway  │                   │
│  │ DNS allowed │           └───────┬───────┘                   │
│  │ → upstream  │                   │                           │
│  └─────────────┘                   ▼                           │
│                            ┌──────────────┐                    │
│                            │   Router     │                    │
│                            │  (Gateway)   │                    │
│                            └──────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

### ARP Spoofing Explained

1. **Discovery**: Bluebox discovers the gateway (router) IP and MAC address
2. **ARP Poisoning**: Periodically sends ARP replies to all devices claiming to be the gateway
3. **Interception**: Devices send their traffic to Bluebox thinking it's the gateway
4. **DNS Filtering**: DNS queries (port 53) are intercepted and filtered
5. **Forwarding**: All other traffic is forwarded to the real gateway

## Installation

### Prerequisites

- Rust 1.75+ (edition 2024)
- Root/sudo privileges (required for raw packet capture and ARP)
- Linux or macOS

### Building

```bash
git clone https://github.com/jeremie/bluebox.git
cd bluebox
cargo build --release
```

The binary will be at `target/release/bluebox`.

### Raspberry Pi Setup

1. Install Rust on your Raspberry Pi:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Clone and build:
   ```bash
   git clone https://github.com/jeremie/bluebox.git
   cd bluebox
   cargo build --release
   ```

3. Copy the binary and config:
   ```bash
   sudo cp target/release/bluebox /usr/local/bin/
   sudo cp config.toml /etc/bluebox/config.toml
   ```

4. Run as a systemd service (see [Systemd Service](#systemd-service) below)

## Configuration

Create a `config.toml` file:

```toml
# Network interface (optional, auto-detected if not specified)
# interface = "eth0"

# Upstream DNS resolver
upstream_resolver = "1.1.1.1:53"

# Cache TTL in seconds
cache_ttl_seconds = 300

# Domains to block (exact match or wildcard)
blocklist = [
    # Social media
    "*.facebook.com",
    "facebook.com",
    "*.instagram.com",
    "instagram.com",
    "*.tiktok.com",
    "tiktok.com",
    
    # Ads and tracking
    "*.doubleclick.net",
    "*.googlesyndication.com",
    "*.googleadservices.com",
    "*.facebook-dns.com",
    "*.adnxs.com",
]

# ARP spoofing for transparent interception
[arp_spoof]
enabled = true
# gateway_ip = "192.168.1.1"  # Optional, auto-detected
spoof_interval_secs = 2
restore_on_shutdown = true
forward_traffic = true
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `interface` | Network interface to use | Auto-detect |
| `upstream_resolver` | Upstream DNS server | Required |
| `cache_ttl_seconds` | How long to cache DNS responses | 300 |
| `blocklist` | List of domains/patterns to block | `[]` |
| `buffer_pool_size` | Size of packet buffer pool | 64 |
| `channel_capacity` | Packet queue capacity | 1000 |

### ARP Spoof Options

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable transparent interception | `false` |
| `gateway_ip` | Gateway IP to impersonate | Auto-detect |
| `spoof_interval_secs` | Seconds between ARP packets | 2 |
| `restore_on_shutdown` | Restore ARP tables on exit | `true` |
| `forward_traffic` | Forward non-DNS traffic | `true` |

## Usage

### Basic Usage (Passive Mode)

Without ARP spoofing, devices must be configured to use Bluebox as their DNS server:

```bash
sudo ./bluebox
```

### Transparent Mode (ARP Spoofing)

With ARP spoofing enabled, no client configuration is needed:

```bash
# Edit config.toml to enable arp_spoof
sudo ./bluebox
```

### Systemd Service

Create `/etc/systemd/system/bluebox.service`:

```ini
[Unit]
Description=Bluebox DNS Interceptor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bluebox
WorkingDirectory=/etc/bluebox
Restart=always
RestartSec=5

# Security
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable bluebox
sudo systemctl start bluebox
sudo systemctl status bluebox
```

## Architecture

```
src/
├── main.rs              # Entry point, orchestration
├── lib.rs               # Library exports
├── config.rs            # Configuration loading
├── error.rs             # Error types
├── dns/
│   ├── blocker.rs       # Domain blocking logic
│   └── resolver.rs      # Upstream DNS resolution
├── cache/
│   └── dns_cache.rs     # Response caching (Moka)
├── network/
│   ├── arp.rs           # ARP spoofing
│   ├── forward.rs       # Traffic forwarding
│   ├── capture.rs       # Packet capture (pnet)
│   ├── packet.rs        # Packet construction
│   └── buffer.rs        # Buffer pooling
└── server.rs            # Query handling
```

### Design Principles

- **Trait-based abstractions**: All components have traits for easy testing/mocking
- **Minimal allocations**: Buffer pooling to reduce heap allocations
- **Async I/O**: Tokio for efficient async operations
- **Zero-copy where possible**: Direct packet manipulation

## Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run benchmarks
cargo bench
```

## Security Considerations

- **Root Required**: Bluebox needs root privileges for raw packet capture and ARP
- **Network Scope**: Only use on networks you own or have permission to manage
- **ARP Spoofing**: This technique is commonly used for parental controls and enterprise monitoring, but could be misused - use responsibly
- **Graceful Shutdown**: Always let Bluebox shut down gracefully (Ctrl+C) to restore ARP tables

## Roadmap

### Implemented
- [x] DNS query interception and filtering
- [x] Domain blocking (exact + wildcard)
- [x] Response caching with TTL
- [x] ARP spoofing for transparent interception
- [x] Traffic forwarding for non-DNS packets
- [x] Gateway auto-detection
- [x] Graceful shutdown with ARP restoration

### Planned
- [ ] Web UI for configuration and statistics
- [ ] Blocklist file support (hosts format, AdBlock format)
- [ ] Per-device policies (allow/block specific devices)
- [ ] DNS-over-HTTPS (DoH) upstream support
- [ ] Statistics and logging dashboard
- [ ] Scheduled blocking (e.g., no social media 9pm-7am)
- [ ] DHCP server mode (alternative to ARP spoofing)
- [ ] IPv6 support for ARP spoofing (NDP)

## Troubleshooting

### "Failed to find network interface"

Make sure you're running as root:
```bash
sudo ./bluebox
```

### "Failed to detect gateway"

Manually specify the gateway in config:
```toml
[arp_spoof]
enabled = true
gateway_ip = "192.168.1.1"  # Your router's IP
```

### Devices lose internet after starting Bluebox

This usually means traffic forwarding isn't working. Check:
1. `forward_traffic = true` in config
2. The gateway MAC was discovered (check logs for "Discovered gateway MAC")
3. IP forwarding is enabled: `sudo sysctl net.ipv4.ip_forward=1`

### Network doesn't recover after stopping Bluebox

If you kill Bluebox with `kill -9` instead of Ctrl+C, ARP tables won't be restored. Fix by:
```bash
# Clear ARP cache on affected devices, or
# Restart their network interface, or
# Wait for ARP cache to expire (usually 1-5 minutes)
```

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
