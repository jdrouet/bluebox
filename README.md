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

**Native Installation:**
- Root/sudo privileges (required for raw packet capture and ARP)
- Linux (Debian/Ubuntu for .deb packages, or any Linux for musl builds)

**Docker Installation:**
- Docker with `--cap-add=NET_ADMIN` and `--cap-add=NET_RAW` capabilities
- `--network host` mode to access the host's network interfaces

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/jeremie/bluebox/releases) page:

| Platform | Binary | Notes |
|----------|--------|-------|
| Linux x86_64 (glibc) | `bluebox-linux-amd64` | Standard Linux |
| Linux aarch64 (glibc) | `bluebox-linux-arm64` | Raspberry Pi 4+, ARM servers |
| Linux x86_64 (musl) | `bluebox-linux-amd64-musl` | Static binary, works on any Linux |
| Linux aarch64 (musl) | `bluebox-linux-arm64-musl` | Static binary for ARM |

### Debian/Ubuntu (.deb package)

The easiest way to install on Debian-based systems:

```bash
# Download the .deb for your architecture
wget https://github.com/jeremie/bluebox/releases/latest/download/bluebox_amd64.deb
# or for ARM64 (Raspberry Pi 4+)
wget https://github.com/jeremie/bluebox/releases/latest/download/bluebox_arm64.deb

# Install
sudo dpkg -i bluebox_*.deb
```

The .deb package includes:
- Binary at `/usr/bin/bluebox`
- Example config at `/etc/bluebox/config.toml`
- Systemd service file
- Dedicated `bluebox` user/group for security

After installation:
```bash
# Edit the configuration
sudo nano /etc/bluebox/config.toml

# Enable and start the service
sudo systemctl enable bluebox
sudo systemctl start bluebox
```

### Docker

The easiest way to run Bluebox in a containerized environment:

```bash
# Pull the latest image
docker pull ghcr.io/jdrouet/bluebox:latest

# Run with default configuration
docker run --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --network host \
  ghcr.io/jdrouet/bluebox:latest

# Run with custom configuration
docker run --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --network host \
  -v $(pwd)/config.toml:/etc/bluebox/config.toml:ro \
  ghcr.io/jdrouet/bluebox:latest
```

**Important Docker Notes:**
- `--cap-add=NET_ADMIN` and `--cap-add=NET_RAW` are required for packet capture and ARP spoofing
- `--network host` is required to access the host's network interfaces
- Without these permissions, Bluebox cannot intercept DNS queries

#### Docker Compose

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  bluebox:
    image: ghcr.io/jdrouet/bluebox:latest
    container_name: bluebox
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./config.toml:/etc/bluebox/config.toml:ro
      # Optional: cache directory for remote blocklists
      - bluebox-cache:/var/cache/bluebox
    environment:
      - RUST_LOG=info
      - CONFIG_PATH=/etc/bluebox/config.toml
    restart: unless-stopped

volumes:
  bluebox-cache:
```

**Usage:**

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f bluebox

# Check status
docker-compose ps

# Restart after config changes
docker-compose restart bluebox

# Stop the service
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

**Example with metrics enabled:**

```yaml
version: '3.8'

services:
  bluebox:
    image: ghcr.io/jdrouet/bluebox:latest
    container_name: bluebox
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./config.toml:/etc/bluebox/config.toml:ro
      - bluebox-cache:/var/cache/bluebox
    environment:
      - RUST_LOG=info
      - CONFIG_PATH=/etc/bluebox/config.toml
    restart: unless-stopped
    # Expose metrics port (if metrics are enabled in config)
    # Note: with network_mode: host, this is informational only
    expose:
      - "9090"

  # Optional: Add Prometheus for metrics collection
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    network_mode: host
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    restart: unless-stopped

volumes:
  bluebox-cache:
  prometheus-data:
```

With this setup, create a `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'bluebox'
    static_configs:
      - targets: ['localhost:9090']
```

#### Building the Docker Image

To build the image yourself:

```bash
docker build -t bluebox:local .

# For multi-architecture builds
docker buildx build --platform linux/amd64,linux/arm64 -t bluebox:local .
```

### Building from Source

Requirements: Rust 1.75+ (edition 2024)

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
   sudo mkdir -p /etc/bluebox
   sudo cp config.toml /etc/bluebox/config.toml
   ```

4. Run as a systemd service (see [Systemd Service](#systemd-service) below)

Alternatively, download the pre-built `bluebox_arm64.deb` package for Raspberry Pi 4+.

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

# External blocklist sources (optional)
# Load blocklists from files or remote URLs
[[blocklist_sources]]
name = "steven-black-hosts"
enabled = true
source = { type = "remote", url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" }
format = "hosts"
refresh_interval_hours = 24

[[blocklist_sources]]
name = "local-custom"
enabled = true
source = { type = "file", path = "/etc/bluebox/custom-blocklist.txt" }
format = "domains"

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
| `blocklist_sources` | External blocklist sources (see below) | `[]` |
| `buffer_pool_size` | Size of packet buffer pool | 64 |
| `channel_capacity` | Packet queue capacity | 1000 |

### Blocklist Sources

You can load blocklists from local files or remote URLs. Each source has the following options:

| Option | Description | Default |
|--------|-------------|---------|
| `name` | Unique identifier for this source | Required |
| `enabled` | Whether to use this source | `true` |
| `source.type` | `file` or `remote` | Required |
| `source.path` | Path to local file (for `file` type) | - |
| `source.url` | URL to fetch (for `remote` type) | - |
| `format` | File format: `domains`, `hosts`, or `adblock` | `domains` |
| `refresh_interval_hours` | How often to refresh remote sources | - |

**Supported formats:**
- `domains` - One domain per line
- `hosts` - Standard hosts file format (e.g., `0.0.0.0 example.com`)
- `adblock` - AdBlock filter syntax (future support)

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

If you installed via the .deb package, the systemd service is already set up. Just enable and start it:

```bash
sudo systemctl enable bluebox
sudo systemctl start bluebox
sudo systemctl status bluebox
```

For manual installations, create `/etc/systemd/system/bluebox.service`:

```ini
[Unit]
Description=Bluebox DNS Interceptor and Cache
Documentation=https://github.com/jeremie/bluebox
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bluebox
Group=bluebox
ExecStart=/usr/bin/bluebox --config /etc/bluebox/config.toml
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/cache/bluebox

# Required for binding to port 53 and ARP spoofing
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

You'll also need to create the user and directories:

```bash
sudo addgroup --system bluebox
sudo adduser --system --ingroup bluebox --no-create-home --home /var/cache/bluebox bluebox
sudo mkdir -p /var/cache/bluebox
sudo chown bluebox:bluebox /var/cache/bluebox
```

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable bluebox
sudo systemctl start bluebox
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
- [x] External blocklist sources (file and remote URL)
- [x] Multiple blocklist formats (domains, hosts, adblock)

### Planned
- [ ] Web UI for configuration and statistics
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

### Docker: "Operation not permitted" or "Permission denied"

Make sure you're running with the required capabilities:
```bash
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW --network host ...
```

Without these capabilities, Bluebox cannot:
- Open raw sockets for packet capture
- Send ARP packets
- Modify network interfaces

### Docker: "Failed to find network interface"

When using `--network host`, Docker containers have access to the host's network interfaces. If you're specifying an interface in `config.toml`, make sure it exists on the host:

```bash
# List available interfaces on host
ip link show
```

### Docker: Container exits immediately

Check the logs:
```bash
docker logs <container-id>
```

Common issues:
- Missing required capabilities (`NET_ADMIN`, `NET_RAW`)
- Invalid configuration file path
- Interface specified in config doesn't exist

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
