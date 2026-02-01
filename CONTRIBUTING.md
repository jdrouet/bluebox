# Contributing to Bluebox

Thank you for your interest in contributing to Bluebox! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Prerequisites**
   - Rust 1.75+ (edition 2024)
   - Root/sudo access (required for raw packet capture)

2. **Clone and build**
   ```bash
   git clone https://github.com/jeremie/bluebox.git
   cd bluebox
   cargo build
   ```

3. **Run tests**
   ```bash
   cargo test
   ```

4. **Run with sudo** (required for packet capture)
   ```bash
   sudo cargo run
   ```

## Code Style

We use standard Rust formatting and linting:

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy --all-targets --all-features
```

The CI will reject PRs that don't pass `cargo fmt --check` and `cargo clippy`.

### Linting Configuration

We use pedantic clippy lints. The full configuration is in `Cargo.toml`. Key rules:
- No unsafe code (`unsafe_code = "forbid"`)
- All warnings treated as errors in CI

### Naming Conventions

**Error variables**: Use descriptive names for error variables, not single letters.

```rust
// Good
if let Err(err) = operation() {
    warn!("Operation failed: {}", err);
}

match result {
    Ok(value) => process(value),
    Err(load_err) => handle_error(load_err),
}

// Avoid
if let Err(e) = operation() {
    warn!("Operation failed: {}", e);
}
```

### Comments

Avoid large separator comments or ASCII art banners. Use simple doc comments and let the code structure speak for itself.

```rust
// Good - simple module documentation
/// Handles blocklist loading from various sources.

// Avoid - decorative separators
// =============================================================================
// Blocklist Loading
// =============================================================================
```

### String Formatting

Use inline format syntax (captured identifiers) instead of positional arguments when possible. This is more concise and readable.

```rust
// Good - inline format syntax
format!("{value:?}");
println!("Hello {name}!");
error!("Failed to load: {err}");

// Avoid - positional arguments
format!("{:?}", value);
println!("Hello {}!", name);
error!("Failed to load: {}", err);
```

Note: Inline syntax only works with simple identifiers. For method calls or field access, positional arguments are still required:

```rust
// These require positional arguments (method calls / field access)
info!("Count: {}", items.len());
info!("Name: {}", config.name);
```

## Architecture

The codebase is organized into modules with clear responsibilities:

```
src/
├── main.rs          # Entry point, wiring
├── lib.rs           # Library exports
├── config.rs        # Configuration
├── error.rs         # Error types
├── dns/
│   ├── blocker.rs   # Domain blocking
│   └── resolver.rs  # DNS resolution
├── cache/
│   └── dns_cache.rs # Caching
├── network/
│   ├── buffer.rs    # Buffer pooling
│   ├── capture.rs   # Packet capture
│   └── packet.rs    # Packet construction
└── server.rs        # Server orchestration
```

### Design Principles

1. **Trait-based abstractions**: All major components have trait definitions to enable testing
2. **Minimize allocations**: Use buffer pools and avoid unnecessary heap allocations
3. **Testability**: Every module should be testable without network access
4. **Clear error handling**: Use `thiserror` for typed errors
5. **Debug formatting**: In error messages and logs, prefer `{:?}` over `{}` for interpolating values. This ensures consistent debug output and avoids potential issues with Display implementations.

   ```rust
   // Good
   tracing::error!(name = ?source.name, "failed to load blocklist");
   return Err(ValidationError::InvalidUrl { url: url.clone() });
   
   // Avoid
   tracing::error!("failed to load blocklist: {}", source.name);
   ```

### Error Message Formatting

When defining error types with `thiserror`, **do not include the source error in the `#[error]` message**. The error chain is automatically handled by `anyhow` when displaying errors. Including the source creates duplicate information in error output.

```rust
// Good - source is not included in the message
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file")]
    ReadFile(#[source] std::io::Error),

    #[error("failed to parse config")]
    Parse(#[source] toml::de::Error),
}

// Avoid - source is duplicated in the message
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadFile(#[source] std::io::Error),

    #[error("failed to parse config: {0}")]
    Parse(#[source] toml::de::Error),
}
```

With the correct approach, error output looks clean:

```
Error: Failed to load configuration

Caused by:
    0: configuration error
    1: failed to read config file
    2: No such file or directory (os error 2)
```

With the incorrect approach, you get duplicated information:

```
Error: Failed to load configuration

Caused by:
    0: configuration error: failed to read config file: No such file or directory (os error 2)
    1: failed to read config file: No such file or directory (os error 2)
    2: No such file or directory (os error 2)
```

**Exception**: Include context directly in the message when it's not from a source error:

```rust
// Good - url and status are not source errors, they're context
#[error("HTTP request failed for {url}: status {status}")]
HttpStatus { url: String, status: u16 },

// Good - path is context, source is separate
#[error("I/O error reading {path:?}")]
Io {
    path: PathBuf,
    #[source]
    source: std::io::Error,
},
```

## Testing

### Test Naming Convention

Test functions should describe what they're testing using the pattern `should_X_when_Y` rather than starting with `test_`. This makes test output more readable and self-documenting.

```rust
// Good - describes the expected behavior
#[test]
fn should_block_domain_when_exact_match() { ... }

#[test]
fn should_return_empty_vec_when_file_is_empty() { ... }

#[test]
fn should_skip_comments_when_line_starts_with_hash() { ... }

// Avoid - doesn't describe the behavior
#[test]
fn test_blocker() { ... }

#[test]
fn test_empty_file() { ... }
```

### Unit Tests

Each module contains its own unit tests. Run them with:

```bash
cargo test
```

### Integration Tests

Located in `tests/`. These test the full query handling flow with mock components:

```bash
cargo test --test integration
```

### Benchmarks

Performance-critical code has benchmarks in `benches/`:

```bash
cargo bench
```

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Write tests**: All new functionality should have tests
3. **Run checks locally**:
   ```bash
   cargo fmt
   cargo clippy --all-targets --all-features
   cargo test
   ```
4. **Create PR**: Describe your changes clearly
5. **CI must pass**: All checks must be green

### Commit Messages

Use clear, descriptive commit messages:
- `feat: add DNS-over-HTTPS support`
- `fix: handle malformed DNS packets gracefully`
- `refactor: simplify buffer pool implementation`
- `test: add property tests for blocker`
- `docs: update README with configuration options`

## Adding New Features

1. **Start with the trait**: Define the interface first
2. **Implement with tests**: Write tests alongside implementation
3. **Add mock implementation**: For testing dependent code
4. **Update documentation**: Keep docs in sync with code

### Example: Adding a New Resolver Type

```rust
// 1. Implement the trait
impl DnsResolver for DohResolver {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        // Implementation
    }
}

// 2. Add tests
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn should_resolve_query_when_upstream_available() {
        // Test with mock HTTP client
    }
}
```

## Performance Considerations

Bluebox is designed for speed. When contributing:

1. **Avoid allocations in hot paths**: Use buffer pools
2. **Profile before optimizing**: Use `cargo bench` to measure
3. **Consider cache friendliness**: Keep hot data together
4. **Document complexity**: Note O(n) characteristics

## Questions?

Open an issue for questions or discussions about proposed changes.
