//! Metrics initialization for Prometheus exporter.

use metrics_exporter_prometheus::PrometheusBuilder;

use crate::config::MetricsConfig;
use crate::error::Result;

/// Initialize the metrics system based on configuration.
///
/// When metrics are enabled, this starts an HTTP server that exposes
/// a `/metrics` endpoint for Prometheus to scrape.
///
/// When metrics are disabled, this is a no-op. The `metrics` crate
/// handles unregistered metrics gracefully (they become no-ops).
pub fn init(config: &MetricsConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    PrometheusBuilder::new()
        .with_http_listener(config.listen)
        .install()
        .map_err(crate::error::Error::Metrics)?;

    Ok(())
}
