# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/jdrouet/bluebox/releases/tag/v0.1.0) - 2026-01-31

### Added

- *(metrics)* add DNS query metrics with Prometheus exporter ([#14](https://github.com/jdrouet/bluebox/pull/14))
- *(blocklist)* implement BlocklistManager with hot-reload support ([#13](https://github.com/jdrouet/bluebox/pull/13))
- *(blocklist)* implement remote URL blocklist loader with caching ([#12](https://github.com/jdrouet/bluebox/pull/12))
- *(blocklist)* implement local file blocklist loader ([#11](https://github.com/jdrouet/bluebox/pull/11))
- *(blocklist)* implement blocklist format parsers ([#10](https://github.com/jdrouet/bluebox/pull/10))
- blocklist source abstraction and configuration schema ([#9](https://github.com/jdrouet/bluebox/pull/9))
- implement spoofing
- add tracing
- implement a blocking mechanism
- first working version

### Fixed

- remove Cargo.lock from gitignore
- address clippy issues

### Other

- configure release-plz
- update README with blocklist sources documentation
- make it cleaner
- add interface in config
- init project
