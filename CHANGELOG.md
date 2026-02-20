# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/jdrouet/bluebox/compare/v0.1.2...v0.1.3) - 2026-02-20

### Added

- add env variable to load config path

### Fixed

- remove duplicate context from error messages

### Other

- bump proptest from 1.9.0 to 1.10.0 ([#29](https://github.com/jdrouet/bluebox/pull/29))
- bump toml from 0.8.23 to 0.9.11+spec-1.1.0 ([#30](https://github.com/jdrouet/bluebox/pull/30))
- bump criterion from 0.5.1 to 0.8.2 ([#31](https://github.com/jdrouet/bluebox/pull/31))
- bump anyhow from 1.0.100 to 1.0.101 ([#32](https://github.com/jdrouet/bluebox/pull/32))
- bump bytes from 1.11.0 to 1.11.1 ([#28](https://github.com/jdrouet/bluebox/pull/28))
- add workflow to release docker image
- create dockerfile based on alpine
- simplify release workflow using cross for musl builds
- fix binary release

## [0.1.2](https://github.com/jdrouet/bluebox/compare/v0.1.1...v0.1.2) - 2026-02-01

### Fixed

- build deb packages with musl for broader compatibility ([#25](https://github.com/jdrouet/bluebox/pull/25))

## [0.1.1](https://github.com/jdrouet/bluebox/compare/v0.1.0...v0.1.1) - 2026-02-01

### Added

- *(release)* add manual workflow trigger, musl builds, and deb packaging

### Fixed

- remove Cargo.lock from gitignore

### Other

- bump hickory-proto from 0.24.4 to 0.25.2 ([#21](https://github.com/jdrouet/bluebox/pull/21))
- increase code coverage from 82% to 88% ([#24](https://github.com/jdrouet/bluebox/pull/24))
- bump thiserror from 1.0.69 to 2.0.18 ([#22](https://github.com/jdrouet/bluebox/pull/22))
- bump metrics-exporter-prometheus from 0.16.2 to 0.18.1 ([#23](https://github.com/jdrouet/bluebox/pull/23))
- bump moka from 0.12.12 to 0.12.13 ([#20](https://github.com/jdrouet/bluebox/pull/20))
- bump pnet from 0.34.0 to 0.35.0 ([#19](https://github.com/jdrouet/bluebox/pull/19))
- bump codecov/codecov-action from 4 to 5 ([#18](https://github.com/jdrouet/bluebox/pull/18))
- bump actions/checkout from 4 to 6 ([#17](https://github.com/jdrouet/bluebox/pull/17))
- add dependabot configuration for cargo and github-actions
- update README with installation instructions for pre-built binaries and deb packages
- release v0.1.0 ([#15](https://github.com/jdrouet/bluebox/pull/15))
- allow trigger release binaries manually

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
