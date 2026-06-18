# Changelog

All notable changes to this project are documented in this file.

## [2.0.0] - 2026-06-18

### Added

- Modern CSP directive support:
  - `worker-src`, `manifest-src`, `media-src`, `child-src`
  - `script-src-elem`, `script-src-attr`, `style-src-elem`, `style-src-attr`
  - `webrtc`, `trusted-types`, `sandbox`, `upgrade-insecure-requests`
- Separate `reportUri` (legacy) and `reportTo` (modern) options
- Policy presets: `strict`, `strict-dynamic`, `development`
- `formatNonce()`, `hashSource()`, `createNonceMiddleware()`, and `nonceDirective()`
- `getReportingEndpointsHeader()` for `Reporting-Endpoints` header setup
- TypeScript declarations generated from JSDoc
- Expanded test coverage and CI on Node.js 20, 22, and 24

### Changed

- **Breaking:** `reportTo` now maps to the `report-to` directive instead of deprecated `report-uri`
- **Breaking:** `getDirectives()` formats nonce values as quoted `'nonce-…'` source expressions
- **Breaking:** package `main` now points to `./index.js`
- **Breaking:** Node.js 18+ is required
- README rewritten for Helmet 7+ integration and modern CSP workflows
- `generateNonce()` accepts an optional byte length argument

### Removed

- Support for Node.js 14 and 16 in CI

## [1.1.2] - Previous release

- Initial public API with `generateNonce()` and `getDirectives()`
- Basic directive support for scripts, styles, fonts, connect, frame, images, and Trusted Types

[2.0.0]: https://github.com/xNifty/nonce-simple/compare/v1.1.2...v2.0.0
