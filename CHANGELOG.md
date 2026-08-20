# Changelog

All notable changes to this project will be documented in this file.

## 1.0.1 - 2026-08-20

Packaging and developer-experience release.

- Added npm package metadata, exports, changelog, and publish verification.
- Split optional database integration into the `@kowalski21/tsrad/db` subpath.
- Improved packaged-consumer and integration test reliability.

## 1.0.0 - 2026-08-19

Initial npm release.

- RADIUS authentication, accounting, CoA, Disconnect, and Status-Server support.
- UDP over IPv4 and IPv6, plus RadSec over TLS.
- FreeRADIUS-compatible dictionaries, vendor attributes, TLVs, and RFC 6929 extended attributes.
- Client failover, proxy routing, middleware, deduplication, rate limiting, metrics, and structured logging.
- Optional Knex-based FreeRADIUS `rlm_sql` database integration through `@kowalski21/tsrad/db`.
- Promise-based client/server APIs and pyrad compatibility aliases.
