# Changelog

All notable changes to Passportless will be documented in this file.

## v1.2.0 - 2026-07-12

### What's Changed

* SPA auth: same-origin middleware, refresh-token revocation, cacheable handlers, cookie path fix by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/7
* feat: add session-level revocation service by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/8
* refactor: consolidate session revocation, remove final from AuthBinding, update arch tests by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/9
* Add passportless doctor command by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/10
* feat: add InteractsWithPassportless testing trait by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/11
* fix: allow apostrophes in cookie names by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/12
* feat: add logoutCurrentSession and logoutAllSessions methods by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/13
* chore: code cleanup — Pint style fixes, Pint config, docs restructure by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/14

**Full Changelog**: https://github.com/l3aro/passportless-for-laravel/compare/v1.1.3...v1.2.0

## v1.1.3 - 2026-07-10

### What's Changed

* Cookie auth, CSRF middleware, guard-scoped access cookies by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/6

**Full Changelog**: https://github.com/l3aro/passportless-for-laravel/compare/v1.1.2...v1.1.3

## v1.1.2 - 2026-07-09

### What's Changed

* fix: derive provider from guard config, remove passportless.provider by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/4
* docs: deduplicate and reorganize browser cookie sections in README by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/5

**Full Changelog**: https://github.com/l3aro/passportless-for-laravel/compare/v1.1.1...v1.1.2

## v1.1.1 - 2026-07-08

### What's Changed

* feat: multi-guard cookie configuration and refresh isolation by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/3

**Full Changelog**: https://github.com/l3aro/passportless-for-laravel/compare/v1.1.0...v1.1.1

## v1.1.0 - 2026-07-07

### What's Changed

* Support multiple authenticatable models with named guards by @l3aro in https://github.com/l3aro/passportless-for-laravel/pull/2

**Full Changelog**: https://github.com/l3aro/passportless-for-laravel/compare/v1.0.1...v1.1.0

## v1.0.0 - 2026-07-07

- Hashed personal access tokens for API authentication.
- Optional refresh-token rotation with reuse detection.
- Token sessions for grouping and revoking related tokens.
- Laravel guard and middleware integration.
- Simple token ability checks with tokenCan and tokenCannot.
- HTTP-only cookie helpers for browser access, refresh, and CSRF cookies.

**Full Changelog**: https://github.com/l3aro/passportless-for-laravel/commits/v1.0.0
