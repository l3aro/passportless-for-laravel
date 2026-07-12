# Passportless Laravel Package

## Commands

- Requires PHP `^8.3`. Install dependencies with `composer install`; Composer's `post-autoload-dump` runs `composer prepare`, which calls `vendor/bin/testbench package:discover --ansi`.
- Run all tests: `composer test`. Run one file: `vendor/bin/pest tests/RefreshTokenTest.php`. Filter a test: `vendor/bin/pest --filter='name fragment'`.
- Run static analysis: `composer analyse`. PHPStan level 5 analyzes `src`, `config`, and `database`; keep baseline changes intentional.
- Format PHP: `composer format`. Pint uses the `per` preset. CI auto-commits Pint fixes, so format before push.
- Runtime supports Laravel 11 through 13; CI runs Pest against Laravel 12 and 13 on PHP 8.3, 8.4, and 8.5 with both `prefer-lowest` and `prefer-stable` dependencies. Avoid relying on undeclared transitive APIs.

## Package Map

- `src/PassportlessServiceProvider.php` is the Laravel integration entrypoint: provider registrations, the `passportless` guard, middleware aliases, publish tags, and commands.
- `src/Passportless.php` owns token issuance, lookup, refresh rotation, and revocation. Keep token lifecycle behavior here; expose model-level convenience through `src/Concerns/HasPassportless.php`.
- `config/passportless.php` is the source of defaults for token expiry, abilities, and per-guard cookie behavior. Migration schema is the publishable stub at `database/migrations/create_passportless_tables.php.stub`.
- The package supports bearer-token API auth and optional cookie-based SPA auth. Preserve bearer-header precedence and cover both paths when changing authenticator, cookie, middleware, or session behavior.
- Public Laravel surfaces include guard `passportless`, middleware `abilities`, `ability`, `passportless.csrf`, and `passportless.origin`, plus `Route::passportlessSpaAuth()`.

## Tests

- Pest applies `tests/TestCase.php` to all tests. It uses Orchestra Testbench, registers the package provider, and configures a testing database; no host Laravel application is required.
- Tests define their own schema and test-only models inline. Match the nearby test's `beforeEach()` setup instead of assuming the publishable migration runs.
- After changing auth guard or provider config in a test, call `Auth::forgetGuards()` before asserting behavior.
- Keep architecture tests in `tests/ArchTest.php` passing; the suite runs Pest's PHP, security, Laravel, and relaxed presets.

## Verification

- For PHP changes, run `composer format`, `composer analyse`, then focused Pest tests; run `composer test` for cross-cutting auth, schema, provider, or routing changes.
- PHPUnit runs tests in random order and fails on warnings, risky tests, empty suites, and unexpected output. Do not depend on test execution order or emit debug output.
