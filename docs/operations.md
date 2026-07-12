# Operations

[← Docs index](README.md) · [README](../README.md)

## Configuration audit

```bash
php artisan passportless:doctor
```

Run after publishing config/migrations, and whenever guard, cookie, SPA route, or CORS settings change.

Checks:

- Passportless guard/provider bindings and model traits
- Effective cookie profiles
- Refresh-cookie path coverage for registered SPA refresh and logout routes
- Applicable credentialed CORS settings
- Required Passportless tables and columns

Reports only — never modifies application configuration, routes, or database schema. Exits nonzero on configuration errors or security recommendations.

## Prune stale tokens

```bash
php artisan passportless:prune-stale
php artisan passportless:prune-stale --hours=48
```

Deletes access and refresh tokens that have been expired or revoked for at least `--hours` (default `24`), then deletes orphaned token sessions with no remaining tokens.

Schedule in production if you accumulate tokens, for example in `routes/console.php` or the scheduler:

```php
Schedule::command('passportless:prune-stale')->daily();
```

## Related

- [Configuration](configuration.md)
- [Browser cookies](browser-cookies.md)
