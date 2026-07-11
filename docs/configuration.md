# Configuration

[← Docs index](README.md) · [README](../README.md)

## Publish

```bash
php artisan vendor:publish --tag="passportless-config"
```

File: `config/passportless.php`.

## Important defaults

| Key | Default | Meaning |
| --- | --- | --- |
| `access_tokens_table` | `passportless_tokens` | Access token table |
| `refresh_tokens_table` | `passportless_refresh_tokens` | Refresh token table |
| `sessions_table` | `passportless_token_sessions` | Token session table |
| `guard` | `passportless` | Default guard name |
| `access_token.expiration` | `15` (minutes) | Access token / access cookie lifetime |
| `access_token.last_used_update_interval` | `60` (seconds) | Throttle `last_used_at` writes |
| `refresh_token.expiration` | `43200` (30 days, minutes) | Refresh + CSRF cookie lifetime |
| `refresh_token.reuse_detection` | `REVOKE_FAMILY` | Behavior on refresh reuse (`IGNORE` also available) |
| `abilities.default` | `['*']` | Default abilities when omitted |
| `abilities.wildcard_enabled` | `true` | Allow `*` ability |
| `token.max_length` | `120` | Max accepted plain-text token length |
| `cookie.domain` | `null` | Cookie domain |
| `cookie.secure` | `null` | `null` → Secure when `APP_ENV=production` |
| `cookie.same_site` | `lax` | SameSite policy |
| `cookie.access.path` | `/` | Access cookie path |
| `cookie.refresh.path` | `/api/auth` | Must match SPA route prefix |
| `cookie.csrf.path` | `/` | CSRF cookie path |
| `cookie.guards` | `[]` | Per-guard cookie overrides |

## Guard binding

Passportless resolves the authenticatable provider from the Laravel guard:

```text
auth.guards.{guard}.provider → auth.providers.{provider}.model
```

The default guard name is `config('passportless.guard')`. See [Multiple guards](multi-guard.md).

## Cookie safety

`PassportlessCookieManager` rejects invalid or unsafe configuration when resolved:

- Access and refresh cookies must remain HttpOnly
- Cookie names must be unique
- Paths must be absolute
- Token lifetimes must be positive integers
- `SameSite=None` requires Secure cookies

Per-guard overrides: `passportless.cookie.guards.{guard}`. The unscoped manager uses `passportless.guard` as fallback.

## Related

- [Browser cookies](browser-cookies.md)
- [Operations](operations.md) — audit with `passportless:doctor`
