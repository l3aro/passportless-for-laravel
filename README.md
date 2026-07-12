# Passportless for Laravel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/l3aro/passportless-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/passportless-for-laravel)
[![GitHub Tests Action Status](https://github.com/l3aro/passportless-for-laravel/actions/workflows/run-tests.yml/badge.svg)](https://github.com/l3aro/passportless-for-laravel/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://github.com/l3aro/passportless-for-laravel/actions/workflows/fix-php-code-style-issues.yml/badge.svg)](https://github.com/l3aro/passportless-for-laravel/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/l3aro/passportless-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/passportless-for-laravel)

**API token authentication for first-party Laravel apps** — personal access tokens, optional refresh-token rotation, token sessions, and ability checks. No OAuth2 server.

Abilities are simple permission strings on access tokens. They are not OAuth scopes.

## When to use

| Use Passportless when…                                                                               | Prefer something else when…                                                                                                                    |
| ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Your Laravel app issues tokens for **its own** clients (mobile, CLI, internal API, server-to-server) | You need a full **OAuth2** authorization server → [Laravel Passport](https://laravel.com/docs/passport)                                        |
| You want hashed access tokens + optional refresh rotation without OAuth clients/redirects            | You mainly need **SPA session cookies** with Laravel’s first-party stack → [Laravel Sanctum](https://laravel.com/docs/sanctum) is often enough |
| You want low ops: publish migrations, register a guard, protect routes                               | You need third-party delegated access, authorization-code grants, or OAuth clients                                                             |

**Two client paths** (same package):

1. **API / mobile / CLI** — `Authorization: Bearer {token}` (this quick start)
2. **Browser SPA** — optional HTTP-only cookies + CSRF → [docs/browser-cookies.md](docs/browser-cookies.md)

## Quick start

### 1. Install

```bash
composer require l3aro/passportless-for-laravel

php artisan vendor:publish --tag="passportless-migrations"
php artisan migrate
```

Optional config:

```bash
php artisan vendor:publish --tag="passportless-config"
```

### 2. Register the guard

In `config/auth.php`:

```php
'guards' => [
    'passportless' => [
        'driver' => 'passportless',
        'provider' => 'users',
    ],
],
```

Provider should already point at your user model (`providers.users.model`).

### 3. Add the trait

```php
use l3aro\Passportless\Concerns\HasPassportless;

class User extends Authenticatable
{
    use HasPassportless;
}
```

### 4. Issue a token and call your API

```php
$token = $user->createToken('iphone', ['orders:read', 'orders:write']);

// Show / store the plain-text token once. It is not stored in the database.
return ['token' => $token->plainTextToken];
```

Protect a route:

```php
Route::get('/orders', OrdersController::class)
    ->middleware(['auth:passportless', 'abilities:orders:read']);
```

Client request:

```http
GET /orders HTTP/1.1
Authorization: Bearer 1|your-plain-text-token
Accept: application/json
```

```php
Http::withToken($plainTextToken)->get('/api/orders');
```

That’s the core loop.

## Next steps

| Guide                                      | Topic                                                        |
| ------------------------------------------ | ------------------------------------------------------------ |
| [API tokens](docs/api-tokens.md)           | Abilities, middleware, refresh pairs, logout, listing tokens |
| [Browser cookies](docs/browser-cookies.md) | SPA HttpOnly cookies, SPA routes, CSRF, CORS                 |
| [Multiple guards](docs/multi-guard.md)     | Users vs staff (separate identity models)                    |
| [Configuration](docs/configuration.md)     | Expirations, reuse detection, cookie settings                |
| [Operations](docs/operations.md)           | `passportless:doctor`, `passportless:prune-stale`            |
| [Testing](docs/testing.md)                 | Host-app test helpers                                        |
| [Docs index](docs/README.md)               | Full documentation map                                       |

## Features

- Hashed personal access tokens
- Optional refresh-token rotation with reuse detection
- Token sessions (group and revoke related tokens)
- Laravel guard + middleware (`auth:passportless`, `abilities`, `ability`)
- `tokenCan` / `tokenCannot` on the authenticated user
- Optional HTTP-only cookie helpers and SPA auth routes
- `passportless:doctor` and `passportless:prune-stale`

## Comparison

|             | Passportless                                        | Laravel Passport              | Laravel Sanctum                      |
| ----------- | --------------------------------------------------- | ----------------------------- | ------------------------------------ |
| OAuth2      | No                                                  | Yes                           | No                                   |
| Best fit    | First-party API tokens (mobile, CLI, internal APIs) | Third-party / delegated OAuth | SPAs + simple personal access tokens |
| Ops cost    | Low                                                 | High                          | Low                                  |
| Permissions | Token abilities                                     | OAuth scopes                  | Token abilities                      |
| Extras      | Refresh rotation, sessions, cookie helpers          | Full OAuth server             | SPA cookie auth, CSRF                |

## Changelog

See [CHANGELOG](CHANGELOG.md).

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md).

## Security Vulnerabilities

See [our security policy](../../security/policy).

## Credits

- [l3aro](https://github.com/l3aro)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). See [License File](LICENSE.md).
