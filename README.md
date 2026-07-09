# Passportless for Laravel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/l3aro/passportless-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/passportless-for-laravel)
[![GitHub Tests Action Status](https://github.com/l3aro/passportless-for-laravel/actions/workflows/run-tests.yml/badge.svg)](https://github.com/l3aro/passportless-for-laravel/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://github.com/l3aro/passportless-for-laravel/actions/workflows/fix-php-code-style-issues.yml/badge.svg)](https://github.com/l3aro/passportless-for-laravel/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/l3aro/passportless-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/passportless-for-laravel)

Passportless provides API token authentication for Laravel applications that need personal access tokens, optional refresh-token rotation, token sessions, and ability checks without running an OAuth2 server. Abilities are simple permission strings attached to access tokens; they are not OAuth scopes and do not add OAuth2 grant flows.

## Features

- Hashed personal access tokens for API authentication.
- Optional refresh-token rotation with reuse detection.
- Token sessions for grouping and revoking related tokens.
- Laravel guard and middleware integration.
- Simple token ability checks with `tokenCan` and `tokenCannot`.
- HTTP-only cookie helpers for browser access, refresh, and CSRF cookies.

## Purpose and comparison

Passportless is built for applications where your own Laravel app issues and validates tokens for your own clients, such as mobile apps, CLIs, internal APIs, and server-to-server integrations. It keeps token authentication small and explicit: hashed access tokens, optional refresh tokens with reuse detection, guard integration, and `tokenCan` / `tokenCannot` ability checks.

Use Passportless when your Laravel app should issue and validate its own API tokens without OAuth clients, authorization-code redirects, client secrets, or delegated third-party access flows. Compared with Laravel Passport and Laravel Sanctum:

| Aspect | Passportless for Laravel | Laravel Passport | Laravel Sanctum |
| --- | --- | --- | --- |
| Primary purpose | API token authentication owned by your Laravel app | Full OAuth2 authorization server | SPA authentication and simple API tokens |
| OAuth2 support | No | Yes | No |
| Features | Access tokens, optional refresh-token rotation, token sessions, guard/middleware integration, ability checks, cookie helpers | OAuth2 clients, grants, scopes, refresh tokens, authorization-code redirects | Personal access tokens, SPA cookie authentication, CSRF protection |
| Token model | Hashed access tokens with optional rotated refresh tokens | OAuth2 access tokens, refresh tokens, clients, and scopes | Personal access tokens and cookie-based SPA sessions |
| Permissions | Simple token abilities | OAuth2 scopes | Token abilities |
| Best fit | Mobile apps, CLIs, internal APIs, server-to-server tokens | Third-party integrations and delegated OAuth access | Laravel SPAs and simple personal access tokens |
| Operational complexity | Low: publish migrations/config, use guard and middleware | High: keys, clients, grants, redirects, scopes | Low: token table and optional SPA cookie setup |

## Installation

You can install the package via composer:

```bash
composer require l3aro/passportless-for-laravel
```

You can publish and run the migrations with:

```bash
php artisan vendor:publish --tag="passportless-migrations"
php artisan migrate
```

You can publish the config file with:

```bash
php artisan vendor:publish --tag="passportless-config"
```

The published `config/passportless.php` file contains token storage, guard, expiration, reuse detection, ability, and token parsing settings:

```php
return [
    'access_tokens_table' => 'passportless_tokens',
    'refresh_tokens_table' => 'passportless_refresh_tokens',
    'sessions_table' => 'passportless_token_sessions',
    'guard' => 'passportless',
    // ...
];
```

Define the Passportless guard and provider in `config/auth.php`:

```php
'guards' => [
    'passportless' => [
        'driver' => 'passportless',
        'provider' => 'users',
    ],
],

'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => App\Models\User::class,
    ],
],
```

Passportless derives the authenticatable provider from the selected Laravel guard, for example `auth.guards.passportless.provider`.

## Usage

```php
use l3aro\Passportless\Concerns\HasPassportless;

class User extends Authenticatable
{
    use HasPassportless;
}

$token = $user->createToken('iphone', ['orders:read', 'orders:write']);

return ['token' => $token->plainTextToken];
```

Use `tokenCan` and `tokenCannot` to check the current access token abilities:

```php
if ($request->user()->tokenCan('orders:read')) {
    // ...
}
```

Use `*` to create a token that can perform every ability:

```php
$token = $user->createToken('admin', ['*']);
```

Protect routes with middleware aliases registered by the package:

```php
Route::get('/orders', OrdersController::class)
    ->middleware(['auth:passportless', 'abilities:orders:read']);

Route::post('/orders', OrdersController::class)
    ->middleware(['auth:passportless', 'ability:orders:write,orders:admin']);
```

## Multiple authenticatable models

Use separate Passportless guards when one app issues tokens for separate identity stores, such as users and staff. `config/auth.php` owns guards, providers, and models:

```php
'guards' => [
    'passportless-client' => [
        'driver' => 'passportless',
        'provider' => 'users',
    ],
    'passportless-admin' => [
        'driver' => 'passportless',
        'provider' => 'staff',
    ],
],

'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => App\Models\User::class,
    ],
    'staff' => [
        'driver' => 'eloquent',
        'model' => App\Models\Staff::class,
    ],
],
```

Set the default Passportless guard in `config/passportless.php`, or select another guard explicitly when issuing tokens:

```php
$clientToken = $user->createToken('iphone');
$staffPair = $staff->createTokenPair('admin-browser', ['staff:read'], guard: 'passportless-admin');
```

Protect each route with its matching Laravel guard:

```php
Route::get('/me', ClientProfileController::class)->middleware('auth:passportless-client');
Route::get('/admin/me', StaffProfileController::class)->middleware('auth:passportless-admin');
```

Guards and providers are identity boundaries. Use policies or gates for current business authorization; token abilities remain per-token permissions and should not be the only proof of staff status.

Passportless validates that the token owner model matches the provider model for the resolved guard. A `User` cannot mint or authenticate a `passportless-admin` token when that guard points to `App\Models\Staff`.

## Best practice: browser authentication with HTTP-only cookies

For browser clients, issue both the access token and refresh token as HTTP-only cookies with `PassportlessCookieManager`. Do not expose either token in JSON responses, JavaScript-readable cookies, local storage, or session storage. JavaScript should only receive non-secret response data and, when needed, a separate CSRF value.

Use a short-lived access cookie for normal API requests and a refresh cookie for a dedicated refresh endpoint. On login, create a token pair, attach both cookies to the response, and send a CSRF cookie or response value for double-submit CSRF protection:

```php
use Illuminate\Support\Str;
use l3aro\Passportless\PassportlessCookieManager;

Route::post('/auth/login', function (PassportlessCookieManager $cookies) {
    $pair = auth()->user()->createTokenPair('browser');
    $csrf = Str::random(40);

    return response()->json(['csrf_token' => $csrf])
        ->withCookie($cookies->createAccessCookie($pair->plainTextAccessToken()))
        ->withCookie($cookies->createRefreshCookie($pair->plainTextRefreshToken()))
        ->withCookie($cookies->createCsrfCookie($csrf));
});
```

Read the access token from the configured access cookie inside host-owned authentication middleware or routes, then let `auth:passportless` protect API routes. When the access token expires, call a refresh route that reads only the refresh cookie, rotates the token pair, returns replacement access and refresh cookies, and rejects reused refresh tokens.

Keep access and refresh cookies `HttpOnly`, use `Secure` cookies over HTTPS, and choose the narrowest practical cookie path and domain. Same-origin browser clients can use Fetch `credentials: 'same-origin'`; cross-origin clients must use `credentials: 'include'`, explicit CORS origins, credential support, CSRF protection, and `SameSite=None` with `Secure=true` when cookies are cross-site.

## Browser cookies

Passportless provides `l3aro\Passportless\PassportlessCookieManager` for host-owned browser routes that want access, refresh, and CSRF cookies. The manager is container-resolved as a singleton and returns Symfony `Cookie` objects only; it does not register routes, mutate responses, or queue cookies.

```php
use l3aro\Passportless\PassportlessCookieManager;

Route::post('/auth/login', function (PassportlessCookieManager $cookies) {
    $pair = auth()->user()->createTokenPair('browser');
    $csrf = Str::random(40);

    return response()->json(['csrf_token' => $csrf])
        ->withCookie($cookies->createAccessCookie($pair->plainTextAccessToken()))
        ->withCookie($cookies->createRefreshCookie($pair->plainTextRefreshToken()))
        ->withCookie($cookies->createCsrfCookie($csrf));
});
```

The published `passportless.cookie` config owns cookie names, paths, domain, Secure flag, SameSite policy, and role-specific HttpOnly flags. Defaults are first-party browser defaults: access and refresh cookies are HttpOnly, the CSRF cookie is readable by JavaScript, SameSite is `lax`, access and CSRF paths are `/`, refresh path is `/api/auth/refresh`, and Secure is enabled when `APP_ENV=production`. Access cookie lifetime follows `passportless.access_token.expiration`; refresh and CSRF cookie lifetimes follow `passportless.refresh_token.expiration`. Deletion methods use the same configured name, path, domain, Secure, HttpOnly, and SameSite attributes as issuance.

The manager rejects invalid or unsafe configuration when resolved. Access and refresh cookies must remain HttpOnly, cookie names must be unique, paths must be absolute, token lifetimes must be positive integers, and `SameSite=None` requires Secure cookies.

Use configured names when reading cookies in host middleware or routes:

```php
$request->cookie($cookies->refreshCookieName());
$cookies->forgetAccessCookie();
$cookies->forgetRefreshCookie();
$cookies->forgetCsrfCookie();
```

Same-origin browser clients generally do not need CORS and can use Fetch `credentials: 'same-origin'`. Cross-origin clients must use `credentials: 'include'`, explicit allowed origins, and host-owned Laravel CORS configuration with credential support; wildcard origins are not valid for credentialed CORS. Cross-site cookies must be configured with `SameSite=None` and `Secure=true`. CORS controls browser access to cross-origin responses and does not authenticate requests or replace CSRF protection.

Laravel's `EncryptCookies` middleware encrypts response cookies and decrypts request cookies by default. Keep access and refresh tokens HttpOnly and unavailable to JavaScript. If your double-submit CSRF design requires JavaScript to read the CSRF cookie, configure the host application's cookie encryption exclusions for that CSRF cookie name; Passportless cannot infer that safely for every application.

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [l3aro](https://github.com/l3aro)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
