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

For browser cookie write routes, optional double-submit CSRF middleware is available as `passportless.csrf`. See [Browser cookies](#browser-cookies).

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

## Browser cookies

For browser clients, issue access and refresh tokens as HTTP-only cookies with `PassportlessCookieManager`. Do not put either token in JSON responses, JavaScript-readable cookies, local storage, or session storage. JavaScript should only receive non-secret response data and, when needed, a separate CSRF value.

`PassportlessCookieManager` is container-resolved as a singleton and returns Symfony `Cookie` objects only. It does not mutate responses or queue cookies. By default the host owns login, refresh, logout, CORS, CSRF value generation, cookie attachment, route coverage, and cookie encryption exclusions. Hosts may opt into package SPA cookie routes with `Route::passportlessSpaAuth(...)`.

Recommended flow:

1. On login, create a token pair, attach access + refresh cookies, and send a CSRF cookie or response value for double-submit CSRF protection.
2. Protect APIs with `auth:passportless` (or a named Passportless guard). The guard authenticates from `Authorization: Bearer` first, then from the configured guard-scoped access cookie when no bearer token is present. It does not mutate the request `Authorization` header.
3. When the access token expires, call a refresh route that reads only the refresh cookie, rotates the pair, returns replacement cookies, and rejects reused refresh tokens.
4. Keep access and refresh cookies `HttpOnly`, use `Secure` over HTTPS, and choose the narrowest practical cookie path and domain.
5. Protect unsafe cookie-authenticated methods with CSRF validation. CSRF is separate from guard authentication.

### Optional SPA cookie routes

Register the common browser cookie endpoints with one call per guard. Routes are never auto-loaded.

```php
use App\Models\Staff;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;

final class AuthenticateUser
{
    public function __invoke(\Illuminate\Http\Request $request): ?User
    {
        $user = User::query()->where('email', $request->input('email'))->first();

        if ($user === null || ! Hash::check((string) $request->input('password'), $user->password)) {
            return null;
        }

        return $user;
    }
}

final class AuthenticateStaff
{
    public function __invoke(\Illuminate\Http\Request $request): ?Staff
    {
        $staff = Staff::query()->where('email', $request->input('email'))->first();

        if ($staff === null || ! Hash::check((string) $request->input('password'), $staff->password)) {
            return null;
        }

        return $staff;
    }
}

Route::passportlessSpaAuth(
    prefix: 'api/auth',
    guard: 'passportless',
    authenticate: AuthenticateUser::class,
    abilities: ['demo:read'],
    loginMiddleware: ['throttle:login'],
    refreshMiddleware: ['throttle:refresh'],
);

Route::passportlessSpaAuth(
    prefix: 'api/auth/admin',
    guard: 'passportless-admin',
    authenticate: AuthenticateStaff::class,
    abilities: ['admin:read'],
);
```

Registered endpoints for each call:

- `POST {prefix}/login`
- `POST {prefix}/refresh`
- `POST {prefix}/logout`

Behavior:

- Host `authenticate` must be a container-resolvable invokable class or `Class@method` string. It owns credential verification and returns an authenticatable or `null`/`false`; closures are not supported because routes must be cacheable.
- Login issues a token pair, attaches guard-scoped cookies, and returns fixed non-secret JSON (`token_type`, expirations, optional `csrf_token`, `session`).
- Refresh reads the refresh cookie, enforces the expected guard, rotates the pair, and never returns plain access/refresh tokens in JSON.
- Logout revokes the session from either active access or refresh cookie, then forgets access/refresh/CSRF cookies.
- When `csrf: true` (default), package same-origin middleware protects login and CSRF middleware protects refresh and logout.
- Align `passportless.cookie.guards.{guard}.refresh.path` with the SPA route prefix so browsers send it to both refresh and logout; the default `/api/auth` matches the example.
- Hosts still own CORS, `EncryptCookies` exclusions, and throttle middleware.

Manual cookie construction remains available for custom response shapes:

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

### Optional CSRF middleware

Passportless ships optional route middleware alias `passportless.csrf` for double-submit CSRF validation of browser cookie flows. It is opt-in. Host apps that already use Laravel session CSRF or another strategy may keep their existing protection.

Behavior:

- Skips safe methods: `GET`, `HEAD`, and `OPTIONS`.
- Compares the configured CSRF cookie to the `X-CSRF-TOKEN` header with timing-safe comparison.
- Accepts an optional guard parameter and uses `PassportlessCookieManager::forGuard($guard)` when supplied.
- Fails closed with HTTP `419` and a generic mismatch message when either value is missing, empty, or mismatched.

Single-guard browser write routes:

```php
Route::middleware(['passportless.csrf', 'auth:passportless'])->post('/profile', ...);
```

Multi-guard browser write routes:

```php
Route::middleware(['passportless.csrf:passportless-admin', 'auth:passportless-admin'])
    ->post('/admin/profile', ...);
```

The middleware does not authenticate users, rotate tokens, attach cookies, or generate CSRF values. Host applications still own CSRF value generation, cookie attachment, CORS, route coverage, middleware ordering, and excluding the JavaScript-readable CSRF cookie from encryption when needed.

For a multi-guard browser app, scope the manager once per flow and protect each route with its matching guard:

```php
$cookies = app(PassportlessCookieManager::class)->forGuard('passportless-admin');

Route::get('/admin/me', AdminProfileController::class)
    ->middleware('auth:passportless-admin');

Route::post('/admin/profile', AdminProfileController::class)
    ->middleware(['passportless.csrf:passportless-admin', 'auth:passportless-admin']);
```

`auth:passportless-admin` reads the `passportless-admin` access cookie profile. Cookie names and paths are delivery controls only; stored guard and provider snapshots remain authoritative for token identity.

Read and clear cookies with the configured names:

```php
$request->cookie($cookies->refreshCookieName());
$cookies->forgetAccessCookie();
$cookies->forgetRefreshCookie();
$cookies->forgetCsrfCookie();
```

### Cookie configuration

`passportless.cookie` owns names, paths, domain, Secure flag, SameSite policy, and role-specific HttpOnly flags. Defaults suit first-party browsers:

- Access and refresh cookies are HttpOnly; the CSRF cookie is JavaScript-readable.
- SameSite defaults to `lax`.
- Secure is enabled when `APP_ENV=production` unless overridden.
- Access cookie lifetime follows `passportless.access_token.expiration`; refresh and CSRF lifetimes follow `passportless.refresh_token.expiration`.
- Forget methods use the same name, path, domain, Secure, HttpOnly, and SameSite attributes as issuance.

#### Cookie paths

Browsers only attach a cookie when the request URL path starts with the cookie's `path`. Defaults differ by role on purpose:

| Cookie | Default path | Why |
| --- | --- | --- |
| Access | `/` | Guard auth reads it on every protected API route, so it must travel broadly. |
| CSRF | `/` | JavaScript must read it and send `X-CSRF-TOKEN` on any browser write route (refresh, logout, profile, etc.). |
| Refresh | `/api/auth` | Long-lived secret that mints new access tokens. Narrow path limits which endpoints receive it. Must cover both SPA `refresh` and `logout` under that prefix—not only `/api/auth/refresh`. |

Do not set refresh path to `/` unless you accept sending the refresh token on every same-site request. Do not set it to `/api/auth/refresh` alone if logout also needs the refresh cookie when the access cookie is missing or expired.

If SPA routes live elsewhere (for example `prefix: 'auth'`), override `passportless.cookie.guards.{guard}.refresh.path` to that same prefix so browsers send the cookie to both refresh and logout.

Optional `passportless.cookie.guards` overrides those settings per guard. The unscoped manager uses `passportless.guard` as the fallback.

The manager rejects invalid or unsafe configuration when resolved: access and refresh cookies must remain HttpOnly, cookie names must be unique, paths must be absolute, token lifetimes must be positive integers, and `SameSite=None` requires Secure cookies.

### Browser deployment notes

Same-origin clients can use Fetch `credentials: 'same-origin'`. Cross-origin clients must use `credentials: 'include'`, explicit allowed origins, and host-owned Laravel CORS with credential support; wildcard origins are invalid for credentialed CORS. Cross-site cookies need `SameSite=None` and `Secure=true`. CORS does not authenticate requests or replace CSRF protection.

Laravel's `EncryptCookies` middleware encrypts response cookies and decrypts request cookies by default. Keep access and refresh tokens HttpOnly. If double-submit CSRF requires JavaScript to read the CSRF cookie, exclude that CSRF cookie name from encryption in the host app; Passportless cannot infer that safely for every application.

## Testing

```bash
composer test
```

### Consumer test helpers

Host tests can opt into `InteractsWithPassportless`; it is not available on the service or facade. The trait uses Laravel's test-case and `TestResponse` APIs.

```php
use l3aro\Passportless\Testing\InteractsWithPassportless;

uses(InteractsWithPassportless::class);

it('authenticates a cookie session', function () {
    $this->withPassportlessCookieSession($user)
        ->get('/api/me')
        ->assertOk();
});
```

PHPUnit-style host test cases may add `use InteractsWithPassportless;`. The trait provides protected fluent methods: `actingAsPassportless`, `withPassportlessCookieSession`, `assertPassportlessAuthCookiesQueued`, and `assertPassportlessAuthCookiesForgotten`. Cookie setup injects normal access, refresh, and CSRF request cookies for the selected guard; it does not return token credentials.

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
