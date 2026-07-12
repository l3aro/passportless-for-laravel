# Multiple authenticatable models

[← Docs index](README.md) · [README](../README.md)

Use separate Passportless guards when one app has separate identity stores (for example users vs staff).

## Configure guards and providers

`config/auth.php` owns guards, providers, and models:

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

Both models need `HasPassportless` (or extend `l3aro\Passportless\Models\Tokenable`).

Default Passportless guard name lives in `config/passportless.php` (`guard`). With named guards like below, pass the guard on every issue call (or set `passportless.guard` to one of them):

```php
$clientToken = $user->createToken('iphone', guard: 'passportless-client');
$staffPair = $staff->createTokenPair('admin-browser', ['staff:read'], guard: 'passportless-admin');
```

Protect each route with its matching Laravel guard:

```php
Route::get('/me', ...)->middleware('auth:passportless-client');
Route::get('/admin/me', ...)->middleware('auth:passportless-admin');
```

## Rules

- Guards and providers are **identity** boundaries.
- Use policies or gates for business authorization.
- Token abilities are per-token permissions — not proof of “is staff”.
- Passportless validates that the token owner model matches the provider model for the resolved guard. A `User` cannot mint or authenticate a `passportless-admin` token when that guard points to `Staff`.

## Browser / SPA

SPA routes call `PassportlessCookieManager::forGuard($guard)`. Non-default guards **require** a cookie profile under `passportless.cookie.guards.{guard}` — missing profiles throw at login/refresh/logout. Cookie **names** must be unique across guards; **refresh paths** must cover each SPA prefix (including both refresh and logout).

```php
// config/passportless.php (or runtime config)
'guard' => 'passportless-client', // fallback / unscoped manager

'cookie' => [
    // base profile for passportless-client (or set via cookie.guards.passportless-client)
    'refresh' => [
        'path' => '/api/auth',
    ],
    'guards' => [
        'passportless-admin' => [
            'access' => [
                'name' => 'admin_access_token',
            ],
            'refresh' => [
                'name' => 'admin_refresh_token',
                'path' => '/api/auth/admin',
            ],
            'csrf' => [
                'name' => 'admin_csrf_token',
                'http_only' => false,
            ],
        ],
    ],
],
```

Register SPA auth once per guard with matching prefixes:

```php
Route::passportlessSpaAuth(
    prefix: 'api/auth',
    guard: 'passportless-client',
    authenticate: AuthenticateUser::class,
);

Route::passportlessSpaAuth(
    prefix: 'api/auth/admin',
    guard: 'passportless-admin',
    authenticate: AuthenticateStaff::class,
);
```

If you keep `passportless.guard` as `passportless` (published default) and only use named guards, put **every** SPA guard under `cookie.guards` — including distinct names and refresh paths. See [Browser cookies](browser-cookies.md) and [Configuration](configuration.md).

## Related

- [API tokens](api-tokens.md)
- [Browser cookies](browser-cookies.md)
