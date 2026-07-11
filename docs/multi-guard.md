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

Default Passportless guard name lives in `config/passportless.php` (`guard`). Override per call:

```php
$clientToken = $user->createToken('iphone');
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

Register SPA auth once per guard with different prefixes:

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

Cookie profiles can be overridden per guard under `passportless.cookie.guards.{guard}`. See [Browser cookies](browser-cookies.md) and [Configuration](configuration.md).

## Related

- [API tokens](api-tokens.md)
- [Browser cookies](browser-cookies.md)
