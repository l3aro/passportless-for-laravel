# API tokens

[← Docs index](README.md) · [README](../README.md)

Bearer-token path for mobile, CLI, internal APIs, and server-to-server clients.

Prerequisites: [Quick start](../README.md#quick-start) (install, guard, `HasPassportless`).

## Issue an access token

```php
$token = $user->createToken('iphone', ['orders:read', 'orders:write']);

// Plain text is available only at creation time.
return ['token' => $token->plainTextToken];
```

Format is `{id}|{secret}` (e.g. `1|…`). Store the full string on the client. The database stores only a hash.

Optional expiry override:

```php
$token = $user->createToken('short', ['orders:read'], expiresAt: now()->addHour());
```

## Call the API

```http
GET /orders HTTP/1.1
Authorization: Bearer 1|your-plain-text-token
Accept: application/json
```

```php
Http::withToken($plainTextToken)->get('/api/orders');
```

## Abilities

Abilities are simple permission strings on the access token. They are not OAuth scopes.

```php
if ($request->user()->tokenCan('orders:read')) {
    // ...
}

if ($request->user()->tokenCannot('orders:write')) {
    abort(403);
}
```

Grant every ability with `*`:

```php
$token = $user->createToken('admin', ['*']);
```

`createToken` / `createTokenPair` default the abilities argument to `['*']` in PHP. Omitting the argument always issues a wildcard token; it does **not** read `config('passportless.abilities.default')`. That config is used by SPA auth routes when `abilities` is not passed to `Route::passportlessSpaAuth(...)`. See [Configuration](configuration.md) and [Browser cookies](browser-cookies.md).

## Protecting routes

| Alias | Meaning |
| --- | --- |
| `auth:passportless` | Authenticate via Bearer (or access cookie — see [Browser cookies](browser-cookies.md)) |
| `abilities:foo,bar` | Token must have **all** listed abilities |
| `ability:foo,bar` | Token must have **any** listed ability |

```php
Route::get('/orders', OrdersController::class)
    ->middleware(['auth:passportless', 'abilities:orders:read']);

Route::post('/orders', OrdersController::class)
    ->middleware(['auth:passportless', 'ability:orders:write,orders:admin']);
```

Cookie-related middleware (`passportless.csrf`, `passportless.origin`) is documented under [Browser cookies](browser-cookies.md).

## List and manage tokens

The `HasPassportless` trait exposes Eloquent relations:

```php
// Access tokens for this user
$user->tokens;

// Token sessions (created by createTokenPair / browser flows)
$user->tokenSessions;
```

Current request token (after guard auth):

```php
$request->user()->currentAccessToken();
```

## Refresh token pairs

For long-lived client sessions, issue an access + refresh pair. This creates a **token session** that groups related credentials.

```php
$pair = $user->createTokenPair('iphone', ['orders:read']);

$access = $pair->plainTextAccessToken();   // short-lived
$refresh = $pair->plainTextRefreshToken(); // long-lived; rotate on refresh
```

Rotate with the facade:

```php
use l3aro\Passportless\Facades\Passportless;

$newPair = Passportless::refreshToken($plainTextRefreshToken, guard: 'passportless');
// null if invalid, expired, revoked, or reuse detected
```

Reuse detection defaults to revoking the whole refresh family (`refresh_token.reuse_detection` in config).

## Logout and session revocation

A **session** groups related access/refresh tokens. Revoking a session revokes **all** active tokens in that session — not only the credential you pass.

```php
use l3aro\Passportless\Facades\Passportless;

// Device that presented this access token
Passportless::logoutCurrentSession($plainTextAccessToken, 'passportless');

// Logout using a refresh credential (e.g. cookie-only flow)
Passportless::revokeSessionFromRefreshToken($plainTextRefreshToken, 'passportless');

// Every session for this user on this guard
Passportless::logoutAllSessions($user, 'passportless');
```

Invalid, expired, revoked, or mismatched credentials no-op safely. Guard/provider isolation is enforced.

Aliases:

- `logoutCurrentSession` → `revokeCurrentSession`
- `revokeCurrentSessionByRefreshToken` → `revokeSessionFromRefreshToken`

## Related

- [Multiple guards](multi-guard.md) — more than one authenticatable model
- [Browser cookies](browser-cookies.md) — SPA delivery of the same tokens
- [Configuration](configuration.md) — expirations and reuse policy
