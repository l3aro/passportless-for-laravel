# Browser cookies

[← Docs index](README.md) · [README](../README.md)

Optional SPA path: deliver access and refresh tokens as HTTP-only cookies instead of JSON or `localStorage`.

Same token model as [API tokens](api-tokens.md); different delivery.

## Rules of thumb

- Access + refresh cookies: **HttpOnly** only
- JavaScript may read a separate **CSRF** cookie (not the tokens)
- Guard checks `Authorization: Bearer` first, then the configured access cookie
- CSRF is separate from authentication
- Do not put access or refresh tokens in JSON, JS-readable cookies, or web storage

You can wire routes with `PassportlessCookieManager`, or register package SPA routes.

## Option A — SPA routes (recommended starter)

Routes are **never** auto-loaded. Register per guard:

```php
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use App\Models\User;

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

Route::passportlessSpaAuth(
    prefix: 'api/auth',
    guard: 'passportless',
    authenticate: AuthenticateUser::class,
    abilities: ['demo:read'],
    loginMiddleware: ['throttle:login'],
    refreshMiddleware: ['throttle:refresh'],
);
```

| Method | Path               | Role                            |
| ------ | ------------------ | ------------------------------- |
| `POST` | `{prefix}/login`   | Issue pair + set cookies        |
| `POST` | `{prefix}/refresh` | Rotate from refresh cookie      |
| `POST` | `{prefix}/logout`  | Revoke session + forget cookies |

Notes:

- `authenticate` must be a resolvable invokable class or `Class@method` (no closures — routes must be cacheable)
- Login JSON is non-secret (`token_type`, expirations, optional `csrf_token`, `session`) — never plain access/refresh tokens
- With `csrf: true` (default): `passportless.origin` on login; CSRF middleware on refresh/logout
- Align refresh cookie path with the prefix (default `/api/auth` covers both refresh and logout)
- Host still owns CORS, `EncryptCookies` exclusions for the JS-readable CSRF cookie, and throttles

Multi-guard: call `Route::passportlessSpaAuth(...)` again with another `prefix`, `guard`, and authenticator. Each non-fallback guard needs a `passportless.cookie.guards.{guard}` profile (unique cookie names + refresh path covering that prefix). See [Multiple guards](multi-guard.md).

## Option B — Manual cookies

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

`PassportlessCookieManager` returns Symfony `Cookie` objects only. It does not queue or mutate responses. Scope per guard with `->forGuard('passportless-admin')` — that guard must exist under `passportless.cookie.guards` (or be `passportless.guard`) or construction throws.

Read / clear:

```php
$request->cookie($cookies->refreshCookieName());
$cookies->forgetAccessCookie();
$cookies->forgetRefreshCookie();
$cookies->forgetCsrfCookie();
```

## CSRF middleware

Opt-in alias `passportless.csrf` (double-submit: CSRF cookie vs `X-CSRF-TOKEN` header).

- Skips `GET`, `HEAD`, `OPTIONS`
- Timing-safe comparison
- Optional guard parameter: `passportless.csrf:passportless-admin`
- Fails closed with HTTP `419` on missing/empty/mismatched values

```php
Route::middleware(['passportless.csrf', 'auth:passportless'])
    ->post('/profile', ...);

Route::middleware(['passportless.csrf:passportless-admin', 'auth:passportless-admin'])
    ->post('/admin/profile', ...);
```

Does not authenticate, rotate tokens, attach cookies, or generate CSRF values. Host owns generation, attachment, CORS, route coverage, middleware order, and CSRF cookie encryption exclusion.

## Same-origin middleware

`passportless.origin` rejects a present `Origin` whose scheme, host, or port differs from the request origin. Applied automatically to SPA login when `csrf: true`. Does not replace CSRF. Missing `Origin` continues to the route.

```php
Route::post('/auth/login', AuthenticateUserController::class)
    ->middleware('passportless.origin');
```

## Cookie paths

Browsers only send a cookie when the request path starts with the cookie’s `path`:

| Cookie  | Default path | Why                                                                         |
| ------- | ------------ | --------------------------------------------------------------------------- |
| Access  | `/`          | Needed on every protected API route                                         |
| CSRF    | `/`          | JS must read it for any write route                                         |
| Refresh | `/api/auth`  | Narrow path for a long-lived secret; must cover **both** refresh and logout |

Do not set refresh path to `/` unless you accept sending it on every same-site request. Do not set it to `/api/auth/refresh` alone if logout also needs the refresh cookie when access is missing/expired.

If SPA routes use another prefix (e.g. `prefix: 'auth'`), set `passportless.cookie.guards.{guard}.refresh.path` to that same prefix.

## Browser deployment checklist

- Same-origin: Fetch `credentials: 'same-origin'`
- Cross-origin: `credentials: 'include'`, explicit CORS origins (no `*` with credentials), host-owned Laravel CORS
- Cross-site cookies: `SameSite=None` + `Secure=true`
- Exclude JS-readable CSRF cookie name from `EncryptCookies` when JS must read it
- Keep access/refresh HttpOnly
- CORS does not authenticate or replace CSRF

Run `php artisan passportless:doctor` after changing guards, cookies, SPA routes, or CORS. See [Operations](operations.md).

## Related

- [Configuration](configuration.md) — cookie names, SameSite, Secure, per-guard overrides
- [API tokens](api-tokens.md) — refresh and logout semantics
- [Testing](testing.md) — `withPassportlessCookieSession`
