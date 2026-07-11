# Testing

[← Docs index](README.md) · [README](../README.md)

## Package tests

From the package root:

```bash
composer test
```

## Host application helpers

Opt into `InteractsWithPassportless` in your test case. It is **not** available on the service or facade. Uses Laravel’s test-case and `TestResponse` APIs.

### Pest

```php
use l3aro\Passportless\Testing\InteractsWithPassportless;

uses(InteractsWithPassportless::class);

it('authenticates a cookie session', function () {
    $this->withPassportlessCookieSession($user)
        ->get('/api/me')
        ->assertOk();
});
```

### PHPUnit

```php
use l3aro\Passportless\Testing\InteractsWithPassportless;

class ExampleTest extends TestCase
{
    use InteractsWithPassportless;

    public function test_me(): void
    {
        $this->actingAsPassportless($user)
            ->getJson('/api/me')
            ->assertOk();
    }
}
```

## Helpers

| Method | Role |
| --- | --- |
| `actingAsPassportless($user, $guard = 'passportless')` | `actingAs` for a Passportless guard; validates model matches guard provider |
| `withPassportlessCookieSession($user, $guard = 'passportless')` | Injects access, refresh, and CSRF request cookies + `X-CSRF-TOKEN` |
| `assertPassportlessAuthCookiesQueued($response, $guard = 'passportless')` | Assert access/refresh/CSRF cookies were queued |
| `assertPassportlessAuthCookiesForgotten($response, $guard = 'passportless')` | Assert forget cookies were queued |

Cookie setup injects normal request cookies for the selected guard. It does **not** return plain-text token credentials to your test.

## Related

- [Browser cookies](browser-cookies.md)
- [API tokens](api-tokens.md)
