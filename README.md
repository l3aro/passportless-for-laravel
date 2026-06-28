# Secure token-based authentication for first-party Laravel APIs

[![Latest Version on Packagist](https://img.shields.io/packagist/v/l3aro/auth-token-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/auth-token-for-laravel)
[![GitHub Tests Action Status](https://github.com/spatie/package-auth-token-for-laravel-laravel/actions/workflows/run-tests.yml/badge.svg)](https://github.com/l3aro/auth-token-for-laravel/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://github.com/spatie/package-auth-token-for-laravel-laravel/actions/workflows/fix-php-code-style-issues.yml/badge.svg)](https://github.com/l3aro/auth-token-for-laravel/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/l3aro/auth-token-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/auth-token-for-laravel)

Auth Token for Laravel provides first-party API tokens with optional abilities. Abilities are simple permission strings attached to access tokens; they are not OAuth scopes and do not add OAuth2 grant flows.

## Support us

[<img src="https://github-ads.s3.eu-central-1.amazonaws.com/auth-token-for-laravel.jpg?t=1" width="419px" />](https://spatie.be/github-ad-click/auth-token-for-laravel)

We invest a lot of resources into creating [best in class open source packages](https://spatie.be/open-source). You can support us by [buying one of our paid products](https://spatie.be/open-source/support-us).

We highly appreciate you sending us a postcard from your hometown, mentioning which of our package(s) you are using. You'll find our address on [our contact page](https://spatie.be/about-us). We publish all received postcards on [our virtual postcard wall](https://spatie.be/open-source/postcards).

## Installation

You can install the package via composer:

```bash
composer require l3aro/auth-token-for-laravel
```

You can publish and run the migrations with:

```bash
php artisan vendor:publish --tag="auth-token-for-laravel-migrations"
php artisan migrate
```

You can publish the config file with:

```bash
php artisan vendor:publish --tag="auth-token-for-laravel-config"
```

This is the contents of the published config file:

```php
return [
    'table' => 'auth_tokens',
];
```

Optionally, you can publish the views using

```bash
php artisan vendor:publish --tag="auth-token-for-laravel-views"
```

## Usage

```php
use l3aro\AuthToken\Concerns\HasAuthTokens;

class User extends Authenticatable
{
    use HasAuthTokens;
}

$token = $user->createToken('iphone', ['orders:read', 'orders:write']);

return ['token' => $token->plainTextToken];
```

Use `tokenCan` and `tokenCant` to check the current access token abilities:

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
    ->middleware(['auth:auth-token', 'abilities:orders:read']);

Route::post('/orders', OrdersController::class)
    ->middleware(['auth:auth-token', 'ability:orders:write,orders:admin']);
```

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
