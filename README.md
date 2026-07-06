# Passportless

[![Latest Version on Packagist](https://img.shields.io/packagist/v/l3aro/passportless-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/passportless-for-laravel)
[![GitHub Tests Action Status](https://github.com/l3aro/passportless-for-laravel/actions/workflows/run-tests.yml/badge.svg)](https://github.com/l3aro/passportless-for-laravel/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://github.com/l3aro/passportless-for-laravel/actions/workflows/fix-php-code-style-issues.yml/badge.svg)](https://github.com/l3aro/passportless-for-laravel/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/l3aro/passportless-for-laravel.svg?style=flat-square)](https://packagist.org/packages/l3aro/passportless-for-laravel)

Passportless provides first-party API tokens with optional abilities. Abilities are simple permission strings attached to access tokens; they are not OAuth scopes and do not add OAuth2 grant flows.

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
    'provider' => null,
    // ...
];
```

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
