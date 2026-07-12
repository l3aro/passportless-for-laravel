<?php

namespace l3aro\Passportless\Routing;

use Illuminate\Routing\Router;
use Illuminate\Support\Str;
use InvalidArgumentException;
use l3aro\Passportless\Http\Controllers\SpaLoginController;
use l3aro\Passportless\Http\Controllers\SpaLogoutController;
use l3aro\Passportless\Http\Controllers\SpaRefreshController;

class SpaAuthRoutes
{
    /**
     * @param  string  $authenticate  Cacheable class-string or Class@method descriptor.
     * @param  array<int, string>|null  $abilities
     * @param  array<int, string>  $middleware
     * @param  array<int, string>  $loginMiddleware
     * @param  array<int, string>  $refreshMiddleware
     * @param  array<int, string>  $logoutMiddleware
     */
    public static function register(
        Router $router,
        string $prefix,
        string $guard,
        string $authenticate,
        string $name = 'browser',
        ?array $abilities = null,
        array $middleware = [],
        array $loginMiddleware = [],
        array $refreshMiddleware = [],
        array $logoutMiddleware = [],
        ?string $as = null,
        bool $csrf = true,
        ?string $domain = null,
    ): void {
        if ($authenticate === '') {
            throw new InvalidArgumentException('SPA auth route authenticate handler must be a non-empty class string or Class@method descriptor.');
        }

        $abilities ??= config('passportless.abilities.default', ['*']);
        $as ??= 'passportless.' . Str::slug($guard, '_') . '.';
        $defaults = [
            'passportlessGuard' => $guard,
            'passportlessAuthenticate' => $authenticate,
            'passportlessName' => $name,
            'passportlessAbilities' => $abilities,
            'passportlessCsrf' => $csrf,
        ];

        $router->group([
            'prefix' => trim($prefix, '/'),
            'middleware' => $middleware,
            'as' => $as,
            'domain' => $domain,
        ], function (Router $router) use ($defaults, $guard, $csrf, $loginMiddleware, $refreshMiddleware, $logoutMiddleware): void {
            $withDefaults = static function ($route) use ($defaults) {
                return $route
                    ->defaults('passportlessGuard', $defaults['passportlessGuard'])
                    ->defaults('passportlessAuthenticate', $defaults['passportlessAuthenticate'])
                    ->defaults('passportlessName', $defaults['passportlessName'])
                    ->defaults('passportlessAbilities', $defaults['passportlessAbilities'])
                    ->defaults('passportlessCsrf', $defaults['passportlessCsrf']);
            };

            $loginMiddlewareStack = $loginMiddleware;

            if ($csrf) {
                $loginMiddlewareStack = array_values(array_unique([
                    ...$loginMiddlewareStack,
                    'passportless.origin',
                ]));
            }

            $withDefaults(
                $router->post('login', SpaLoginController::class)
                    ->name('login')
                    ->middleware($loginMiddlewareStack),
            );

            $refreshMiddlewareStack = $refreshMiddleware;
            $logoutMiddlewareStack = $logoutMiddleware;

            if ($csrf) {
                $refreshMiddlewareStack = array_values(array_unique([
                    ...$refreshMiddlewareStack,
                    'passportless.csrf:' . $guard,
                ]));
                $logoutMiddlewareStack = array_values(array_unique([
                    ...$logoutMiddlewareStack,
                    'passportless.csrf:' . $guard,
                ]));
            }

            $withDefaults(
                $router->post('refresh', SpaRefreshController::class)
                    ->name('refresh')
                    ->middleware($refreshMiddlewareStack),
            );

            $withDefaults(
                $router->post('logout', SpaLogoutController::class)
                    ->name('logout')
                    ->middleware($logoutMiddlewareStack),
            );
        });
    }
}
