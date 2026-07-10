<?php

namespace l3aro\Passportless;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use l3aro\Passportless\Commands\PruneStaleCommand;
use l3aro\Passportless\Guards\PassportlessAuthenticator;
use l3aro\Passportless\Guards\PassportlessRequestGuard;
use l3aro\Passportless\Http\Middleware\CheckAbilities;
use l3aro\Passportless\Http\Middleware\CheckForAnyAbility;
use l3aro\Passportless\Http\Middleware\ValidateCsrfCookie;
use l3aro\Passportless\Routing\SpaAuthRoutes;
use l3aro\Passportless\Support\AuthBindingResolver;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class PassportlessServiceProvider extends PackageServiceProvider
{
    public function packageRegistered(): void
    {
        $this->app->scoped(Passportless::class);
        $this->app->scoped(PassportlessCookieManager::class);
        $this->app->scoped(PassportlessAuthenticator::class);
        $this->app->scoped(AuthBindingResolver::class);
    }

    public function packageBooted(): void
    {
        $router = $this->app['router'];

        $router->aliasMiddleware('abilities', CheckAbilities::class);
        $router->aliasMiddleware('ability', CheckForAnyAbility::class);
        $router->aliasMiddleware('passportless.csrf', ValidateCsrfCookie::class);

        Route::macro('passportlessSpaAuth', function (
            string $prefix,
            string $guard,
            mixed $authenticate,
            string $name = 'browser',
            ?array $abilities = null,
            array $middleware = [],
            array $loginMiddleware = [],
            array $refreshMiddleware = [],
            array $logoutMiddleware = [],
            ?string $as = null,
            bool $csrf = true,
            ?string $domain = null,
        ) use ($router): void {
            SpaAuthRoutes::register(
                router: $router,
                prefix: $prefix,
                guard: $guard,
                authenticate: $authenticate,
                name: $name,
                abilities: $abilities,
                middleware: $middleware,
                loginMiddleware: $loginMiddleware,
                refreshMiddleware: $refreshMiddleware,
                logoutMiddleware: $logoutMiddleware,
                as: $as,
                csrf: $csrf,
                domain: $domain,
            );
        });

        Auth::extend('passportless', function ($app, string $name, array $config): PassportlessRequestGuard {
            $authenticator = $app->make(PassportlessAuthenticator::class);

            $guard = new PassportlessRequestGuard(
                fn ($request) => $authenticator->authenticate($request, $name),
                $app['request'],
                Auth::createUserProvider($config['provider'] ?? null),
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('passportless')
            ->hasConfigFile()
            ->hasMigration('create_passportless_tables')
            ->hasCommand(PruneStaleCommand::class);
    }
}
