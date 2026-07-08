<?php

namespace l3aro\Passportless;

use Illuminate\Auth\RequestGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use l3aro\Passportless\Commands\PruneStaleCommand;
use l3aro\Passportless\Http\Middleware\CheckAbilities;
use l3aro\Passportless\Http\Middleware\CheckForAnyAbility;
use l3aro\Passportless\Support\AuthBindingResolver;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class PassportlessServiceProvider extends PackageServiceProvider
{
    public function packageRegistered(): void
    {
        $this->app->scoped(Passportless::class);
        $this->app->scoped(PassportlessCookieManager::class);
        $this->app->scoped(AuthBindingResolver::class);
    }

    public function packageBooted(): void
    {
        $router = $this->app['router'];

        $router->aliasMiddleware('abilities', CheckAbilities::class);
        $router->aliasMiddleware('ability', CheckForAnyAbility::class);

        Auth::extend('passportless', function ($app, string $name, array $config): RequestGuard {
            $guard = new RequestGuard(function ($request) use ($app, $name) {
                $plainTextToken = $request->bearerToken();

                if (! $plainTextToken) {
                    return null;
                }

                $accessToken = $app->make(Passportless::class)->findToken($plainTextToken, $name);

                if (! $accessToken) {
                    return null;
                }

                $tokenable = $accessToken->tokenable;

                if (! $tokenable instanceof Model || ! method_exists($tokenable, 'withAccessToken')) {
                    return null;
                }

                $lastUsedAt = $accessToken->last_used_at;
                $updateInterval = (int) config('passportless.access_token.last_used_update_interval', 60);

                if ($lastUsedAt === null || $lastUsedAt->copy()->addSeconds($updateInterval)->isPast()) {
                    $accessToken->recordUsage(now());
                }

                return $tokenable->withAccessToken($accessToken);
            }, $app['request'], Auth::createUserProvider($config['provider'] ?? null));

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
            ->hasViews()
            ->hasMigration('create_passportless_tables')
            ->hasCommand(PruneStaleCommand::class);
    }
}
