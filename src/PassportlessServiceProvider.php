<?php

namespace l3aro\Passportless;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use l3aro\Passportless\Commands\PruneStaleCommand;
use l3aro\Passportless\Http\Middleware\CheckAbilities;
use l3aro\Passportless\Http\Middleware\CheckForAnyAbility;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class PassportlessServiceProvider extends PackageServiceProvider
{
    public function packageRegistered(): void
    {
        $this->app->singleton(Passportless::class);
    }

    public function packageBooted(): void
    {
        config()->set('auth.guards.passportless.driver', config('auth.guards.passportless.driver', 'passportless'));

        $router = $this->app['router'];

        $router->aliasMiddleware('abilities', CheckAbilities::class);
        $router->aliasMiddleware('ability', CheckForAnyAbility::class);

        Auth::viaRequest('passportless', function ($request) {
            $plainTextToken = $request->bearerToken();

            if (! $plainTextToken) {
                return null;
            }

            $accessToken = $this->app->make(Passportless::class)->findToken($plainTextToken);

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
