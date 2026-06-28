<?php

namespace l3aro\AuthToken;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use l3aro\AuthToken\Commands\AuthTokenCommand;
use l3aro\AuthToken\Http\Middleware\CheckAbilities;
use l3aro\AuthToken\Http\Middleware\CheckForAnyAbility;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class AuthTokenServiceProvider extends PackageServiceProvider
{
    public function packageRegistered(): void
    {
        $this->app->singleton(AuthToken::class);
    }

    public function packageBooted(): void
    {
        config()->set('auth.guards.auth-token.driver', config('auth.guards.auth-token.driver', 'auth-token'));

        $router = $this->app['router'];

        $router->aliasMiddleware('abilities', CheckAbilities::class);
        $router->aliasMiddleware('ability', CheckForAnyAbility::class);

        Auth::viaRequest('auth-token', function ($request) {
            $plainTextToken = $request->bearerToken();

            if (! $plainTextToken) {
                return null;
            }

            $accessToken = $this->app->make(AuthToken::class)->findToken($plainTextToken);

            if (! $accessToken) {
                return null;
            }

            $tokenable = $accessToken->tokenable;

            if (! $tokenable instanceof Model || ! method_exists($tokenable, 'withAccessToken')) {
                return null;
            }

            $accessToken->forceFill(['last_used_at' => now()])->save();

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
            ->name('auth-token-for-laravel')
            ->hasConfigFile()
            ->hasViews()
            ->hasMigration('create_auth_token_for_laravel_table')
            ->hasCommand(AuthTokenCommand::class);
    }
}
