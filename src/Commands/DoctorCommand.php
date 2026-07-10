<?php

namespace l3aro\Passportless\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Schema\Builder;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Arr;
use InvalidArgumentException;
use l3aro\Passportless\Concerns\HasPassportless;
use l3aro\Passportless\Http\Controllers\SpaLogoutController;
use l3aro\Passportless\Http\Controllers\SpaRefreshController;
use l3aro\Passportless\Support\AuthBindingResolver;
use Throwable;

class DoctorCommand extends Command
{
    public $signature = 'passportless:doctor';

    public $description = 'Check Passportless browser authentication configuration';

    /** @var array<int, string> */
    protected array $errors = [];

    public function handle(AuthBindingResolver $bindings, Router $router, Builder $schema): int
    {
        $this->errors = [];

        $guards = $this->configuredGuards();

        $this->checkBindings($bindings, $guards);
        $profiles = $this->checkCookieProfiles($guards);
        $routes = $this->passportlessRoutes($router);
        $this->checkRouteCookiePaths($routes, $profiles);
        $this->checkCors($routes, $profiles);
        $this->checkMigrations($schema);

        if ($this->errors === []) {
            $this->info('Passportless doctor found no configuration errors.');

            return self::SUCCESS;
        }

        $this->newLine();
        $this->error('Passportless doctor found '.count($this->errors).' configuration error(s).');

        return self::FAILURE;
    }

    /**
     * @return array<int, string>
     */
    protected function configuredGuards(): array
    {
        $guards = [];
        $default = config('passportless.guard', 'passportless');

        if (! is_string($default) || $default === '') {
            $this->recordError('passportless.guard must be a non-empty string.');
        } else {
            $guards[] = $default;
        }

        $authGuards = config('auth.guards', []);

        if (is_array($authGuards)) {
            foreach ($authGuards as $guard => $config) {
                if (is_string($guard) && is_array($config) && ($config['driver'] ?? null) === 'passportless') {
                    $guards[] = $guard;
                }
            }
        }

        $cookieGuards = config('passportless.cookie.guards', []);

        if (! is_array($cookieGuards)) {
            $this->recordError('passportless.cookie.guards must be an array.');
        } else {
            foreach (array_keys($cookieGuards) as $guard) {
                if (is_string($guard) && $guard !== '') {
                    $guards[] = $guard;
                }
            }
        }

        return array_values(array_unique($guards));
    }

    /**
     * @param  array<int, string>  $guards
     */
    protected function checkBindings(AuthBindingResolver $bindings, array $guards): void
    {
        foreach ($guards as $guard) {
            try {
                $binding = $bindings->resolveForGuard($guard);
            } catch (InvalidArgumentException $exception) {
                $this->recordError($exception->getMessage());

                continue;
            }

            if (! in_array(HasPassportless::class, class_uses_recursive($binding->model), true)) {
                $this->recordError("Passportless provider model [{$binding->model}] for guard [{$guard}] must use HasPassportless.");
            }
        }
    }

    /**
     * @param  array<int, string>  $guards
     * @return array<string, array<string, mixed>>
     */
    protected function checkCookieProfiles(array $guards): array
    {
        $profiles = [];
        $names = [];

        foreach ($guards as $guard) {
            try {
                $profile = $this->effectiveCookieProfile($guard);
            } catch (InvalidArgumentException $exception) {
                $this->recordError($exception->getMessage());

                continue;
            }

            $profiles[$guard] = $profile;
            $this->checkCookieProfile($guard, $profile, $names);
        }

        return $profiles;
    }

    /**
     * @param  array<string, mixed>  $profile
     * @param  array<string, string>  $names
     */
    protected function checkCookieProfile(string $guard, array $profile, array &$names): void
    {
        foreach (['access', 'refresh', 'csrf'] as $role) {
            $cookie = $profile[$role] ?? null;

            if (! is_array($cookie)) {
                $this->recordError("Passportless {$role} cookie configuration for guard [{$guard}] must be an array.");

                continue;
            }

            $name = $cookie['name'] ?? null;
            $path = $cookie['path'] ?? null;
            $httpOnly = $cookie['http_only'] ?? null;

            if (! is_string($name) || $name === '' || preg_match('/[=,;\s]/', $name) === 1) {
                $this->recordError("Passportless {$role} cookie name for guard [{$guard}] is invalid.");
            } elseif (isset($names[$name])) {
                $this->recordError("Passportless cookie name [{$name}] is shared by guards [{$names[$name]}] and [{$guard}].");
            } else {
                $names[$name] = $guard;
            }

            if (! is_string($path) || ! str_starts_with($path, '/')) {
                $this->recordError("Passportless {$role} cookie path for guard [{$guard}] must start with [/].");
            }

            if (! is_bool($httpOnly)) {
                $this->recordError("Passportless {$role} cookie http_only setting for guard [{$guard}] must be boolean.");
            } elseif (($role === 'access' || $role === 'refresh') && ! $httpOnly) {
                $this->recordError("Passportless {$role} cookie for guard [{$guard}] must be HttpOnly.");
            } elseif ($role === 'csrf' && $httpOnly) {
                $this->recordError("Passportless CSRF cookie for guard [{$guard}] must be readable by the client (http_only=false).");
            }
        }

        $sameSite = $profile['same_site'] ?? null;
        $secure = $this->secureCookieProfile($profile);

        if (! is_string($sameSite) || ! in_array(strtolower($sameSite), ['lax', 'strict', 'none'], true)) {
            $this->recordError("Passportless SameSite setting for guard [{$guard}] must be lax, strict, or none.");
        } elseif (strtolower($sameSite) === 'none' && ! $secure) {
            $this->recordError("Passportless SameSite=None cookies for guard [{$guard}] must be secure.");
        }
    }

    /**
     * @param  array<int, Route>  $routes
     * @param  array<string, array<string, mixed>>  $profiles
     */
    protected function checkRouteCookiePaths(array $routes, array $profiles): void
    {
        foreach ($routes as $route) {
            $guard = $route->defaults['passportlessGuard'] ?? null;

            if (! is_string($guard) || ! isset($profiles[$guard])) {
                continue;
            }

            $controller = $route->getControllerClass();

            if ($controller !== SpaRefreshController::class && $controller !== SpaLogoutController::class) {
                continue;
            }

            $path = Arr::get($profiles[$guard], 'refresh.path');

            if (! is_string($path) || ! $this->cookiePathCoversRoute($path, $route->uri())) {
                $this->recordError("Refresh cookie path for guard [{$guard}] does not cover Passportless route [/{$route->uri()}].");
            }
        }
    }

    /**
     * @param  array<int, Route>  $routes
     * @param  array<string, array<string, mixed>>  $profiles
     */
    protected function checkCors(array $routes, array $profiles): void
    {
        if ($routes === []) {
            return;
        }

        $origins = config('cors.allowed_origins', []);
        $patterns = config('cors.allowed_origins_patterns', []);
        $supportsCredentials = config('cors.supports_credentials');
        $hasWildcard = (is_array($origins) && in_array('*', $origins, true))
            || (is_array($patterns) && in_array('*', $patterns, true));

        if ($supportsCredentials === true && $hasWildcard) {
            $this->recordError('Credentialed CORS must not use a wildcard allowed origin.');
        }

        foreach ($profiles as $profile) {
            if (strtolower((string) ($profile['same_site'] ?? '')) !== 'none') {
                continue;
            }

            if ($supportsCredentials !== true) {
                $this->recordError('Cross-origin cookie auth requires cors.supports_credentials=true.');

                return;
            }
        }
    }

    protected function checkMigrations(Builder $schema): void
    {
        $tables = [
            (string) config('passportless.sessions_table', 'passportless_token_sessions') => ['id', 'tokenable_id', 'tokenable_type', 'name', 'guard', 'provider', 'ip_address', 'user_agent', 'last_used_at', 'revoked_at', 'created_at', 'updated_at'],
            (string) config('passportless.access_tokens_table', 'passportless_tokens') => ['id', 'tokenable_id', 'tokenable_type', 'session_id', 'name', 'token', 'abilities', 'guard', 'provider', 'last_used_at', 'expires_at', 'revoked_at', 'created_at', 'updated_at'],
            (string) config('passportless.refresh_tokens_table', 'passportless_refresh_tokens') => ['id', 'tokenable_id', 'tokenable_type', 'session_id', 'family_id', 'token', 'guard', 'provider', 'expires_at', 'rotated_at', 'revoked_at', 'created_at', 'updated_at'],
        ];

        foreach ($tables as $table => $columns) {
            try {
                if (! $schema->hasTable($table)) {
                    $this->recordError("Required Passportless migration table [{$table}] does not exist.");

                    continue;
                }

                foreach ($columns as $column) {
                    if (! $schema->hasColumn($table, $column)) {
                        $this->recordError("Passportless table [{$table}] is missing required column [{$column}].");
                    }
                }
            } catch (Throwable $exception) {
                $this->recordError("Could not inspect Passportless table [{$table}] (".$exception::class.').');
            }
        }
    }

    /**
     * @return array<int, Route>
     */
    protected function passportlessRoutes(Router $router): array
    {
        return array_values(array_filter(
            $router->getRoutes()->getRoutes(),
            static fn (Route $route): bool => is_string($route->defaults['passportlessGuard'] ?? null),
        ));
    }

    /**
     * @return array<string, mixed>
     */
    protected function effectiveCookieProfile(string $guard): array
    {
        $fallback = config('passportless.guard', 'passportless');
        $legacy = config('passportless.cookie', []);
        $profiles = config('passportless.cookie.guards', []);

        if (! is_string($fallback) || $fallback === '') {
            throw new InvalidArgumentException('Passportless cookie fallback guard must be a non-empty string.');
        }

        if (! is_array($legacy) || ! is_array($profiles)) {
            throw new InvalidArgumentException('Passportless cookie configuration must be an array.');
        }

        unset($legacy['guards']);

        if ($profiles === []) {
            if ($guard !== $fallback) {
                throw new InvalidArgumentException("Passportless cookie guard [{$guard}] is not configured.");
            }

            return $legacy;
        }

        $fallbackProfile = $this->mergeCookieProfile($legacy, $profiles[$fallback] ?? []);

        if ($guard === $fallback) {
            return $fallbackProfile;
        }

        if (! isset($profiles[$guard]) || ! is_array($profiles[$guard])) {
            throw new InvalidArgumentException("Passportless cookie guard [{$guard}] is not configured.");
        }

        return $this->mergeCookieProfile($fallbackProfile, $profiles[$guard]);
    }

    /**
     * @param  array<string, mixed>  $base
     * @return array<string, mixed>
     */
    protected function mergeCookieProfile(array $base, mixed $overrides): array
    {
        if (! is_array($overrides)) {
            throw new InvalidArgumentException('Passportless cookie guard configuration must be an array.');
        }

        foreach (['domain', 'secure', 'same_site'] as $key) {
            if (array_key_exists($key, $overrides)) {
                $base[$key] = $overrides[$key];
            }
        }

        foreach (['access', 'refresh', 'csrf'] as $role) {
            $base[$role] = array_replace(
                is_array($base[$role] ?? null) ? $base[$role] : [],
                is_array($overrides[$role] ?? null) ? $overrides[$role] : [],
            );
        }

        return $base;
    }

    /**
     * @param  array<string, mixed>  $profile
     */
    protected function secureCookieProfile(array $profile): bool
    {
        $secure = $profile['secure'] ?? null;

        return $secure === null ? config('app.env') === 'production' : $secure === true;
    }

    protected function cookiePathCoversRoute(string $cookiePath, string $routeUri): bool
    {
        $path = '/'.trim($cookiePath, '/');
        $routePath = '/'.trim($routeUri, '/');

        return $path === '/' || $routePath === $path || str_starts_with($routePath, $path.'/');
    }

    protected function recordError(string $message): void
    {
        $this->errors[] = $message;
        $this->error('FAIL: '.$message);
    }
}
