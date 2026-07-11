<?php

namespace l3aro\Passportless\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Schema\Builder;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
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

        $routes = $this->passportlessRoutes($router);
        $cookieGuards = $this->configuredCookieGuards($routes);
        $guards = $this->configuredGuards($cookieGuards);

        $this->checkBindings($bindings, $guards);
        $profiles = $this->checkCookieProfiles($cookieGuards);
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
    protected function configuredGuards(array $cookieGuards): array
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

        $guards = [...$guards, ...$cookieGuards];

        return array_values(array_unique($guards));
    }

    /**
     * @return array<int, string>
     */
    protected function configuredCookieGuards(array $routes): array
    {
        $guards = [];
        $fallback = config('passportless.guard', 'passportless');

        if (is_string($fallback) && $fallback !== '') {
            $guards[] = $fallback;
        }

        $cookieGuards = config('passportless.cookie.guards', []);

        if (! is_array($cookieGuards)) {
            $this->recordError('passportless.cookie.guards must be an array.');
        } else {
            foreach ($cookieGuards as $guard => $profile) {
                if (! is_string($guard) || $guard === '') {
                    $this->recordError('passportless.cookie.guards keys must be non-empty strings.');

                    continue;
                }

                if (! is_array($profile)) {
                    $this->recordError("Passportless cookie guard configuration for guard [{$guard}] must be an array.");

                    continue;
                }

                $guards[] = $guard;
            }
        }

        foreach ($routes as $route) {
            $guard = $route->defaults['passportlessGuard'] ?? null;

            if (is_string($guard) && $guard !== '') {
                $guards[] = $guard;
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

            if (! is_string($name) || $name === '' || preg_match('/[=,;\s"\x00-\x1F\x7F]/', $name) === 1) {
                $this->recordError("Passportless {$role} cookie name for guard [{$guard}] is invalid.");
            } elseif (isset($names[$name])) {
                $this->recordError("Passportless cookie name [{$name}] is shared by guards [{$names[$name]}] and [{$guard}].");
            } else {
                $names[$name] = $guard;
            }

            if (! is_string($path) || ! str_starts_with($path, '/')) {
                $this->recordError("Passportless {$role} cookie path for guard [{$guard}] must start with [/].");
            } elseif ($role === 'refresh' && $path === '/') {
                $this->recordError("Passportless refresh cookie path for guard [{$guard}] should not be [/] because it sends the refresh token on every same-site request.");
            }

            if (! is_bool($httpOnly)) {
                $this->recordError("Passportless {$role} cookie http_only setting for guard [{$guard}] must be boolean.");
            } elseif (($role === 'access' || $role === 'refresh') && ! $httpOnly) {
                $this->recordError("Passportless {$role} cookie for guard [{$guard}] must be HttpOnly.");
            } elseif ($role === 'csrf' && $httpOnly) {
                $this->recordError("Passportless CSRF cookie for guard [{$guard}] must be readable by the client (http_only=false).");
            }
        }

        $domain = $profile['domain'] ?? null;
        $secure = $profile['secure'] ?? null;
        $sameSite = $profile['same_site'] ?? null;

        if ($domain !== null && (! is_string($domain) || ! $this->domainIsValid($domain))) {
            $this->recordError("Passportless cookie domain for guard [{$guard}] is invalid.");
        }

        if ($secure !== null && ! is_bool($secure)) {
            $this->recordError("Passportless cookie secure setting for guard [{$guard}] must be boolean or null.");
        } elseif ($secure === false && config('app.env') === 'production') {
            $this->recordError("Passportless cookies for guard [{$guard}] should be secure in production.");
        }

        if (! is_string($sameSite) || ! in_array(strtolower($sameSite), ['lax', 'strict', 'none'], true)) {
            $this->recordError("Passportless SameSite setting for guard [{$guard}] must be lax, strict, or none.");
        } elseif (strtolower($sameSite) === 'none' && ! $this->secureCookieProfile($profile)) {
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

        try {
            $hasWildcardPattern = is_array($patterns) && $this->allowsAnyHttpsOrigin($patterns);
            $hasWildcard = (is_array($origins) && in_array('*', $origins, true))
                || (is_array($patterns) && in_array('*', $patterns, true))
                || $hasWildcardPattern;
        } catch (Throwable) {
            $this->recordError('CORS allowed_origins_patterns contains an invalid regular expression.');
            $hasWildcard = false;
        }

        if ($supportsCredentials === true && $hasWildcard) {
            $this->recordError('Credentialed CORS must not use a wildcard allowed origin.');
        }

        if ($supportsCredentials !== true || ! $this->hasSameSiteNoneProfile($profiles)) {
            return;
        }

        $paths = config('cors.paths', []);

        foreach ($routes as $route) {
            if (! $this->corsPathsCoverRoute($paths, $route)) {
                $this->recordError("Passportless route [/{$route->uri()}] is not covered by cors.paths.");
            }
        }
    }

    /**
     * @param  array<string, array<string, mixed>>  $profiles
     */
    protected function hasSameSiteNoneProfile(array $profiles): bool
    {
        foreach ($profiles as $profile) {
            if (strtolower((string) ($profile['same_site'] ?? '')) === 'none') {
                return true;
            }
        }

        return false;
    }

    protected function corsPathsCoverRoute(mixed $configuredPaths, Route $route): bool
    {
        if (! is_array($configuredPaths)) {
            return false;
        }

        $host = $route->domain() ?? parse_url((string) config('app.url', ''), PHP_URL_HOST);
        $paths = is_string($host) && isset($configuredPaths[$host])
            ? $configuredPaths[$host]
            : array_filter($configuredPaths, is_string(...));

        if (! is_array($paths)) {
            return false;
        }

        $uri = trim($route->uri(), '/');

        foreach ($paths as $path) {
            if (! is_string($path)) {
                continue;
            }

            $path = $path === '/' ? '/' : trim($path, '/');

            if (Str::is($path, $uri)) {
                return true;
            }
        }

        return false;
    }

    protected function checkMigrations(Builder $schema): void
    {
        $tables = [
            [(string) config('passportless.sessions_table', 'passportless_token_sessions'), ['id', 'tokenable_id', 'tokenable_type', 'name', 'guard', 'provider', 'ip_address', 'user_agent', 'last_used_at', 'revoked_at', 'created_at', 'updated_at']],
            [(string) config('passportless.access_tokens_table', 'passportless_tokens'), ['id', 'tokenable_id', 'tokenable_type', 'session_id', 'name', 'token', 'abilities', 'guard', 'provider', 'last_used_at', 'expires_at', 'revoked_at', 'created_at', 'updated_at']],
            [(string) config('passportless.refresh_tokens_table', 'passportless_refresh_tokens'), ['id', 'tokenable_id', 'tokenable_type', 'session_id', 'family_id', 'token', 'guard', 'provider', 'expires_at', 'rotated_at', 'revoked_at', 'created_at', 'updated_at']],
        ];

        $configuredTables = array_column($tables, 0);
        $duplicateTables = [];

        foreach ($tables as [$table, $columns]) {
            if (count(array_keys($configuredTables, $table, true)) > 1 && ! in_array($table, $duplicateTables, true)) {
                $this->recordError("Passportless migration table [{$table}] is configured for multiple Passportless models.");
                $duplicateTables[] = $table;
            }

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
            if (array_key_exists($role, $overrides) && ! is_array($overrides[$role])) {
                throw new InvalidArgumentException("Passportless {$role} cookie configuration must be an array.");
            }

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

    /**
     * @param  array<int, mixed>  $patterns
     */
    protected function allowsAnyHttpsOrigin(array $patterns): bool
    {
        $origins = [
            'https://passportless-doctor-a.invalid',
            'https://passportless-doctor-b.invalid',
        ];
        $allowsAnyOrigin = false;

        foreach ($patterns as $pattern) {
            if (! is_string($pattern) || $pattern === '*') {
                continue;
            }

            foreach ($origins as $origin) {
                $matches = preg_match($pattern, $origin);

                if ($matches === false) {
                    throw new InvalidArgumentException('CORS allowed origins pattern must be a valid regular expression.');
                }

                if ($matches !== 1) {
                    continue 2;
                }
            }

            $allowsAnyOrigin = true;
        }

        return $allowsAnyOrigin;
    }

    protected function domainIsValid(string $domain): bool
    {
        $hostname = ltrim($domain, '.');

        if ($hostname === '' || str_contains($domain, '..')) {
            return false;
        }

        if (filter_var($hostname, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        return filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
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
