<?php

namespace l3aro\Passportless;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Cookie;

class PassportlessCookieManager
{
    public function __construct(
        protected readonly ConfigRepository $config,
        protected readonly ?string $guard = null,
    ) {
        $this->validateConfiguration();

        if ($this->guard !== null) {
            $this->effectiveCookieConfig($this->guard);
        }
    }

    public function forGuard(string $guard): self
    {
        return new self($this->config, $guard);
    }

    public function accessCookieName(): string
    {
        return $this->roleName('access');
    }

    public function refreshCookieName(): string
    {
        return $this->roleName('refresh');
    }

    public function csrfCookieName(): string
    {
        return $this->roleName('csrf');
    }

    public function createAccessCookie(string $token): Cookie
    {
        return $this->makeCookie('access', $token, $this->minutes('passportless.access_token.expiration', 15));
    }

    public function createRefreshCookie(string $token): Cookie
    {
        return $this->makeCookie('refresh', $token, $this->minutes('passportless.refresh_token.expiration', 60 * 24 * 30));
    }

    public function createCsrfCookie(string $token): Cookie
    {
        return $this->makeCookie('csrf', $token, $this->minutes('passportless.refresh_token.expiration', 60 * 24 * 30));
    }

    public function forgetAccessCookie(): Cookie
    {
        return $this->forgetCookie('access');
    }

    public function forgetRefreshCookie(): Cookie
    {
        return $this->forgetCookie('refresh');
    }

    public function forgetCsrfCookie(): Cookie
    {
        return $this->forgetCookie('csrf');
    }

    protected function makeCookie(string $role, string $value, int $minutes): Cookie
    {
        return new Cookie(
            $this->roleName($role),
            $value,
            now()->addMinutes($minutes),
            $this->rolePath($role),
            $this->domain(),
            $this->secure(),
            $this->httpOnly($role),
            false,
            $this->sameSite(),
        );
    }

    protected function forgetCookie(string $role): Cookie
    {
        return new Cookie(
            $this->roleName($role),
            null,
            now()->subYears(5),
            $this->rolePath($role),
            $this->domain(),
            $this->secure(),
            $this->httpOnly($role),
            false,
            $this->sameSite(),
        );
    }

    protected function roleName(string $role): string
    {
        $config = $this->effectiveCookieConfig($this->guard);
        $name = $config[$role]['name'] ?? null;

        return is_string($name) && $name !== '' ? $name : "passportless_{$role}_token";
    }

    protected function rolePath(string $role): string
    {
        $config = $this->effectiveCookieConfig($this->guard);
        $path = $config[$role]['path'] ?? null;

        return is_string($path) && $path !== '' ? $path : '/';
    }

    protected function domain(): ?string
    {
        $domain = $this->effectiveCookieConfig($this->guard)['domain'] ?? null;

        return is_string($domain) && $domain !== '' ? $domain : null;
    }

    protected function secure(): bool
    {
        $secure = $this->effectiveCookieConfig($this->guard)['secure'] ?? null;

        if ($secure === null) {
            return $this->config->get('app.env') === 'production';
        }

        return (bool) $secure;
    }

    protected function httpOnly(string $role): bool
    {
        $config = $this->effectiveCookieConfig($this->guard);

        return (bool) ($config[$role]['http_only'] ?? true);
    }

    protected function sameSite(): ?string
    {
        $sameSite = $this->effectiveCookieConfig($this->guard)['same_site'] ?? 'lax';

        return is_string($sameSite) && $sameSite !== '' ? $sameSite : null;
    }

    /**
     * @return array<string, mixed>
     */
    protected function effectiveCookieConfig(?string $guard): array
    {
        $fallbackGuard = $this->fallbackCookieGuard();
        $legacy = $this->legacyCookieConfig();
        $guards = $this->cookieGuards();

        if ($guards === []) {
            if ($guard !== null && $guard !== $fallbackGuard) {
                throw new InvalidArgumentException("Passportless cookie guard [{$guard}] is not configured.");
            }

            return $legacy;
        }

        $selectedGuard = $guard ?? $fallbackGuard;
        $fallback = $this->mergeCookieConfig($legacy, $guards[$fallbackGuard] ?? []);

        if ($selectedGuard === $fallbackGuard) {
            return $fallback;
        }

        if (! array_key_exists($selectedGuard, $guards)) {
            throw new InvalidArgumentException("Passportless cookie guard [{$selectedGuard}] is not configured.");
        }

        return $this->mergeCookieConfig($fallback, $guards[$selectedGuard]);
    }

    protected function fallbackCookieGuard(): string
    {
        $guard = $this->config->get('passportless.guard', 'passportless');

        if (! is_string($guard) || $guard === '') {
            throw new InvalidArgumentException('Passportless cookie fallback guard must be a non-empty string.');
        }

        return $guard;
    }

    /**
     * @return array<string, mixed>
     */
    protected function legacyCookieConfig(): array
    {
        return [
            'domain' => $this->config->get('passportless.cookie.domain'),
            'secure' => $this->config->get('passportless.cookie.secure'),
            'same_site' => $this->config->get('passportless.cookie.same_site', 'lax'),
            'access' => $this->config->get('passportless.cookie.access', []),
            'refresh' => $this->config->get('passportless.cookie.refresh', []),
            'csrf' => $this->config->get('passportless.cookie.csrf', []),
        ];
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    protected function cookieGuards(): array
    {
        $guards = $this->config->get('passportless.cookie.guards', []);

        if (! is_array($guards)) {
            throw new InvalidArgumentException('The [passportless.cookie.guards] configuration value must be an array.');
        }

        foreach ($guards as $guard => $config) {
            if (! is_string($guard) || $guard === '' || ! is_array($config)) {
                throw new InvalidArgumentException('Passportless cookie guard entries must be keyed by non-empty guard names.');
            }

            foreach (['access', 'refresh', 'csrf'] as $role) {
                if (array_key_exists($role, $config) && ! is_array($config[$role])) {
                    throw new InvalidArgumentException("The [passportless.cookie.guards.{$guard}.{$role}] configuration value must be an array.");
                }
            }
        }

        return $guards;
    }

    /**
     * @param  array<string, mixed>  $base
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    protected function mergeCookieConfig(array $base, array $overrides): array
    {
        foreach (['domain', 'secure', 'same_site'] as $key) {
            if (array_key_exists($key, $overrides)) {
                $base[$key] = $overrides[$key];
            }
        }

        foreach (['access', 'refresh', 'csrf'] as $role) {
            $baseRole = is_array($base[$role] ?? null) ? $base[$role] : [];
            $overrideRole = is_array($overrides[$role] ?? null) ? $overrides[$role] : [];
            $base[$role] = array_replace($baseRole, $overrideRole);
        }

        return $base;
    }

    protected function minutes(string $key, int $default): int
    {
        $minutes = $this->config->get($key, $default);

        if ((! is_int($minutes) && ! (is_string($minutes) && ctype_digit($minutes))) || (int) $minutes <= 0) {
            throw new InvalidArgumentException("The [{$key}] configuration value must be a positive integer.");
        }

        return (int) $minutes;
    }

    protected function validateConfiguration(): void
    {
        $guards = $this->cookieGuards();
        $this->validateCookieConfigurationForGuard(null);

        $guardKeys = array_unique(array_merge([$this->fallbackCookieGuard()], array_keys($guards)));

        foreach ($guardKeys as $guard) {
            $this->validateCookieConfigurationForGuard($guard);
        }

        $this->minutes('passportless.access_token.expiration', 15);
        $this->minutes('passportless.refresh_token.expiration', 60 * 24 * 30);
    }

    protected function validateCookieConfigurationForGuard(?string $guard): void
    {
        $config = $this->effectiveCookieConfig($guard);
        $guardLabel = $guard ?? $this->fallbackCookieGuard();
        $names = [];

        foreach (['access', 'refresh', 'csrf'] as $role) {
            $roleConfig = $config[$role] ?? null;

            if (! is_array($roleConfig)) {
                throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.{$role}] configuration value must be an array.");
            }

            $name = $roleConfig['name'] ?? null;
            $path = $roleConfig['path'] ?? null;
            $httpOnly = $roleConfig['http_only'] ?? null;

            if (! is_string($name) || $name === '' || preg_match('/[=,;\s"\'\x00-\x1F\x7F]/', $name) === 1) {
                throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.{$role}.name] configuration value is invalid.");
            }

            if (in_array($name, $names, true)) {
                throw new InvalidArgumentException("Passportless cookie names must be unique for guard [{$guardLabel}].");
            }

            if (! is_string($path) || ! str_starts_with($path, '/')) {
                throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.{$role}.path] configuration value must start with [/].");
            }

            if (! is_bool($httpOnly)) {
                throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.{$role}.http_only] configuration value must be boolean.");
            }

            if ($role !== 'csrf' && ! $httpOnly) {
                throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.{$role}.http_only] configuration value must be true.");
            }

            $names[] = $name;
        }

        $domain = $config['domain'] ?? null;
        $secure = $config['secure'] ?? null;
        $sameSite = $config['same_site'] ?? null;

        if ($domain !== null && (! is_string($domain) || ! $this->domainIsValid($domain))) {
            throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.domain] configuration value is invalid.");
        }

        if ($secure !== null && ! is_bool($secure)) {
            throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.secure] configuration value must be boolean or null.");
        }

        if (! is_string($sameSite) || ! in_array(strtolower($sameSite), ['lax', 'strict', 'none'], true)) {
            throw new InvalidArgumentException("The [passportless.cookie.guards.{$guardLabel}.same_site] configuration value must be lax, strict, or none.");
        }

        if (strtolower($sameSite) === 'none' && ! $this->secureForGuard($guard)) {
            throw new InvalidArgumentException("SameSite=None requires secure Passportless cookies for guard [{$guardLabel}].");
        }
    }

    protected function secureForGuard(?string $guard): bool
    {
        $secure = $this->effectiveCookieConfig($guard)['secure'] ?? null;

        if ($secure === null) {
            return $this->config->get('app.env') === 'production';
        }

        return (bool) $secure;
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
}
