<?php

namespace l3aro\Passportless;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Cookie;

class PassportlessCookieManager
{
    public function __construct(protected readonly ConfigRepository $config)
    {
        $this->validateConfiguration();
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
        $name = $this->config->get("passportless.cookie.{$role}.name");

        return is_string($name) && $name !== '' ? $name : "passportless_{$role}_token";
    }

    protected function rolePath(string $role): string
    {
        $path = $this->config->get("passportless.cookie.{$role}.path");

        return is_string($path) && $path !== '' ? $path : '/';
    }

    protected function domain(): ?string
    {
        $domain = $this->config->get('passportless.cookie.domain');

        return is_string($domain) && $domain !== '' ? $domain : null;
    }

    protected function secure(): bool
    {
        $secure = $this->config->get('passportless.cookie.secure');

        if ($secure === null) {
            return $this->config->get('app.env') === 'production';
        }

        return (bool) $secure;
    }

    protected function httpOnly(string $role): bool
    {
        return (bool) $this->config->get("passportless.cookie.{$role}.http_only", true);
    }

    protected function sameSite(): ?string
    {
        $sameSite = $this->config->get('passportless.cookie.same_site', 'lax');

        return is_string($sameSite) && $sameSite !== '' ? $sameSite : null;
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
        $names = [];

        foreach (['access', 'refresh', 'csrf'] as $role) {
            $name = $this->config->get("passportless.cookie.{$role}.name");
            $path = $this->config->get("passportless.cookie.{$role}.path");
            $httpOnly = $this->config->get("passportless.cookie.{$role}.http_only");

            if (! is_string($name) || $name === '' || preg_match('/[=,;\s]/', $name) === 1) {
                throw new InvalidArgumentException("The [passportless.cookie.{$role}.name] configuration value is invalid.");
            }

            if (in_array($name, $names, true)) {
                throw new InvalidArgumentException('Passportless cookie names must be unique.');
            }

            if (! is_string($path) || ! str_starts_with($path, '/')) {
                throw new InvalidArgumentException("The [passportless.cookie.{$role}.path] configuration value must start with [/].");
            }

            if (! is_bool($httpOnly)) {
                throw new InvalidArgumentException("The [passportless.cookie.{$role}.http_only] configuration value must be boolean.");
            }

            if ($role !== 'csrf' && ! $httpOnly) {
                throw new InvalidArgumentException("The [passportless.cookie.{$role}.http_only] configuration value must be true.");
            }

            $names[] = $name;
        }

        $domain = $this->config->get('passportless.cookie.domain');
        $secure = $this->config->get('passportless.cookie.secure');
        $sameSite = $this->config->get('passportless.cookie.same_site');

        if ($domain !== null && (! is_string($domain) || ! $this->domainIsValid($domain))) {
            throw new InvalidArgumentException('The [passportless.cookie.domain] configuration value is invalid.');
        }

        if ($secure !== null && ! is_bool($secure)) {
            throw new InvalidArgumentException('The [passportless.cookie.secure] configuration value must be boolean or null.');
        }

        if (! is_string($sameSite) || ! in_array(strtolower($sameSite), ['lax', 'strict', 'none'], true)) {
            throw new InvalidArgumentException('The [passportless.cookie.same_site] configuration value must be lax, strict, or none.');
        }

        if (strtolower($sameSite) === 'none' && ! $this->secure()) {
            throw new InvalidArgumentException('SameSite=None requires secure Passportless cookies.');
        }

        $this->minutes('passportless.access_token.expiration', 15);
        $this->minutes('passportless.refresh_token.expiration', 60 * 24 * 30);
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
