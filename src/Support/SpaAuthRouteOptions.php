<?php

namespace l3aro\Passportless\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use InvalidArgumentException;

class SpaAuthRouteOptions
{
    /**
     * @param  array<int, string>  $abilities
     * @param  callable|array{0: class-string|object, 1: string}|class-string  $authenticate
     */
    public function __construct(
        public readonly string $guard,
        public readonly mixed $authenticate,
        public readonly string $name,
        public readonly array $abilities,
        public readonly bool $csrf,
    ) {}

    public static function fromRequest(Request $request): self
    {
        $route = $request->route();

        if ($route === null) {
            throw new InvalidArgumentException('SPA auth route options require an active route.');
        }

        $guard = $route->defaults['passportlessGuard'] ?? null;
        $authenticate = $route->defaults['passportlessAuthenticate'] ?? null;
        $name = $route->defaults['passportlessName'] ?? 'browser';
        $abilities = $route->defaults['passportlessAbilities'] ?? config('passportless.abilities.default', ['*']);
        $csrf = (bool) ($route->defaults['passportlessCsrf'] ?? true);

        if (! is_string($guard) || $guard === '') {
            throw new InvalidArgumentException('SPA auth route is missing a Passportless guard.');
        }

        if ($authenticate === null) {
            throw new InvalidArgumentException('SPA auth route is missing an authenticate callable.');
        }

        if (! is_string($name) || $name === '') {
            $name = 'browser';
        }

        if (! is_array($abilities)) {
            $abilities = config('passportless.abilities.default', ['*']);
        }

        /** @var array<int, string> $abilities */
        return new self($guard, $authenticate, $name, $abilities, $csrf);
    }

    public function resolveAuthenticate(Request $request): Model|false|null
    {
        $result = app()->call($this->authenticate, ['request' => $request]);

        if ($result === null || $result === false) {
            return $result;
        }

        if (! $result instanceof Model) {
            return null;
        }

        return $result;
    }
}
