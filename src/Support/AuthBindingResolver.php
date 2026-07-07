<?php

namespace l3aro\Passportless\Support;

use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

class AuthBindingResolver
{
    public function validateConfiguration(): void
    {
        $this->resolve();
    }

    public function resolve(?string $guard = null): AuthBinding
    {
        return $this->bindingFromGuard($guard ?? $this->defaultGuard());
    }

    public function resolveForGuard(string $guard): AuthBinding
    {
        return $this->bindingFromGuard($guard);
    }

    public function resolveForStoredContext(?string $guard, ?string $provider): ?AuthBinding
    {
        if ($guard === null || $provider === null) {
            return null;
        }

        try {
            $resolved = $this->bindingFromGuard($guard);
        } catch (InvalidArgumentException) {
            return null;
        }

        return $resolved->provider === $provider ? $resolved : null;
    }

    protected function defaultGuard(): string
    {
        $guard = config('passportless.guard', 'passportless');
        $provider = config('passportless.provider');

        if (! is_string($guard) || $guard === '') {
            throw new InvalidArgumentException('Passportless guard must be a non-empty string.');
        }

        if ($provider !== null && (! is_string($provider) || $provider === '')) {
            throw new InvalidArgumentException('Passportless provider must be null or a non-empty string.');
        }

        return $guard;
    }

    protected function bindingFromGuard(string $guard): AuthBinding
    {
        $guardConfig = $this->assertPassportlessGuard($guard);
        $provider = config('passportless.provider') ?? ($guardConfig['provider'] ?? null);

        if (! is_string($provider) || $provider === '') {
            throw new InvalidArgumentException("Passportless guard [{$guard}] must define a provider.");
        }

        $model = $this->assertProvider($provider);

        return new AuthBinding($guard, $provider, $model);
    }

    /**
     * @return array<string, mixed>
     */
    protected function assertPassportlessGuard(string $guard): array
    {
        $guardConfig = config("auth.guards.{$guard}");

        if (! is_array($guardConfig)) {
            throw new InvalidArgumentException("Passportless guard [{$guard}] is not defined in auth.guards.");
        }

        if (($guardConfig['driver'] ?? null) !== 'passportless') {
            throw new InvalidArgumentException("Passportless guard [{$guard}] must use the passportless driver.");
        }

        return $guardConfig;
    }

    /**
     * @return class-string<Model>
     */
    protected function assertProvider(string $provider): string
    {
        $providerConfig = config("auth.providers.{$provider}");

        if (! is_array($providerConfig)) {
            throw new InvalidArgumentException("Passportless provider [{$provider}] is not defined in auth.providers.");
        }

        $model = $providerConfig['model'] ?? null;

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new InvalidArgumentException("Passportless provider [{$provider}] must define an Eloquent model.");
        }

        return $model;
    }
}
