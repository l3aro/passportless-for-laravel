<?php

namespace l3aro\AuthToken\Concerns;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use l3aro\AuthToken\AuthToken;
use l3aro\AuthToken\Models\PersonalAccessToken;
use l3aro\AuthToken\Models\TokenSession;
use l3aro\AuthToken\Support\NewAccessToken;
use l3aro\AuthToken\Support\NewTokenPair;

/**
 * @mixin Model
 */
trait HasAuthTokens
{
    protected ?PersonalAccessToken $accessToken = null;

    public function tokens(): MorphMany
    {
        return $this->morphMany(PersonalAccessToken::class, 'tokenable');
    }

    /**
     * @param  array<int, string>  $abilities
     */
    public function createToken(string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null): NewAccessToken
    {
        return app(AuthToken::class)->createToken($this, $name, $abilities, $expiresAt);
    }

    /**
     * @param  array<int, string>  $abilities
     */
    public function createTokenPair(string $name, array $abilities = ['*']): NewTokenPair
    {
        return app(AuthToken::class)->createTokenPair($this, $name, $abilities);
    }

    public function tokenSessions(): MorphMany
    {
        return $this->morphMany(TokenSession::class, 'tokenable');
    }

    public function currentAccessToken(): ?PersonalAccessToken
    {
        return $this->accessToken;
    }

    public function withAccessToken(PersonalAccessToken $accessToken): static
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function tokenCan(string $ability): bool
    {
        return $this->accessToken?->can($ability) ?? false;
    }

    public function tokenCannot(string $ability): bool
    {
        return ! $this->tokenCan($ability);
    }
}
