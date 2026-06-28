<?php

namespace l3aro\AuthToken\Concerns;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use l3aro\AuthToken\AuthToken;
use l3aro\AuthToken\Models\PersonalAccessToken;
use l3aro\AuthToken\Support\NewAccessToken;

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

    public function tokenCant(string $ability): bool
    {
        return ! $this->tokenCan($ability);
    }
}
