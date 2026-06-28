<?php

namespace l3aro\AuthToken\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use l3aro\AuthToken\Contracts\HasAbilities;

/**
 * @property array<int, string>|null $abilities
 * @property Carbon|null $expires_at
 * @property string $token
 */
class PersonalAccessToken extends Model implements HasAbilities
{
    protected $guarded = [];

    protected $casts = [
        'abilities' => 'array',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('auth-token-for-laravel.table', 'auth_tokens');
    }

    public function tokenable(): MorphTo
    {
        return $this->morphTo();
    }

    public function can(string $ability): bool
    {
        return in_array('*', $this->abilities ?? [], true)
            || in_array($ability, $this->abilities ?? [], true);
    }

    public function cant(string $ability): bool
    {
        return ! $this->can($ability);
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }
}
