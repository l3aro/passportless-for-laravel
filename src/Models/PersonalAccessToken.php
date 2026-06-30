<?php

namespace l3aro\AuthToken\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use l3aro\AuthToken\Contracts\HasAbilities;

/**
 * @property array<int, string>|null $abilities
 * @property Carbon|null $expires_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $revoked_at
 * @property string $token
 */
class PersonalAccessToken extends Model implements HasAbilities
{
    use HasUlids;

    protected $guarded = [];

    protected $casts = [
        'abilities' => 'array',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('auth-token-for-laravel.access_tokens_table', 'auth_tokens');
    }

    public function tokenable(): MorphTo
    {
        return $this->morphTo();
    }

    public function session(): BelongsTo
    {
        return $this->belongsTo(TokenSession::class, 'session_id');
    }

    public function can(string $ability): bool
    {
        return (config('auth-token-for-laravel.abilities.wildcard_enabled', true)
                && in_array('*', $this->abilities ?? [], true))
            || in_array($ability, $this->abilities ?? [], true);
    }

    public function cannot(string $ability): bool
    {
        return ! $this->can($ability);
    }

    public function recordUsage(Carbon $usedAt): bool
    {
        $threshold = $usedAt->copy()->subSeconds(
            max(0, (int) config('auth-token-for-laravel.access_token.last_used_update_interval', 60))
        );

        $updated = static::query()
            ->whereKey($this->getKey())
            ->where(function (Builder $query) use ($threshold): void {
                $query->whereNull('last_used_at')
                    ->orWhere('last_used_at', '<=', $threshold);
            })
            ->update(['last_used_at' => $usedAt]);

        if ($updated === 1) {
            $this->setAttribute('last_used_at', $usedAt);
        }

        return $updated === 1;
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }
}
