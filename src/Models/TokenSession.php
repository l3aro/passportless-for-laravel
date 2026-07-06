<?php

namespace l3aro\Passportless\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * @property string $name
 * @property Carbon|null $revoked_at
 */
class TokenSession extends Model
{
    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    protected $casts = [
        'last_used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    protected static function booted(): void
    {
        static::creating(function (TokenSession $session): void {
            if (! $session->getKey()) {
                $session->setAttribute($session->getKeyName(), (string) Str::uuid());
            }
        });
    }

    public function getTable(): string
    {
        return config('passportless.sessions_table', 'passportless_token_sessions');
    }

    public function tokenable(): MorphTo
    {
        return $this->morphTo();
    }

    public function accessTokens(): HasMany
    {
        return $this->hasMany(PersonalAccessToken::class, 'session_id');
    }

    public function refreshTokens(): HasMany
    {
        return $this->hasMany(RefreshToken::class, 'session_id');
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }
}
