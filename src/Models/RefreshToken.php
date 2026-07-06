<?php

namespace l3aro\Passportless\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;

/**
 * @property Carbon $expires_at
 * @property Carbon|null $rotated_at
 * @property Carbon|null $revoked_at
 * @property string $family_id
 * @property string $token
 */
class RefreshToken extends Model
{
    use HasUlids;

    protected $guarded = [];

    protected $casts = [
        'expires_at' => 'datetime',
        'rotated_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('passportless.refresh_tokens_table', 'passportless_refresh_tokens');
    }

    public function tokenable(): MorphTo
    {
        return $this->morphTo();
    }

    public function session(): BelongsTo
    {
        return $this->belongsTo(TokenSession::class, 'session_id');
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isRotated(): bool
    {
        return $this->rotated_at !== null;
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }
}
