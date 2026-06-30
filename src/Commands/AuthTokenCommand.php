<?php

namespace l3aro\AuthToken\Commands;

use Illuminate\Console\Command;
use l3aro\AuthToken\Models\PersonalAccessToken;
use l3aro\AuthToken\Models\RefreshToken;

class AuthTokenCommand extends Command
{
    public $signature = 'auth-token-for-laravel:prune {--hours=24 : Prune tokens expired or revoked for at least this many hours}';

    public $description = 'Prune expired and revoked auth tokens';

    public function handle(): int
    {
        $hours = max(0, (int) $this->option('hours'));
        $threshold = now()->subHours($hours);

        $accessTokens = PersonalAccessToken::query()
            ->where(function ($query) use ($threshold): void {
                $query->where('expires_at', '<=', $threshold)
                    ->orWhere('revoked_at', '<=', $threshold);
            })
            ->delete();

        $refreshTokens = RefreshToken::query()
            ->where(function ($query) use ($threshold): void {
                $query->where('expires_at', '<=', $threshold)
                    ->orWhere('revoked_at', '<=', $threshold);
            })
            ->delete();

        $this->info("Pruned {$accessTokens} access tokens and {$refreshTokens} refresh tokens.");

        return self::SUCCESS;
    }
}
