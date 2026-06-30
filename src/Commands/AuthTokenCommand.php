<?php

namespace l3aro\AuthToken\Commands;

use Illuminate\Console\Command;
use l3aro\AuthToken\Models\PersonalAccessToken;
use l3aro\AuthToken\Models\RefreshToken;
use l3aro\AuthToken\Models\TokenSession;

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

        $sessions = 0;

        TokenSession::query()
            ->whereDoesntHave('accessTokens')
            ->whereDoesntHave('refreshTokens')
            ->select('id')
            ->chunkById(1000, function ($orphanedSessions) use (&$sessions): void {
                $sessions += TokenSession::query()->whereKey($orphanedSessions->modelKeys())->delete();
            });

        $this->info("Pruned {$accessTokens} access tokens, {$refreshTokens} refresh tokens, and {$sessions} sessions.");

        return self::SUCCESS;
    }
}
