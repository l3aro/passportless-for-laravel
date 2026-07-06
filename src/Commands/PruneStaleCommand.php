<?php

namespace l3aro\Passportless\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use l3aro\Passportless\Models\PersonalAccessToken;
use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Models\TokenSession;

class PruneStaleCommand extends Command
{
    public $signature = 'passportless:prune-stale {--hours=24 : Prune tokens expired or revoked for at least this many hours}';

    public $description = 'Prune expired and revoked auth tokens';

    public function handle(): int
    {
        $hours = max(0, (int) $this->option('hours'));
        $threshold = now()->subHours($hours);

        $accessTokens = $this->deleteExpiredOrRevokedInChunks(PersonalAccessToken::class, $threshold);
        $refreshTokens = $this->deleteExpiredOrRevokedInChunks(RefreshToken::class, $threshold);

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

    /**
     * @param  class-string<Model>  $modelClass
     */
    protected function deleteExpiredOrRevokedInChunks(string $modelClass, mixed $threshold): int
    {
        $deleted = 0;

        $modelClass::query()
            ->where(function (Builder $query) use ($threshold): void {
                $query->where('expires_at', '<=', $threshold)
                    ->orWhere('revoked_at', '<=', $threshold);
            })
            ->select('id')
            ->chunkById(1000, function ($tokens) use (&$deleted): void {
                $deleted += $tokens->first()?->newQuery()->whereKey($tokens->modelKeys())->delete() ?? 0;
            });

        return $deleted;
    }
}
