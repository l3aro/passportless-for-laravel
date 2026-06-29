<?php

namespace l3aro\AuthToken;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use l3aro\AuthToken\Models\PersonalAccessToken;
use l3aro\AuthToken\Models\RefreshToken;
use l3aro\AuthToken\Models\TokenSession;
use l3aro\AuthToken\Support\NewAccessToken;
use l3aro\AuthToken\Support\NewTokenPair;

class AuthToken
{
    /**
     * @param  array<int, string>  $abilities
     */
    public function createToken(Model $tokenable, string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null): NewAccessToken
    {
        $plainTextToken = Str::random(40);

        $token = $tokenable->morphMany(PersonalAccessToken::class, 'tokenable')->create([
            'name' => $name,
            'token' => hash('sha256', $plainTextToken),
            'abilities' => $abilities,
            'guard' => config('auth-token-for-laravel.guard'),
            'provider' => config('auth-token-for-laravel.provider'),
            'expires_at' => $expiresAt ?? now()->addMinutes((int) config('auth-token-for-laravel.access_token.expiration', 15)),
        ]);

        return new NewAccessToken($token, $token->getKey().'|'.$plainTextToken);
    }

    /**
     * @param  array<int, string>  $abilities
     */
    public function createTokenPair(Model $tokenable, string $name, array $abilities = ['*']): NewTokenPair
    {
        $session = $tokenable->morphMany(TokenSession::class, 'tokenable')->create([
            'name' => $name,
            'guard' => config('auth-token-for-laravel.guard'),
            'provider' => config('auth-token-for-laravel.provider'),
        ]);

        return $this->issueTokenPair($tokenable, $session, (string) Str::uuid(), $name, $abilities);
    }

    /**
     * @param  array<int, string>|null  $abilities
     */
    public function refreshToken(string $plainTextRefreshToken, ?array $abilities = null): ?NewTokenPair
    {
        $refreshToken = $this->findRefreshToken($plainTextRefreshToken);

        if (! $refreshToken instanceof RefreshToken) {
            return null;
        }

        return DB::transaction(function () use ($refreshToken, $abilities): ?NewTokenPair {
            $lockedRefreshToken = RefreshToken::query()->whereKey($refreshToken->getKey())->lockForUpdate()->first();

            if (! $lockedRefreshToken instanceof RefreshToken) {
                return null;
            }

            if ($lockedRefreshToken->isRotated()) {
                if (config('auth-token-for-laravel.refresh_token.reuse_detection', 'revoke_family') === 'revoke_family') {
                    $this->revokeFamily($lockedRefreshToken->family_id);
                }

                return null;
            }

            if ($lockedRefreshToken->isExpired() || $lockedRefreshToken->isRevoked() || ! $this->matchesConfiguredContext($lockedRefreshToken)) {
                return null;
            }

            $session = $lockedRefreshToken->session;
            $tokenable = $lockedRefreshToken->tokenable;

            if (! $session instanceof TokenSession || $session->isRevoked() || ! $this->matchesConfiguredContext($session) || ! $tokenable instanceof Model) {
                return null;
            }

            $lockedRefreshToken->forceFill(['rotated_at' => now()])->save();

            return $this->issueTokenPair(
                $tokenable,
                $session,
                $lockedRefreshToken->family_id,
                (string) $session->getAttribute('name'),
                $abilities ?? $this->abilitiesForSession($session),
            );
        });
    }

    public function findToken(string $plainTextToken): ?PersonalAccessToken
    {
        if (strlen($plainTextToken) > (int) config('auth-token-for-laravel.token.max_length', 120)) {
            return null;
        }

        if (! str_contains($plainTextToken, '|')) {
            return null;
        }

        [$id, $token] = explode('|', $plainTextToken, 2);

        if ($id === '' || $token === '') {
            return null;
        }

        $accessToken = PersonalAccessToken::query()->find($id);

        if (! $accessToken instanceof PersonalAccessToken) {
            return null;
        }

        if (! hash_equals($accessToken->token, hash('sha256', $token))) {
            return null;
        }

        if ($accessToken->isExpired() || $accessToken->isRevoked() || ! $this->matchesConfiguredContext($accessToken)) {
            return null;
        }

        return $accessToken;
    }

    public function findRefreshToken(string $plainTextToken): ?RefreshToken
    {
        if (strlen($plainTextToken) > (int) config('auth-token-for-laravel.token.max_length', 120)) {
            return null;
        }

        if (! str_contains($plainTextToken, '|')) {
            return null;
        }

        [$id, $token] = explode('|', $plainTextToken, 2);

        if ($id === '' || $token === '') {
            return null;
        }

        $refreshToken = RefreshToken::query()->find($id);

        if (! $refreshToken instanceof RefreshToken) {
            return null;
        }

        if (! hash_equals($refreshToken->token, hash('sha256', $token))) {
            return null;
        }

        return $refreshToken;
    }

    /**
     * @param  array<int, string>  $abilities
     */
    protected function issueTokenPair(Model $tokenable, TokenSession $session, string $familyId, string $name, array $abilities): NewTokenPair
    {
        $accessToken = $this->createToken($tokenable, $name, $abilities);
        $accessToken->accessToken->forceFill(['session_id' => $session->getKey()])->save();

        $plainTextRefreshToken = Str::random(64);

        $refreshToken = $tokenable->morphMany(RefreshToken::class, 'tokenable')->create([
            'session_id' => $session->getKey(),
            'family_id' => $familyId,
            'token' => hash('sha256', $plainTextRefreshToken),
            'guard' => config('auth-token-for-laravel.guard'),
            'provider' => config('auth-token-for-laravel.provider'),
            'expires_at' => now()->addMinutes((int) config('auth-token-for-laravel.refresh_token.expiration', 43200)),
        ]);

        $session->forceFill(['last_used_at' => now()])->save();

        return new NewTokenPair($accessToken, $refreshToken, $session, $refreshToken->getKey().'|'.$plainTextRefreshToken);
    }

    protected function revokeFamily(string $familyId): void
    {
        RefreshToken::query()
            ->where('family_id', $familyId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }

    protected function matchesConfiguredContext(Model $model): bool
    {
        return $model->getAttribute('guard') === config('auth-token-for-laravel.guard')
            && $model->getAttribute('provider') === config('auth-token-for-laravel.provider');
    }

    /**
     * @return array<int, string>
     */
    protected function abilitiesForSession(TokenSession $session): array
    {
        $accessToken = $session->accessTokens()
            ->latest('id')
            ->first();

        if (! $accessToken instanceof PersonalAccessToken) {
            return config('auth-token-for-laravel.abilities.default', ['*']);
        }

        return $accessToken->abilities ?? [];
    }
}
