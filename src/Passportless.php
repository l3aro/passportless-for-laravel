<?php

namespace l3aro\Passportless;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use l3aro\Passportless\Enums\RefreshTokenReuseDetection;
use l3aro\Passportless\Models\PersonalAccessToken;
use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Models\TokenSession;
use l3aro\Passportless\Support\AuthBinding;
use l3aro\Passportless\Support\AuthBindingResolver;
use l3aro\Passportless\Support\NewAccessToken;
use l3aro\Passportless\Support\NewTokenPair;

class Passportless
{
    public function __construct(protected AuthBindingResolver $authBindings) {}

    /**
     * @param  array<int, string>  $abilities
     */
    public function createToken(Model $tokenable, string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null, string|int|null $sessionId = null, ?string $guard = null): NewAccessToken
    {
        $resolved = $this->authBindings->resolve($guard);
        $this->assertTokenableMatchesBinding($tokenable, $resolved);

        $plainTextToken = Str::random(40);

        $token = $tokenable->morphMany(PersonalAccessToken::class, 'tokenable')->create([
            'name' => $name,
            'token' => hash('sha256', $plainTextToken),
            'abilities' => $abilities,
            'session_id' => $sessionId,
            'guard' => $resolved->guard,
            'provider' => $resolved->provider,
            'expires_at' => $expiresAt ?? now()->addMinutes((int) config('passportless.access_token.expiration', 15)),
        ]);

        return new NewAccessToken($token, $token->getKey().'|'.$plainTextToken);
    }

    /**
     * @param  array<int, string>  $abilities
     */
    public function createTokenPair(Model $tokenable, string $name, array $abilities = ['*'], ?string $guard = null): NewTokenPair
    {
        $resolved = $this->authBindings->resolve($guard);

        return DB::transaction(function () use ($tokenable, $name, $abilities, $resolved): NewTokenPair {
            $session = $tokenable->morphMany(TokenSession::class, 'tokenable')->create([
                'name' => $name,
                'guard' => $resolved->guard,
                'provider' => $resolved->provider,
            ]);

            return $this->issueTokenPair($tokenable, $session, (string) Str::uuid(), $name, $abilities, $resolved);
        });
    }

    /**
     * @param  array<int, string>|null  $abilities
     */
    public function refreshToken(string $plainTextRefreshToken, ?array $abilities = null, ?string $guard = null): ?NewTokenPair
    {
        $parsedToken = $this->parsePlainTextToken($plainTextRefreshToken);

        if ($parsedToken === null) {
            return null;
        }

        return DB::transaction(function () use ($parsedToken, $abilities, $guard): ?NewTokenPair {
            $locatedRefreshToken = RefreshToken::query()->whereKey($parsedToken['id'])->first();

            if (! $locatedRefreshToken instanceof RefreshToken
                || ! $this->credentialHashMatches($locatedRefreshToken, $parsedToken['token'])) {
                return null;
            }

            $sessionId = $locatedRefreshToken->getAttribute('session_id');

            if (! is_string($sessionId) && ! is_int($sessionId)) {
                return null;
            }

            $lockedSession = TokenSession::query()->whereKey($sessionId)->lockForUpdate()->first();
            $lockedRefreshToken = RefreshToken::query()->whereKey($locatedRefreshToken->getKey())->lockForUpdate()->first();
            $validated = $this->validateLockedCredentialSession(
                $lockedRefreshToken,
                $lockedSession,
                $parsedToken['token'],
                $guard,
            );

            if ($validated === null || $lockedRefreshToken->isExpired() || $lockedRefreshToken->isRevoked()) {
                return null;
            }

            [$session, $tokenable, $binding] = $validated;

            if ($this->shouldRevokeFamily($lockedRefreshToken)) {
                $this->revokeFamily($lockedRefreshToken->family_id, $binding);

                return null;
            }

            if ($lockedRefreshToken->isRotated()) {
                return null;
            }

            $currentAbilities = $this->abilitiesForSession($session, $binding);
            $nextAbilities = $abilities ?? $currentAbilities;

            if (! $this->abilitiesAreSubset($nextAbilities, $currentAbilities)) {
                return null;
            }

            $lockedRefreshToken->forceFill(['rotated_at' => now()])->save();

            return $this->issueTokenPair(
                $tokenable,
                $session,
                $lockedRefreshToken->family_id,
                (string) $session->getAttribute('name'),
                $nextAbilities,
                $binding,
            );
        });
    }

    public function revokeCurrentSession(string $plainTextAccessToken, string $guard): void
    {
        $this->revokeSessionFromCredential($plainTextAccessToken, $guard, PersonalAccessToken::class);
    }

    public function revokeSessionFromRefreshToken(string $plainTextRefreshToken, string $guard): void
    {
        $this->revokeSessionFromCredential($plainTextRefreshToken, $guard, RefreshToken::class);
    }

    public function findToken(string $plainTextToken, ?string $guard = null): ?PersonalAccessToken
    {
        $parsedToken = $this->parsePlainTextToken($plainTextToken);

        if ($parsedToken === null) {
            return null;
        }

        $accessToken = PersonalAccessToken::query()->find($parsedToken['id']);

        if (! $accessToken instanceof PersonalAccessToken) {
            return null;
        }

        if (! hash_equals($accessToken->token, hash('sha256', $parsedToken['token']))) {
            return null;
        }

        $binding = $this->resolveStoredContext($accessToken);

        if ($accessToken->isExpired() || $accessToken->isRevoked() || ! $binding instanceof AuthBinding) {
            return null;
        }

        if ($guard !== null && $binding->guard !== $guard) {
            return null;
        }

        $sessionId = $accessToken->getAttribute('session_id');

        if ($sessionId !== null) {
            $session = $accessToken->session;

            if (! $session instanceof TokenSession || $session->isRevoked() || ! $this->matchesConfiguredContext($session, $binding)) {
                return null;
            }
        }

        $tokenable = $accessToken->tokenable;

        if (! $tokenable instanceof Model || ! $this->tokenableMatchesBinding($tokenable, $binding)) {
            return null;
        }

        return $accessToken;
    }

    public function findRefreshToken(string $plainTextToken): ?RefreshToken
    {
        $parsedToken = $this->parsePlainTextToken($plainTextToken);

        if ($parsedToken === null) {
            return null;
        }

        $refreshToken = RefreshToken::query()->find($parsedToken['id']);

        if (! $refreshToken instanceof RefreshToken) {
            return null;
        }

        if (! hash_equals($refreshToken->token, hash('sha256', $parsedToken['token']))) {
            return null;
        }

        return $refreshToken;
    }

    public function revokeCurrentSessionByRefreshToken(string $plainTextRefreshToken, string $guard): void
    {
        $this->revokeSessionFromCredential($plainTextRefreshToken, $guard, RefreshToken::class);
    }

    /**
     * @return array{id: string, token: string}|null
     */
    protected function parsePlainTextToken(string $plainTextToken): ?array
    {
        if (strlen($plainTextToken) > (int) config('passportless.token.max_length', 120)) {
            return null;
        }

        if (! str_contains($plainTextToken, '|')) {
            return null;
        }

        [$id, $token] = explode('|', $plainTextToken, 2);

        if ($id === '' || $token === '') {
            return null;
        }

        return ['id' => $id, 'token' => $token];
    }

    protected function revokeSession(TokenSession $session, AuthBinding $binding): void
    {
        $sessionKey = $session->getKey();
        $revokedAt = now();

        if (! $session->isRevoked()) {
            $session->forceFill(['revoked_at' => $revokedAt])->save();
        }

        PersonalAccessToken::query()
            ->where('session_id', $sessionKey)
            ->where('guard', $binding->guard)
            ->where('provider', $binding->provider)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $revokedAt]);

        RefreshToken::query()
            ->where('session_id', $sessionKey)
            ->where('guard', $binding->guard)
            ->where('provider', $binding->provider)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $revokedAt]);
    }

    /**
     * @param  array<int, string>  $abilities
     */
    protected function issueTokenPair(Model $tokenable, TokenSession $session, string $familyId, string $name, array $abilities, AuthBinding $binding): NewTokenPair
    {
        $accessToken = $this->createToken($tokenable, $name, $abilities, null, $session->getKey(), $binding->guard);

        $plainTextRefreshToken = Str::random(64);

        $refreshToken = $tokenable->morphMany(RefreshToken::class, 'tokenable')->create([
            'session_id' => $session->getKey(),
            'family_id' => $familyId,
            'token' => hash('sha256', $plainTextRefreshToken),
            'guard' => $binding->guard,
            'provider' => $binding->provider,
            'expires_at' => now()->addMinutes((int) config('passportless.refresh_token.expiration', 60 * 24 * 30)),
        ]);

        $session->forceFill(['last_used_at' => now()])->save();

        return new NewTokenPair($accessToken, $refreshToken, $session, $refreshToken->getKey().'|'.$plainTextRefreshToken);
    }

    protected function revokeFamily(string $familyId, AuthBinding $binding): void
    {
        RefreshToken::query()
            ->where('family_id', $familyId)
            ->where('guard', $binding->guard)
            ->where('provider', $binding->provider)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }

    /**
     * @param  class-string<PersonalAccessToken|RefreshToken>  $credentialClass
     */
    private function revokeSessionFromCredential(string $plainTextCredential, string $guard, string $credentialClass): void
    {
        $parsedToken = $this->parsePlainTextToken($plainTextCredential);

        if ($parsedToken === null) {
            return;
        }

        DB::transaction(function () use ($parsedToken, $guard, $credentialClass): void {
            $locatedCredential = $credentialClass::query()->whereKey($parsedToken['id'])->first();

            if (! $locatedCredential instanceof Model
                || ! is_a($locatedCredential, $credentialClass)
                || ! $this->credentialHashMatches($locatedCredential, $parsedToken['token'])) {
                return;
            }

            $sessionId = $locatedCredential->getAttribute('session_id');

            if (! is_string($sessionId) && ! is_int($sessionId)) {
                return;
            }

            $credentialWasActiveBeforeSessionLock = $this->credentialIsActive($locatedCredential);
            $lockedSession = TokenSession::query()->whereKey($sessionId)->lockForUpdate()->first();
            $lockedCredential = $credentialClass::query()->whereKey($locatedCredential->getKey())->lockForUpdate()->first();
            $validated = $this->validateLockedCredentialSession(
                $lockedCredential,
                $lockedSession,
                $parsedToken['token'],
                $guard,
            );

            if ($validated === null
                || (! $lockedCredential instanceof PersonalAccessToken && ! $lockedCredential instanceof RefreshToken)
                || ! $this->credentialCanRevoke($lockedCredential, $credentialWasActiveBeforeSessionLock)) {
                return;
            }

            [$session, , $binding] = $validated;
            $this->revokeValidatedSession($session, $binding);
        });
    }

    /**
     * @return array{TokenSession, Model, AuthBinding}|null
     */
    private function validateLockedCredentialSession(mixed $credential, mixed $session, string $secret, ?string $guard): ?array
    {
        if ((! $credential instanceof PersonalAccessToken && ! $credential instanceof RefreshToken)
            || ! $session instanceof TokenSession
            || ! $this->credentialHashMatches($credential, $secret)) {
            return null;
        }

        $binding = $this->resolveStoredContext($credential);

        if (! $binding instanceof AuthBinding
            || ($guard !== null && $binding->guard !== $guard)
            || (string) $credential->getAttribute('session_id') !== (string) $session->getKey()
            || $session->isRevoked()
            || ! $this->matchesConfiguredContext($session, $binding)
            || ! $this->rawOwnerIdentityMatches($credential, $session)) {
            return null;
        }

        $credentialOwner = $credential->tokenable;
        $sessionOwner = $session->tokenable;

        if (! $credentialOwner instanceof Model
            || ! $sessionOwner instanceof Model
            || ! $this->tokenableMatchesBinding($credentialOwner, $binding)
            || ! $this->tokenableMatchesBinding($sessionOwner, $binding)
            || $credentialOwner->getMorphClass() !== $this->stringOrNull($credential->getAttribute('tokenable_type'))
            || $sessionOwner->getMorphClass() !== $this->stringOrNull($session->getAttribute('tokenable_type'))
            || (string) $credentialOwner->getKey() !== (string) $credential->getAttribute('tokenable_id')
            || (string) $sessionOwner->getKey() !== (string) $session->getAttribute('tokenable_id')) {
            return null;
        }

        return [$session, $credentialOwner, $binding];
    }

    private function rawOwnerIdentityMatches(Model $credential, TokenSession $session): bool
    {
        return $credential->getAttribute('tokenable_type') === $session->getAttribute('tokenable_type')
            && (string) $credential->getAttribute('tokenable_id') === (string) $session->getAttribute('tokenable_id');
    }

    private function credentialHashMatches(Model $credential, string $secret): bool
    {
        $hash = $credential->getAttribute('token');

        return is_string($hash) && hash_equals($hash, hash('sha256', $secret));
    }

    private function credentialIsActive(PersonalAccessToken|RefreshToken $credential): bool
    {
        return ! $credential->isExpired()
            && ! $credential->isRevoked()
            && (! $credential instanceof RefreshToken || ! $credential->isRotated());
    }

    private function credentialCanRevoke(PersonalAccessToken|RefreshToken $credential, bool $wasActiveBeforeSessionLock): bool
    {
        return ! $credential->isExpired()
            && ! $credential->isRevoked()
            && (! $credential instanceof RefreshToken || ! $credential->isRotated() || $wasActiveBeforeSessionLock);
    }

    private function revokeValidatedSession(TokenSession $session, AuthBinding $binding): void
    {
        $revokedAt = now();

        $session->forceFill(['revoked_at' => $revokedAt])->save();

        PersonalAccessToken::query()
            ->where('session_id', $session->getKey())
            ->where('guard', $binding->guard)
            ->where('provider', $binding->provider)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $revokedAt]);

        RefreshToken::query()
            ->where('session_id', $session->getKey())
            ->where('guard', $binding->guard)
            ->where('provider', $binding->provider)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $revokedAt]);
    }

    protected function matchesConfiguredContext(Model $model, AuthBinding $binding): bool
    {
        $resolved = $this->resolveStoredContext($model);

        return $resolved instanceof AuthBinding
            && $resolved->guard === $binding->guard
            && $resolved->provider === $binding->provider;
    }

    protected function resolveStoredContext(Model $model): ?AuthBinding
    {
        return $this->authBindings->resolveForStoredContext(
            $this->stringOrNull($model->getAttribute('guard')),
            $this->stringOrNull($model->getAttribute('provider')),
        );
    }

    protected function stringOrNull(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    protected function assertTokenableMatchesBinding(Model $tokenable, AuthBinding $binding): void
    {
        if (! $this->tokenableMatchesBinding($tokenable, $binding)) {
            throw new \InvalidArgumentException("Tokenable model does not match Passportless guard [{$binding->guard}].");
        }
    }

    protected function tokenableMatchesBinding(Model $tokenable, AuthBinding $binding): bool
    {
        return $tokenable instanceof $binding->model;
    }

    /**
     * @return array<int, string>
     */
    protected function abilitiesForSession(TokenSession $session, AuthBinding $binding): array
    {
        $accessToken = $session->accessTokens()
            ->where('guard', $binding->guard)
            ->where('provider', $binding->provider)
            ->latest('id')
            ->first();

        if (! $accessToken instanceof PersonalAccessToken) {
            return config('passportless.abilities.default', ['*']);
        }

        return $accessToken->abilities ?? [];
    }

    protected function shouldRevokeFamily(RefreshToken $token): bool
    {
        if (! $token->isRotated()) {
            return false;
        }

        $value = config('passportless.refresh_token.reuse_detection', RefreshTokenReuseDetection::REVOKE_FAMILY);

        $detection = $value instanceof RefreshTokenReuseDetection
            ? $value
            : (RefreshTokenReuseDetection::tryFrom((string) $value) ?? RefreshTokenReuseDetection::IGNORE);

        return $detection === RefreshTokenReuseDetection::REVOKE_FAMILY;
    }

    /**
     * @param  array<int, string>  $requested
     * @param  array<int, string>  $granted
     */
    protected function abilitiesAreSubset(array $requested, array $granted): bool
    {
        if (config('passportless.abilities.wildcard_enabled', true)
            && in_array('*', $granted, true)) {
            return true;
        }

        foreach ($requested as $ability) {
            if (! in_array($ability, $granted, true)) {
                return false;
            }
        }

        return true;
    }
}
