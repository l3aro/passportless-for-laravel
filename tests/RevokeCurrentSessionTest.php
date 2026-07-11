<?php

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Models\PersonalAccessToken;
use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Models\Tokenable;
use l3aro\Passportless\Models\TokenSession;
use l3aro\Passportless\Passportless;

beforeEach(function () {
    config()->set('auth.providers.users.model', PassportlessRevokeTestUser::class);
    config()->set('auth.guards.passportless', [
        'driver' => 'passportless',
        'provider' => 'users',
    ]);
    config()->set('auth.guards.passportless-other', [
        'driver' => 'passportless',
        'provider' => 'other-users',
    ]);
    config()->set('auth.providers.other-users.model', PassportlessRevokeTestUser::class);
    config()->set('passportless.guard', 'passportless');

    Schema::create('passportless_revoke_users', function (Blueprint $table) {
        $table->id();
    });

    Schema::create('passportless_token_sessions', function (Blueprint $table) {
        $table->uuid('id')->primary();
        $table->morphs('tokenable');
        $table->string('name');
        $table->string('guard')->nullable();
        $table->string('provider')->nullable();
        $table->string('ip_address', 45)->nullable();
        $table->text('user_agent')->nullable();
        $table->timestamp('last_used_at')->nullable();
        $table->timestamp('revoked_at')->nullable();
        $table->timestamps();
    });

    Schema::create('passportless_tokens', function (Blueprint $table) {
        $table->ulid('id')->primary();
        $table->morphs('tokenable');
        $table->uuid('session_id')->nullable();
        $table->string('name');
        $table->string('token', 64)->unique();
        $table->json('abilities')->nullable();
        $table->string('guard')->nullable();
        $table->string('provider')->nullable();
        $table->timestamp('last_used_at')->nullable();
        $table->timestamp('expires_at')->nullable();
        $table->timestamp('revoked_at')->nullable();
        $table->timestamps();
    });

    Schema::create('passportless_refresh_tokens', function (Blueprint $table) {
        $table->ulid('id')->primary();
        $table->morphs('tokenable');
        $table->uuid('session_id');
        $table->uuid('family_id');
        $table->string('token', 64)->unique();
        $table->string('guard')->nullable();
        $table->string('provider')->nullable();
        $table->timestamp('expires_at');
        $table->timestamp('rotated_at')->nullable();
        $table->timestamp('revoked_at')->nullable();
        $table->timestamps();
    });
});

it('revokes session access tokens and refresh tokens for the current device', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $pair = $user->createTokenPair('browser', ['orders:read']);
    $other = $user->createTokenPair('other-device', ['orders:read']);

    app(Passportless::class)->revokeCurrentSession(
        $pair->plainTextAccessToken(),
        'passportless',
    );

    expect(TokenSession::query()->find($pair->session->getKey())?->revoked_at)->not->toBeNull()
        ->and(PersonalAccessToken::query()->find($pair->accessToken->accessToken->getKey())?->revoked_at)->not->toBeNull()
        ->and(RefreshToken::query()->find($pair->refreshToken->getKey())?->revoked_at)->not->toBeNull()
        ->and(TokenSession::query()->find($other->session->getKey())?->revoked_at)->toBeNull()
        ->and(PersonalAccessToken::query()->find($other->accessToken->accessToken->getKey())?->revoked_at)->toBeNull()
        ->and(RefreshToken::query()->find($other->refreshToken->getKey())?->revoked_at)->toBeNull()
        ->and(app(Passportless::class)->findToken($pair->plainTextAccessToken()))->toBeNull()
        ->and(app(Passportless::class)->refreshToken($pair->plainTextRefreshToken()))->toBeNull();
});

it('is idempotent for missing invalid and wrong-guard tokens', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $pair = $user->createTokenPair('browser', ['orders:read']);

    app(Passportless::class)->revokeCurrentSession('not-a-token', 'passportless');
    app(Passportless::class)->revokeCurrentSession($pair->plainTextAccessToken(), 'passportless-admin');
    app(Passportless::class)->revokeCurrentSession($pair->plainTextAccessToken(), 'passportless');
    app(Passportless::class)->revokeCurrentSession($pair->plainTextAccessToken(), 'passportless');

    expect(TokenSession::query()->find($pair->session->getKey())?->revoked_at)->not->toBeNull()
        ->and(PersonalAccessToken::query()->find($pair->accessToken->accessToken->getKey())?->revoked_at)->not->toBeNull();
});

it('revokes a session from its active refresh token', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $pair = $user->createTokenPair('browser', ['orders:read']);

    app(Passportless::class)->revokeCurrentSessionByRefreshToken(
        $pair->plainTextRefreshToken(),
        'passportless',
    );

    expect(TokenSession::query()->find($pair->session->getKey())?->revoked_at)->not->toBeNull()
        ->and(PersonalAccessToken::query()->find($pair->accessToken->accessToken->getKey())?->revoked_at)->not->toBeNull()
        ->and(RefreshToken::query()->find($pair->refreshToken->getKey())?->revoked_at)->not->toBeNull();
});

it('logs out the current session with the revocation alias', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $pair = $user->createTokenPair('browser', ['orders:read']);

    app(Passportless::class)->logoutCurrentSession($pair->plainTextAccessToken(), 'passportless');

    expect(TokenSession::query()->find($pair->session->getKey())?->revoked_at)->not->toBeNull()
        ->and(PersonalAccessToken::query()->find($pair->accessToken->accessToken->getKey())?->revoked_at)->not->toBeNull()
        ->and(RefreshToken::query()->find($pair->refreshToken->getKey())?->revoked_at)->not->toBeNull();
});

it('logs out every matching active session and preserves unrelated bindings', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $otherUser = PassportlessRevokeTestUser::query()->create();
    $first = $user->createTokenPair('phone', guard: 'passportless');
    $second = $user->createTokenPair('laptop', guard: 'passportless');
    $otherBinding = $user->createTokenPair('admin', guard: 'passportless-other');
    $otherOwner = $otherUser->createTokenPair('other', guard: 'passportless');

    app(Passportless::class)->logoutAllSessions($user, 'passportless');
    app(Passportless::class)->logoutAllSessions($user, 'passportless');

    expect($first->session->fresh()->isRevoked())->toBeTrue()
        ->and($first->accessToken->accessToken->fresh()->isRevoked())->toBeTrue()
        ->and($first->refreshToken->fresh()->isRevoked())->toBeTrue()
        ->and($second->session->fresh()->isRevoked())->toBeTrue()
        ->and($second->accessToken->accessToken->fresh()->isRevoked())->toBeTrue()
        ->and($second->refreshToken->fresh()->isRevoked())->toBeTrue()
        ->and($otherBinding->session->fresh()->isRevoked())->toBeFalse()
        ->and($otherOwner->session->fresh()->isRevoked())->toBeFalse();
});

it('treats no matching active sessions as an idempotent no-op', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $other = PassportlessRevokeTestUser::query()->create();
    $pair = $other->createTokenPair('browser');

    app(Passportless::class)->logoutAllSessions($user, 'passportless');
    app(Passportless::class)->logoutAllSessions($user, 'passportless');

    expect($pair->session->fresh()->isRevoked())->toBeFalse();
});

it('prevents refresh after all-session logout', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $pair = $user->createTokenPair('browser');
    $service = app(Passportless::class);

    $service->logoutAllSessions($user, 'passportless');

    expect($service->refreshToken($pair->plainTextRefreshToken(), guard: 'passportless'))->toBeNull()
        ->and($pair->session->fresh()->isRevoked())->toBeTrue();
});

it('revokes refresh replacements when refresh completes before all-session logout', function () {
    $user = PassportlessRevokeTestUser::query()->create();
    $pair = $user->createTokenPair('browser');
    $service = app(Passportless::class);

    $replacement = $service->refreshToken($pair->plainTextRefreshToken(), guard: 'passportless');

    expect($replacement)->not->toBeNull();

    if ($replacement === null) {
        $this->fail('Refresh token rotation failed.');
    }

    $service->logoutAllSessions($user, 'passportless');

    expect($pair->session->fresh()->isRevoked())->toBeTrue()
        ->and($replacement->accessToken->accessToken->fresh()->isRevoked())->toBeTrue()
        ->and($replacement->refreshToken->fresh()->isRevoked())->toBeTrue();
});

class PassportlessRevokeTestUser extends Tokenable implements Authenticatable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_revoke_users';

    public function getAuthIdentifierName(): string
    {
        return $this->getKeyName();
    }

    public function getAuthIdentifier(): mixed
    {
        return $this->getKey();
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): void {}

    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }
}
