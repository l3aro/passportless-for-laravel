<?php

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

class PassportlessRevokeTestUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_revoke_users';
}
