<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Models\Tokenable;
use l3aro\Passportless\Passportless;

beforeEach(function () {
    config()->set('auth.providers.users.model', PassportlessRefreshTestUser::class);

    Schema::create('auth_token_refresh_test_users', function (Blueprint $table) {
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

it('issues access and refresh tokens for a session', function () {
    $user = PassportlessRefreshTestUser::query()->create();

    $pair = $user->createTokenPair('iphone', ['orders:read']);

    expect($pair->plainTextAccessToken())->toContain('|')
        ->and($pair->plainTextRefreshToken())->toContain('|')
        ->and($pair->session->exists)->toBeTrue()
        ->and($pair->refreshToken->token)->not->toBe($pair->plainTextRefreshToken());
});

it('rotates refresh tokens once', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    $rotated = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken(), ['orders:read']);

    expect($rotated)->not->toBeNull()
        ->and($pair->refreshToken->fresh()->isRotated())->toBeTrue();

    if ($rotated === null) {
        $this->fail('Refresh token rotation failed.');
    }

    expect($rotated->plainTextRefreshToken())->not->toBe($pair->plainTextRefreshToken())
        ->and($rotated->refreshToken->family_id)->toBe($pair->refreshToken->family_id)
        ->and($rotated->session->getKey())->toBe($pair->session->getKey());
});

it('preserves existing abilities when refresh caller does not pass abilities', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    $rotated = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken());

    if ($rotated === null) {
        $this->fail('Refresh token rotation failed.');
    }

    expect($rotated->accessToken->accessToken->can('orders:read'))->toBeTrue()
        ->and($rotated->accessToken->accessToken->can('orders:write'))->toBeFalse();
});

it('rejects ability expansion during refresh', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    $rotated = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken(), ['orders:read', 'orders:write']);

    expect($rotated)->toBeNull()
        ->and($pair->refreshToken->fresh()->isRotated())->toBeFalse();
});

it('does not coerce malformed abilities during refresh', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', [1]);

    $rotated = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken(), ['1']);

    expect($rotated)->toBeNull()
        ->and($pair->refreshToken->fresh()->isRotated())->toBeFalse();
});

it('allows ability narrowing during refresh', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read', 'orders:write']);

    $rotated = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken(), ['orders:read']);

    expect($rotated)->not->toBeNull()
        ->and($rotated?->accessToken->accessToken->can('orders:read'))->toBeTrue()
        ->and($rotated?->accessToken->accessToken->can('orders:write'))->toBeFalse();
});

it('rejects refresh tokens issued for a removed configured guard', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    config()->set('auth.guards.passportless', null);

    expect(app(Passportless::class)->refreshToken($pair->plainTextRefreshToken()))->toBeNull();
});

it('rejects access tokens issued before the guard provider changed', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    config()->set('auth.providers.other-provider', [
        'driver' => 'eloquent',
        'model' => PassportlessRefreshTestUser::class,
    ]);
    config()->set('auth.guards.passportless.provider', 'other-provider');

    expect(app(Passportless::class)->findToken($pair->plainTextAccessToken()))->toBeNull();
});

it('rejects access tokens for revoked sessions', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    $pair->session->forceFill(['revoked_at' => now()])->save();

    expect(app(Passportless::class)->findToken($pair->plainTextAccessToken()))->toBeNull();
});

it('revokes refresh token family when a rotated refresh token is reused', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    app(Passportless::class)->refreshToken($pair->plainTextRefreshToken(), ['orders:read']);

    $reused = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken(), ['orders:read']);

    expect($reused)->toBeNull()
        ->and(RefreshToken::query()->where('family_id', $pair->refreshToken->family_id)->whereNull('revoked_at')->count())->toBe(0);
});

it('can leave refresh token family untouched on reuse when configured', function () {
    config()->set('passportless.refresh_token.reuse_detection', 'ignore');

    $user = PassportlessRefreshTestUser::query()->create();
    $pair = $user->createTokenPair('iphone', ['orders:read']);

    app(Passportless::class)->refreshToken($pair->plainTextRefreshToken());

    $reused = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken());

    expect($reused)->toBeNull()
        ->and(RefreshToken::query()->where('family_id', $pair->refreshToken->family_id)->whereNull('revoked_at')->count())->toBe(2);
});

it('returns null for malformed plainText tokens (parse failures in findToken/findRefreshToken)', function () {
    $auth = app(Passportless::class);

    // over max_length (default 120)
    expect($auth->findToken(str_repeat('x', 130)))->toBeNull();

    // no pipe
    expect($auth->findToken('no-separator-here'))->toBeNull();

    // empty id part or token part
    expect($auth->findToken('|secret'))->toBeNull()
        ->and($auth->findRefreshToken('123|'))->toBeNull();
});

it('prunes orphaned token sessions', function () {
    $user = PassportlessRefreshTestUser::query()->create();
    $expiredPair = $user->createTokenPair('expired', ['orders:read']);
    $activePair = $user->createTokenPair('active', ['orders:read']);

    $expiredPair->accessToken->accessToken->forceFill(['expires_at' => now()->subHour()])->save();
    $expiredPair->refreshToken->forceFill(['expires_at' => now()->subHour()])->save();

    $this->artisan('passportless:prune-stale', ['--hours' => 0])
        ->assertSuccessful();

    expect($expiredPair->session->fresh())->toBeNull()
        ->and($activePair->session->fresh())->not->toBeNull();
});

class PassportlessRefreshTestUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'auth_token_refresh_test_users';
}
