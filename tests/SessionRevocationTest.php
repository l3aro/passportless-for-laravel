<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Models\Tokenable;
use l3aro\Passportless\Passportless;

beforeEach(function () {
    config()->set('auth.providers.users.model', PassportlessSessionRevocationUser::class);

    Schema::create('passportless_session_revocation_users', function (Blueprint $table) {
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

it('revokes a complete session from either active credential and leaves unrelated sessions unchanged', function (string $credential) {
    $user = PassportlessSessionRevocationUser::query()->create();
    $pair = $user->createTokenPair('phone');
    $secondAccess = app(Passportless::class)->createToken(
        $user,
        'phone-extra',
        sessionId: $pair->session->getKey(),
    );
    $secondRefresh = RefreshToken::query()->create([
        'tokenable_type' => $user->getMorphClass(),
        'tokenable_id' => $user->getKey(),
        'session_id' => $pair->session->getKey(),
        'family_id' => fake()->uuid(),
        'token' => hash('sha256', 'other-refresh-secret'),
        'guard' => 'passportless',
        'provider' => 'users',
        'expires_at' => now()->addHour(),
    ]);
    $unrelated = $user->createTokenPair('laptop');

    $service = app(Passportless::class);
    $credential === 'access'
        ? $service->revokeCurrentSession($pair->plainTextAccessToken(), 'passportless')
        : $service->revokeSessionFromRefreshToken($pair->plainTextRefreshToken(), 'passportless');
    $credential === 'access'
        ? $service->revokeCurrentSession($pair->plainTextAccessToken(), 'passportless')
        : $service->revokeSessionFromRefreshToken($pair->plainTextRefreshToken(), 'passportless');

    expect($pair->session->fresh()->isRevoked())->toBeTrue()
        ->and($pair->accessToken->accessToken->fresh()->isRevoked())->toBeTrue()
        ->and($secondAccess->accessToken->fresh()->isRevoked())->toBeTrue()
        ->and($pair->refreshToken->fresh()->isRevoked())->toBeTrue()
        ->and($secondRefresh->fresh()->isRevoked())->toBeTrue()
        ->and($unrelated->session->fresh()->isRevoked())->toBeFalse()
        ->and($unrelated->accessToken->accessToken->fresh()->isRevoked())->toBeFalse()
        ->and($unrelated->refreshToken->fresh()->isRevoked())->toBeFalse()
        ->and($pair->session->fresh()->revoked_at->equalTo($pair->accessToken->accessToken->fresh()->revoked_at))->toBeTrue()
        ->and($pair->session->fresh()->revoked_at->equalTo($pair->refreshToken->fresh()->revoked_at))->toBeTrue();
})->with(['access', 'refresh']);

it('treats invalid and inactive access credentials as repeatable no-ops', function (Closure $mutate, string $credential) {
    $user = PassportlessSessionRevocationUser::query()->create();
    $pair = $user->createTokenPair('phone');
    $plainText = $mutate($pair, $credential);

    $service = app(Passportless::class);
    $service->revokeCurrentSession($plainText, 'passportless');
    $service->revokeCurrentSession($plainText, 'passportless');

    expect($pair->session->fresh()->revoked_at)->toBeNull();
})->with([
    'malformed' => [fn($pair, $credential) => 'malformed', 'access'],
    'oversized' => [fn($pair, $credential) => str_repeat('x', 121), 'access'],
    'unknown' => [fn($pair, $credential) => '01J00000000000000000000000|secret', 'access'],
    'hash mismatch' => [fn($pair, $credential) => $pair->accessToken->accessToken->getKey() . '|wrong', 'access'],
    'expired' => [function ($pair, $credential) {
        $pair->accessToken->accessToken->forceFill(['expires_at' => now()->subMinute()])->save();

        return $pair->plainTextAccessToken();
    }, 'access'],
    'revoked' => [function ($pair, $credential) {
        $pair->accessToken->accessToken->forceFill(['revoked_at' => now()])->save();

        return $pair->plainTextAccessToken();
    }, 'access'],
]);

it('treats invalid and inactive refresh credentials as repeatable no-ops', function (Closure $mutate) {
    $user = PassportlessSessionRevocationUser::query()->create();
    $pair = $user->createTokenPair('phone');
    $plainText = $mutate($pair);

    $service = app(Passportless::class);
    $service->revokeSessionFromRefreshToken($plainText, 'passportless');
    $service->revokeSessionFromRefreshToken($plainText, 'passportless');

    expect($pair->session->fresh()->revoked_at)->toBeNull();
})->with([
    'malformed' => [fn($pair) => 'malformed'],
    'oversized' => [fn($pair) => str_repeat('x', 121)],
    'unknown' => [fn($pair) => '01J00000000000000000000000|secret'],
    'hash mismatch' => [fn($pair) => $pair->refreshToken->getKey() . '|wrong'],
    'expired' => [function ($pair) {
        $pair->refreshToken->forceFill(['expires_at' => now()->subMinute()])->save();

        return $pair->plainTextRefreshToken();
    }],
    'revoked' => [function ($pair) {
        $pair->refreshToken->forceFill(['revoked_at' => now()])->save();

        return $pair->plainTextRefreshToken();
    }],
    'rotated' => [function ($pair) {
        $pair->refreshToken->forceFill(['rotated_at' => now()])->save();

        return $pair->plainTextRefreshToken();
    }],
]);

it('does not mutate any session rows for wrong-guard credentials', function (string $credential) {
    $user = PassportlessSessionRevocationUser::query()->create();
    $pair = $user->createTokenPair('phone');

    $service = app(Passportless::class);
    $credential === 'access'
        ? $service->revokeCurrentSession($pair->plainTextAccessToken(), 'wrong-guard')
        : $service->revokeSessionFromRefreshToken($pair->plainTextRefreshToken(), 'wrong-guard');

    expect($pair->session->fresh()->revoked_at)->toBeNull()
        ->and($pair->accessToken->accessToken->fresh()->revoked_at)->toBeNull()
        ->and($pair->refreshToken->fresh()->revoked_at)->toBeNull();
})->with(['access', 'refresh']);

it('revokes refresh replacements when refresh wins the session lock', function () {
    $user = PassportlessSessionRevocationUser::query()->create();
    $pair = $user->createTokenPair('phone');
    $service = app(Passportless::class);

    $replacement = $service->refreshToken($pair->plainTextRefreshToken(), guard: 'passportless');

    expect($replacement)->not->toBeNull();

    if ($replacement === null) {
        $this->fail('Refresh token rotation failed.');
    }

    $service->revokeCurrentSession($replacement->plainTextAccessToken(), 'passportless');

    expect($pair->session->fresh()->isRevoked())->toBeTrue()
        ->and($replacement->accessToken->accessToken->fresh()->isRevoked())->toBeTrue()
        ->and($replacement->refreshToken->fresh()->isRevoked())->toBeTrue();
});

it('blocks refresh issuance when session revocation wins the session lock', function () {
    $user = PassportlessSessionRevocationUser::query()->create();
    $pair = $user->createTokenPair('phone');
    $service = app(Passportless::class);

    $service->revokeCurrentSession($pair->plainTextAccessToken(), 'passportless');

    expect($service->refreshToken($pair->plainTextRefreshToken(), guard: 'passportless'))->toBeNull()
        ->and($pair->session->fresh()->isRevoked())->toBeTrue()
        ->and($pair->refreshToken->fresh()->isRevoked())->toBeTrue();
});

it('fails closed when credential session context or owner identity cannot be validated', function (string $credential, string $failure) {
    $user = PassportlessSessionRevocationUser::query()->create();
    $other = PassportlessSessionRevocationUser::query()->create();
    $pair = $user->createTokenPair('phone');
    $storedCredential = $credential === 'access' ? $pair->accessToken->accessToken : $pair->refreshToken;

    match ($failure) {
        'credential context' => $storedCredential->forceFill(['provider' => 'missing'])->save(),
        'session context' => $pair->session->forceFill(['provider' => 'missing'])->save(),
        'session mismatch' => $storedCredential->forceFill(['session_id' => $other->createTokenPair('other')->session->getKey()])->save(),
        'owner mismatch' => $storedCredential->forceFill(['tokenable_id' => $other->getKey()])->save(),
        'deleted owner' => $user->delete(),
        'deleted session' => $pair->session->delete(),
    };

    $service = app(Passportless::class);
    $credential === 'access'
        ? $service->revokeCurrentSession($pair->plainTextAccessToken(), 'passportless')
        : $service->revokeSessionFromRefreshToken($pair->plainTextRefreshToken(), 'passportless');

    expect($storedCredential->fresh()?->revoked_at)->toBeNull();
})->with([
    ['access', 'credential context'],
    ['access', 'session context'],
    ['access', 'session mismatch'],
    ['access', 'owner mismatch'],
    ['access', 'deleted owner'],
    ['access', 'deleted session'],
    ['refresh', 'credential context'],
    ['refresh', 'session context'],
    ['refresh', 'session mismatch'],
    ['refresh', 'owner mismatch'],
    ['refresh', 'deleted owner'],
    ['refresh', 'deleted session'],
]);

class PassportlessSessionRevocationUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_session_revocation_users';
}
