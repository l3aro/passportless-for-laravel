<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Models\Tokenable;
use l3aro\Passportless\Passportless;
use l3aro\Passportless\Support\AuthBindingResolver;

beforeEach(function () {
    Schema::create('passportless_binding_users', function (Blueprint $table) {
        $table->id();
    });

    Schema::create('passportless_binding_staff', function (Blueprint $table) {
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

    configurePassportlessGuards();
});

it('issues explicit and default guard tokens with provider snapshots', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);

    $defaultToken = $user->createToken('client-default');
    $staffPair = $staff->createTokenPair('staff-browser', ['staff:read'], guard: 'passportless-admin');

    expect($defaultToken->accessToken->guard)->toBe('passportless-client')
        ->and($defaultToken->accessToken->provider)->toBe('users')
        ->and($staffPair->session->guard)->toBe('passportless-admin')
        ->and($staffPair->refreshToken->guard)->toBe('passportless-admin')
        ->and($staffPair->accessToken->accessToken->guard)->toBe('passportless-admin')
        ->and($staffPair->accessToken->accessToken->provider)->toBe('staff');
});

it('denies access tokens through the wrong passportless guard', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);
    $clientToken = $user->createToken('client', guard: 'passportless-client');
    $adminToken = $staff->createToken('admin', guard: 'passportless-admin');

    request()->headers->set('Authorization', 'Bearer '.$clientToken->plainTextToken);
    expect(Auth::guard('passportless-client')->user())->toBeInstanceOf(PassportlessBindingUser::class);

    Auth::forgetGuards();
    request()->headers->set('Authorization', 'Bearer '.$clientToken->plainTextToken);
    expect(Auth::guard('passportless-admin')->user())->toBeNull();

    Auth::forgetGuards();
    request()->headers->set('Authorization', 'Bearer '.$adminToken->plainTextToken);
    expect(Auth::guard('passportless-client')->user())->toBeNull();
});

it('prevents tokenable models from minting tokens for another provider guard', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);

    expect(fn () => $user->createToken('admin', guard: 'passportless-admin'))->toThrow(InvalidArgumentException::class);
});

it('rejects tampered tokens whose stored guard does not match the morph owner model', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);
    $adminToken = $staff->createToken('admin', guard: 'passportless-admin');
    $adminPair = $staff->createTokenPair('admin-session', ['staff:read'], 'passportless-admin');

    $adminToken->accessToken->forceFill([
        'tokenable_type' => PassportlessBindingUser::class,
        'tokenable_id' => $user->getKey(),
    ])->save();
    $adminPair->refreshToken->forceFill([
        'tokenable_type' => PassportlessBindingUser::class,
        'tokenable_id' => $user->getKey(),
    ])->save();

    request()->headers->set('Authorization', 'Bearer '.$adminToken->plainTextToken);

    expect(Auth::guard('passportless-admin')->user())->toBeNull()
        ->and(app(Passportless::class)->refreshToken($adminPair->plainTextRefreshToken()))->toBeNull();
});

it('preserves guard through refresh rotation with colliding owner IDs isolated', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);
    $user->createTokenPair('client', ['profile:read'], 'passportless-client');
    $staffPair = $staff->createTokenPair('staff', ['staff:read'], 'passportless-admin');

    $rotated = app(Passportless::class)->refreshToken($staffPair->plainTextRefreshToken(), ['staff:read']);

    expect($rotated)->not->toBeNull()
        ->and($rotated?->session->guard)->toBe('passportless-admin')
        ->and($rotated?->refreshToken->guard)->toBe('passportless-admin')
        ->and($rotated?->accessToken->accessToken->tokenable_type)->toBe(PassportlessBindingStaff::class)
        ->and($rotated?->accessToken->accessToken->tokenable_id)->toBe(1);
});

it('fails closed when refresh expected guard differs from stored guard', function () {
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);
    $staffPair = $staff->createTokenPair('staff', ['staff:read'], 'passportless-admin');

    $wrongGuardRefresh = app(Passportless::class)->refreshToken(
        $staffPair->plainTextRefreshToken(),
        ['staff:read'],
        'passportless-client',
    );

    expect($wrongGuardRefresh)->toBeNull()
        ->and($staffPair->refreshToken->fresh()->isRotated())->toBeFalse();

    $rightGuardRefresh = app(Passportless::class)->refreshToken(
        $staffPair->plainTextRefreshToken(),
        ['staff:read'],
        'passportless-admin',
    );

    expect($rightGuardRefresh)->not->toBeNull()
        ->and($rightGuardRefresh?->refreshToken->guard)->toBe('passportless-admin');
});

it('does not use route cookie path as token identity during refresh', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $userPair = $user->createTokenPair('client', ['profile:read'], 'passportless-client');

    config()->set('passportless.cookie.guards.passportless-admin.refresh.path', '/api/auth/admin/refresh');

    $adminRouteRefresh = app(Passportless::class)->refreshToken(
        $userPair->plainTextRefreshToken(),
        ['profile:read'],
        'passportless-admin',
    );

    expect($adminRouteRefresh)->toBeNull()
        ->and($userPair->refreshToken->fresh()->isRotated())->toBeFalse();

    $userRouteRefresh = app(Passportless::class)->refreshToken(
        $userPair->plainTextRefreshToken(),
        ['profile:read'],
        'passportless-client',
    );

    expect($userRouteRefresh)->not->toBeNull()
        ->and($userRouteRefresh?->session->guard)->toBe('passportless-client');
});

it('scopes refresh family reuse revocation by guard and provider', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);
    $clientPair = $user->createTokenPair('client', ['profile:read'], 'passportless-client');
    $adminPair = $staff->createTokenPair('admin', ['staff:read'], 'passportless-admin');

    $adminPair->refreshToken->forceFill(['family_id' => $clientPair->refreshToken->family_id])->save();
    app(Passportless::class)->refreshToken($clientPair->plainTextRefreshToken(), ['profile:read']);

    expect(app(Passportless::class)->refreshToken($clientPair->plainTextRefreshToken(), ['profile:read']))->toBeNull()
        ->and($adminPair->refreshToken->fresh()->revoked_at)->toBeNull();
});

it('derives refresh abilities only from access tokens in the same guard context', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);
    $clientPair = $user->createTokenPair('client', ['profile:write'], 'passportless-client');
    $adminPair = $staff->createTokenPair('admin', ['staff:read'], 'passportless-admin');

    $clientPair->accessToken->accessToken->forceFill(['session_id' => $adminPair->session->getKey()])->save();

    $rotated = app(Passportless::class)->refreshToken($adminPair->plainTextRefreshToken());

    expect($rotated)->not->toBeNull()
        ->and($rotated?->accessToken->accessToken->can('staff:read'))->toBeTrue()
        ->and($rotated?->accessToken->accessToken->can('profile:write'))->toBeFalse();
});

it('keeps model token session and token relations isolated for colliding owner IDs', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $staff = PassportlessBindingStaff::query()->create(['id' => 1]);
    $userPair = $user->createTokenPair('client', ['profile:read'], 'passportless-client');
    $staffPair = $staff->createTokenPair('admin', ['staff:read'], 'passportless-admin');

    $userPair->session->forceFill(['revoked_at' => now()])->save();

    expect($user->tokenSessions()->pluck('id')->all())->toBe([$userPair->session->getKey()])
        ->and($staff->tokenSessions()->pluck('id')->all())->toBe([$staffPair->session->getKey()])
        ->and($staffPair->session->fresh()->revoked_at)->toBeNull()
        ->and($user->tokens()->pluck('id')->all())->toBe([$userPair->accessToken->accessToken->getKey()])
        ->and($staff->tokens()->pluck('id')->all())->toBe([$staffPair->accessToken->accessToken->getKey()]);
});

it('fails closed for unknown guards and stored context mismatches', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);

    expect(fn () => $user->createToken('bad', guard: 'missing'))->toThrow(InvalidArgumentException::class);

    $token = $user->createToken('client', guard: 'passportless-client');
    $token->accessToken->forceFill(['guard' => 'missing'])->save();

    expect(app(Passportless::class)->findToken($token->plainTextToken))->toBeNull();

    $otherToken = $user->createToken('client-2', guard: 'passportless-client');
    $otherToken->accessToken->forceFill(['provider' => 'staff'])->save();

    expect(app(Passportless::class)->findToken($otherToken->plainTextToken))->toBeNull();
});

it('validates malformed guard configuration', function (Closure $configure) {
    $configure();

    expect(fn () => app(AuthBindingResolver::class)->validateConfiguration())->toThrow(InvalidArgumentException::class);
})->with([
    'empty guard' => [fn () => config()->set('passportless.guard', '')],
    'unknown guard' => [fn () => config()->set('passportless.guard', 'missing')],
    'wrong driver' => [function () {
        config()->set('auth.guards.passportless-client.driver', 'session');
    }],
    'empty provider override' => [fn () => config()->set('passportless.provider', '')],
    'unknown provider override' => [fn () => config()->set('passportless.provider', 'missing')],
]);

it('keeps default config compatible and fails closed for null-provider rows', function () {
    config()->set('passportless.guard', 'passportless');
    config()->set('passportless.provider', null);
    config()->set('auth.guards.passportless', [
        'driver' => 'passportless',
        'provider' => 'users',
    ]);

    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $token = $user->createToken('legacy');

    expect($token->accessToken->guard)->toBe('passportless')
        ->and($token->accessToken->provider)->toBe('users')
        ->and(app(Passportless::class)->findToken($token->plainTextToken))->not->toBeNull();

    $token->accessToken->forceFill(['provider' => null])->save();

    expect(app(Passportless::class)->findToken($token->plainTextToken))->toBeNull();
});

it('rejects unmatched stored guard rows', function () {
    $user = PassportlessBindingUser::query()->create(['id' => 1]);
    $token = $user->createToken('client', guard: 'passportless-client');

    expect(app(Passportless::class)->findToken($token->plainTextToken))->not->toBeNull();

    $token->accessToken->forceFill(['guard' => 'passportless-missing'])->save();

    expect(app(Passportless::class)->findToken($token->plainTextToken))->toBeNull();
});

function configurePassportlessGuards(): void
{
    config()->set('auth.guards.passportless-client', [
        'driver' => 'passportless',
        'provider' => 'users',
    ]);
    config()->set('auth.guards.passportless-admin', [
        'driver' => 'passportless',
        'provider' => 'staff',
    ]);
    config()->set('auth.providers.users', [
        'driver' => 'eloquent',
        'model' => PassportlessBindingUser::class,
    ]);
    config()->set('auth.providers.staff', [
        'driver' => 'eloquent',
        'model' => PassportlessBindingStaff::class,
    ]);
    config()->set('passportless.guard', 'passportless-client');
    config()->set('passportless.provider', null);
    Auth::forgetGuards();
}

class PassportlessBindingUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_binding_users';
}

class PassportlessBindingStaff extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_binding_staff';
}
