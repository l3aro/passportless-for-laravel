<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User as AuthenticatableUser;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Concerns\HasPassportless;
use l3aro\Passportless\Models\PersonalAccessToken;
use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Passportless;
use l3aro\Passportless\PassportlessCookieManager;
use l3aro\Passportless\Testing\InteractsWithPassportless;

uses(InteractsWithPassportless::class);

beforeEach(function () {
    config()->set('auth.guards.passportless', [
        'driver' => 'passportless',
        'provider' => 'users',
    ]);
    config()->set('auth.guards.passportless-admin', [
        'driver' => 'passportless',
        'provider' => 'staff',
    ]);
    config()->set('auth.providers.users', [
        'driver' => 'eloquent',
        'model' => PassportlessTestingUser::class,
    ]);
    config()->set('auth.providers.staff', [
        'driver' => 'eloquent',
        'model' => PassportlessTestingStaff::class,
    ]);
    config()->set('passportless.guard', 'passportless');
    config()->set('passportless.cookie.secure', false);
    config()->set('passportless.cookie.guards', [
        'passportless-admin' => [
            'access' => ['name' => 'admin_access_token'],
            'refresh' => ['name' => 'admin_refresh_token', 'path' => '/admin/auth'],
            'csrf' => ['name' => 'admin_csrf_token', 'http_only' => false],
        ],
    ]);
    Auth::forgetGuards();

    Schema::create('passportless_testing_users', function (Blueprint $table) {
        $table->id();
    });
    Schema::create('passportless_testing_staff', function (Blueprint $table) {
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

    Route::middleware('auth:passportless')->get('/passportless-testing/me', fn() => response()->noContent());
    Route::middleware(['passportless.csrf', 'auth:passportless'])->post('/passportless-testing/me', fn() => response()->noContent());
    Route::get('/passportless-testing/cookies', fn() => response()->noContent()
        ->withCookie(app(PassportlessCookieManager::class)->createAccessCookie('access'))
        ->withCookie(app(PassportlessCookieManager::class)->createRefreshCookie('refresh'))
        ->withCookie(app(PassportlessCookieManager::class)->createCsrfCookie('csrf')));
    Route::get('/passportless-testing/forget-cookies', fn() => response()->noContent()
        ->withCookie(app(PassportlessCookieManager::class)->forgetAccessCookie())
        ->withCookie(app(PassportlessCookieManager::class)->forgetRefreshCookie())
        ->withCookie(app(PassportlessCookieManager::class)->forgetCsrfCookie()));
});

it('impersonates through Laravel without issuing a Passportless token', function () {
    $user = PassportlessTestingUser::query()->create();

    expect($this->actingAsPassportless($user))->toBe($this)
        ->and(PersonalAccessToken::query()->count())->toBe(0);
});

it('rejects impersonation through a guard with a different provider model', function () {
    $user = PassportlessTestingUser::query()->create();

    expect(fn() => $this->actingAsPassportless($user, 'passportless-admin'))
        ->toThrow(InvalidArgumentException::class);
});

it('sets guard-scoped cookie credentials without exposing the token pair', function () {
    $user = PassportlessTestingUser::query()->create();

    expect($this->withPassportlessCookieSession($user))->toBe($this)
        ->and(PersonalAccessToken::query()->count())->toBe(1)
        ->and(RefreshToken::query()->count())->toBe(1)
        ->and($this->get('/passportless-testing/me')->status())->toBe(204)
        ->and($this->post('/passportless-testing/me')->status())->toBe(204);
});

it('preserves guard and provider validation for cookie session setup', function () {
    $user = PassportlessTestingUser::query()->create();

    expect(fn() => $this->withPassportlessCookieSession($user, 'passportless-admin'))
        ->toThrow(InvalidArgumentException::class)
        ->and(PersonalAccessToken::query()->count())->toBe(0)
        ->and(RefreshToken::query()->count())->toBe(0);
});

it('asserts queued and forgotten cookie metadata through the configured manager', function () {
    expect($this->assertPassportlessAuthCookiesQueued($this->get('/passportless-testing/cookies')))->toBe($this)
        ->and($this->assertPassportlessAuthCookiesForgotten($this->get('/passportless-testing/forget-cookies')))->toBe($this);
});

it('keeps rotation and family reuse detection behavior unchanged', function () {
    $user = PassportlessTestingUser::query()->create();
    $pair = $user->createTokenPair('browser');

    $rotated = app(Passportless::class)->refreshToken($pair->plainTextRefreshToken());

    expect($rotated)->not->toBeNull()
        ->and($pair->refreshToken->fresh()->isRotated())->toBeTrue();

    app(Passportless::class)->refreshToken($pair->plainTextRefreshToken());

    expect(RefreshToken::query()->where('family_id', $pair->refreshToken->family_id)->whereNull('revoked_at')->count())->toBe(0);
});

class PassportlessTestingUser extends AuthenticatableUser
{
    use HasPassportless;

    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_testing_users';
}

class PassportlessTestingStaff extends AuthenticatableUser
{
    use HasPassportless;

    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_testing_staff';
}
