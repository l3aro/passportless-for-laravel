<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Models\Tokenable;
use l3aro\Passportless\PassportlessCookieManager;

beforeEach(function () {
    Schema::create('passportless_cookie_auth_users', function (Blueprint $table) {
        $table->id();
    });

    Schema::create('passportless_cookie_auth_staff', function (Blueprint $table) {
        $table->id();
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
        'model' => PassportlessCookieAuthUser::class,
    ]);
    config()->set('auth.providers.staff', [
        'driver' => 'eloquent',
        'model' => PassportlessCookieAuthStaff::class,
    ]);
    config()->set('passportless.guard', 'passportless');
    config()->set('passportless.cookie.secure', false);
    config()->set('passportless.cookie.guards', []);
    Auth::forgetGuards();
});

it('authenticates access cookies through the default package guard', function () {
    $user = PassportlessCookieAuthUser::query()->create();
    $token = $user->createToken('browser', ['orders:read']);
    $cookieName = app(PassportlessCookieManager::class)->accessCookieName();

    request()->cookies->set($cookieName, $token->plainTextToken);

    $resolvedUser = Auth::guard('passportless')->user();

    expect($resolvedUser)->toBeInstanceOf(PassportlessCookieAuthUser::class);

    if (! $resolvedUser instanceof PassportlessCookieAuthUser) {
        $this->fail('Auth token guard did not resolve the cookie tokenable user.');
    }

    expect(method_exists($resolvedUser, 'tokenCan'))->toBeTrue()
        ->and(method_exists($resolvedUser, 'currentAccessToken'))->toBeTrue()
        ->and($resolvedUser->{'tokenCan'}('orders:read'))->toBeTrue()
        ->and($resolvedUser->{'currentAccessToken'}()->last_used_at)->not->toBeNull()
        ->and(request()->headers->get('Authorization'))->toBeNull();
});

it('prefers bearer credentials over access cookies', function () {
    $user = PassportlessCookieAuthUser::query()->create();
    $bearerToken = $user->createToken('api', ['orders:read']);
    $cookieToken = $user->createToken('browser', ['orders:write']);
    $cookieName = app(PassportlessCookieManager::class)->accessCookieName();

    request()->headers->set('Authorization', 'Bearer '.$bearerToken->plainTextToken);
    request()->cookies->set($cookieName, $cookieToken->plainTextToken);

    $resolvedUser = Auth::guard('passportless')->user();

    expect($resolvedUser)->toBeInstanceOf(PassportlessCookieAuthUser::class);

    if (! $resolvedUser instanceof PassportlessCookieAuthUser) {
        $this->fail('Auth token guard did not resolve the bearer tokenable user.');
    }

    expect($resolvedUser->{'tokenCan'}('orders:read'))->toBeTrue()
        ->and($resolvedUser->{'tokenCan'}('orders:write'))->toBeFalse()
        ->and($resolvedUser->{'currentAccessToken'}()->getKey())->toBe($bearerToken->accessToken->getKey())
        ->and(request()->headers->get('Authorization'))->toBe('Bearer '.$bearerToken->plainTextToken);
});

it('does not fall back to cookies when bearer credentials are invalid', function () {
    $user = PassportlessCookieAuthUser::query()->create();
    $cookieToken = $user->createToken('browser', ['orders:read']);
    $cookieName = app(PassportlessCookieManager::class)->accessCookieName();

    request()->headers->set('Authorization', 'Bearer invalid-token');
    request()->cookies->set($cookieName, $cookieToken->plainTextToken);

    expect(Auth::guard('passportless')->user())->toBeNull();
});

it('authenticates guard scoped access cookies for multi guard routes', function () {
    config()->set('passportless.cookie.guards.passportless', [
        'access' => [
            'name' => 'user_access_token',
            'path' => '/api/auth',
        ],
    ]);
    config()->set('passportless.cookie.guards.passportless-admin', [
        'access' => [
            'name' => 'admin_access_token',
            'path' => '/api/auth/admin',
        ],
    ]);

    $user = PassportlessCookieAuthUser::query()->create();
    $staff = PassportlessCookieAuthStaff::query()->create();
    $userToken = $user->createToken('browser', ['orders:read'], guard: 'passportless');
    $adminToken = $staff->createToken('admin-browser', ['staff:read'], guard: 'passportless-admin');

    $adminCookieName = app(PassportlessCookieManager::class)
        ->forGuard('passportless-admin')
        ->accessCookieName();

    request()->cookies->set($adminCookieName, $adminToken->plainTextToken);

    expect(Auth::guard('passportless-admin')->user())->toBeInstanceOf(PassportlessCookieAuthStaff::class);

    Auth::forgetGuards();
    request()->cookies->set($adminCookieName, $userToken->plainTextToken);

    expect(Auth::guard('passportless-admin')->user())->toBeNull();
});

it('rejects wrong guard cookies on multi guard routes', function () {
    config()->set('passportless.cookie.guards.passportless', [
        'access' => [
            'name' => 'user_access_token',
            'path' => '/',
        ],
    ]);
    config()->set('passportless.cookie.guards.passportless-admin', [
        'access' => [
            'name' => 'admin_access_token',
            'path' => '/',
        ],
    ]);

    $user = PassportlessCookieAuthUser::query()->create();
    $userToken = $user->createToken('browser', ['orders:read'], guard: 'passportless');
    $userCookieName = app(PassportlessCookieManager::class)->accessCookieName();

    request()->cookies->set($userCookieName, $userToken->plainTextToken);

    expect(Auth::guard('passportless')->user())->toBeInstanceOf(PassportlessCookieAuthUser::class);

    Auth::forgetGuards();

    expect(Auth::guard('passportless-admin')->user())->toBeNull();
});

it('does not use cookie path as token identity during authentication', function () {
    config()->set('passportless.cookie.guards.passportless', [
        'access' => [
            'name' => 'user_access_token',
            'path' => '/api/auth',
        ],
    ]);
    config()->set('passportless.cookie.guards.passportless-admin', [
        'access' => [
            'name' => 'admin_access_token',
            'path' => '/api/auth/admin',
        ],
    ]);

    $user = PassportlessCookieAuthUser::query()->create();
    $userToken = $user->createToken('browser', ['orders:read'], guard: 'passportless');
    $adminCookieName = app(PassportlessCookieManager::class)
        ->forGuard('passportless-admin')
        ->accessCookieName();

    request()->cookies->set($adminCookieName, $userToken->plainTextToken);
    request()->server->set('REQUEST_URI', '/api/auth/admin/me');

    expect(Auth::guard('passportless-admin')->user())->toBeNull();

    Auth::forgetGuards();
    request()->cookies->set(
        app(PassportlessCookieManager::class)->accessCookieName(),
        $userToken->plainTextToken,
    );
    request()->server->set('REQUEST_URI', '/api/auth/admin/me');

    expect(Auth::guard('passportless')->user())->toBeInstanceOf(PassportlessCookieAuthUser::class);
});

it('fails closed when cookie profile is not configured for the route guard', function () {
    config()->set('passportless.cookie.guards.passportless', [
        'access' => [
            'name' => 'user_access_token',
            'path' => '/',
        ],
    ]);

    $user = PassportlessCookieAuthUser::query()->create();
    $token = $user->createToken('browser', ['orders:read'], guard: 'passportless');

    request()->cookies->set('user_access_token', $token->plainTextToken);

    expect(Auth::guard('passportless-admin')->user())->toBeNull();
});

class PassportlessCookieAuthUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_cookie_auth_users';
}

class PassportlessCookieAuthStaff extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_cookie_auth_staff';
}
