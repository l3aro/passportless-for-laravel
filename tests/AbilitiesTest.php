<?php

use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use l3aro\AuthToken\Concerns\HasAuthTokens;
use l3aro\AuthToken\Http\Middleware\CheckAbilities;
use l3aro\AuthToken\Http\Middleware\CheckForAnyAbility;
use l3aro\AuthToken\Models\PersonalAccessToken;
use l3aro\AuthToken\Models\Tokenable;

it('allows exact token abilities', function () {
    $token = new PersonalAccessToken(['abilities' => ['orders:read']]);

    expect($token->can('orders:read'))->toBeTrue()
        ->and($token->cannot('orders:write'))->toBeTrue();
});

it('allows wildcard token abilities', function () {
    $token = new PersonalAccessToken(['abilities' => ['*']]);

    expect($token->can('orders:delete'))->toBeTrue();
});

it('can disable wildcard token abilities', function () {
    config()->set('auth-token-for-laravel.abilities.wildcard_enabled', false);

    $token = new PersonalAccessToken(['abilities' => ['*']]);

    expect($token->can('orders:delete'))->toBeFalse()
        ->and($token->can('*'))->toBeTrue();
});

it('checks abilities through the tokenable model trait', function () {
    $token = new PersonalAccessToken(['abilities' => ['orders:read']]);

    $user = new class extends Model
    {
        use HasAuthTokens;
    };

    $user->withAccessToken($token);

    expect($user->tokenCan('orders:read'))->toBeTrue()
        ->and($user->tokenCannot('orders:write'))->toBeTrue();
});

it('authenticates bearer tokens through the package guard', function () {
    Schema::create('auth_token_test_users', function (Blueprint $table) {
        $table->id();
    });

    Schema::create('auth_tokens', function (Blueprint $table) {
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

    $user = AuthTokenTestUser::query()->create();
    $newToken = $user->createToken('cli', ['orders:read']);

    request()->headers->set('Authorization', 'Bearer '.$newToken->plainTextToken);

    $resolvedUser = Auth::guard('auth-token')->user();

    expect($resolvedUser)->toBeInstanceOf(AuthTokenTestUser::class);

    if (! $resolvedUser instanceof AuthTokenTestUser) {
        $this->fail('Auth token guard did not resolve the tokenable user.');
    }

    expect(method_exists($resolvedUser, 'tokenCan'))->toBeTrue()
        ->and(method_exists($resolvedUser, 'currentAccessToken'))->toBeTrue()
        ->and($resolvedUser->{'tokenCan'}('orders:read'))->toBeTrue()
        ->and($resolvedUser->{'currentAccessToken'}()->last_used_at)->not->toBeNull();
});

it('throttles last used updates on bearer token authentication', function () {
    config()->set('auth-token-for-laravel.access_token.last_used_update_interval', 60);

    Schema::create('auth_token_throttle_test_users', function (Blueprint $table) {
        $table->id();
    });

    Schema::create('auth_tokens', function (Blueprint $table) {
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

    $user = AuthTokenThrottleTestUser::query()->create();
    $newToken = $user->createToken('cli', ['orders:read']);

    request()->headers->set('Authorization', 'Bearer '.$newToken->plainTextToken);

    Auth::guard('auth-token')->user();

    $firstLastUsedAt = $newToken->accessToken->fresh()->last_used_at;

    Auth::forgetGuards();
    Auth::guard('auth-token')->user();

    expect($newToken->accessToken->fresh()->last_used_at?->equalTo($firstLastUsedAt))->toBeTrue();
});

it('atomically throttles concurrent last used updates', function () {
    config()->set('auth-token-for-laravel.access_token.last_used_update_interval', 60);

    Schema::create('auth_tokens', function (Blueprint $table) {
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

    $token = PersonalAccessToken::query()->create([
        'tokenable_type' => AuthTokenTestUser::class,
        'tokenable_id' => 1,
        'name' => 'cli',
        'token' => hash('sha256', 'token'),
    ]);
    $firstRequestToken = $token->fresh();
    $secondRequestToken = $token->fresh();
    $usedAt = now();

    expect($firstRequestToken?->recordUsage($usedAt))->toBeTrue()
        ->and($secondRequestToken?->recordUsage($usedAt))->toBeFalse();
});

it('requires every ability for abilities middleware', function () {
    $request = Request::create('/');
    $request->setUserResolver(fn () => new class
    {
        public function tokenCan(string $ability): bool
        {
            return in_array($ability, ['orders:read', 'orders:write'], true);
        }
    });

    $response = (new CheckAbilities)->handle($request, fn () => response('ok'), 'orders:read', 'orders:write');

    expect($response->getContent())->toBe('ok');
});

it('requires any ability for ability middleware', function () {
    $request = Request::create('/');
    $request->setUserResolver(fn () => new class
    {
        public function tokenCan(string $ability): bool
        {
            return $ability === 'orders:read';
        }
    });

    $response = (new CheckForAnyAbility)->handle($request, fn () => response('ok'), 'orders:write', 'orders:read');

    expect($response->getContent())->toBe('ok');
});

it('rejects ability middleware without an authenticated token user', function () {
    (new CheckAbilities)->handle(Request::create('/'), fn () => response('ok'), 'orders:read');
})->throws(AuthenticationException::class);

it('rejects ability middleware without required abilities', function () {
    $request = Request::create('/');
    $request->setUserResolver(fn () => new class
    {
        public function tokenCan(string $ability): bool
        {
            return true;
        }
    });

    (new CheckAbilities)->handle($request, fn () => response('ok'));
})->throws(AuthenticationException::class);

it('rejects any ability middleware without required abilities', function () {
    $request = Request::create('/');
    $request->setUserResolver(fn () => new class
    {
        public function tokenCan(string $ability): bool
        {
            return true;
        }
    });

    (new CheckForAnyAbility)->handle($request, fn () => response('ok'));
})->throws(AuthenticationException::class);

class AuthTokenTestUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'auth_token_test_users';
}

class AuthTokenThrottleTestUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'auth_token_throttle_test_users';
}
