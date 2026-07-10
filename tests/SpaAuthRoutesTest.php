<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Http\Middleware\ValidateSameOrigin;
use l3aro\Passportless\Models\PersonalAccessToken;
use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Models\Tokenable;
use l3aro\Passportless\Models\TokenSession;
use l3aro\Passportless\PassportlessCookieManager;
use Symfony\Component\HttpFoundation\Cookie;

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
        'model' => PassportlessSpaUser::class,
    ]);
    config()->set('auth.providers.staff', [
        'driver' => 'eloquent',
        'model' => PassportlessSpaStaff::class,
    ]);
    config()->set('passportless.guard', 'passportless');
    config()->set('passportless.cookie.secure', false);
    config()->set('passportless.cookie.guards', [
        'passportless' => [
            'refresh' => [
                'path' => '/auth',
            ],
        ],
        'passportless-admin' => [
            'access' => [
                'name' => 'admin_access_token',
                'path' => '/',
            ],
            'refresh' => [
                'name' => 'admin_refresh_token',
                'path' => '/auth/admin/refresh',
            ],
            'csrf' => [
                'name' => 'admin_csrf_token',
                'path' => '/',
                'http_only' => false,
            ],
        ],
    ]);

    Schema::create('passportless_spa_users', function (Blueprint $table) {
        $table->id();
        $table->string('email')->nullable();
    });

    Schema::create('passportless_spa_staff', function (Blueprint $table) {
        $table->id();
        $table->string('email')->nullable();
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

    Route::passportlessSpaAuth(
        prefix: 'auth',
        guard: 'passportless',
        authenticate: PassportlessSpaUserAuthenticator::class,
        abilities: ['demo:read'],
    );

    Route::passportlessSpaAuth(
        prefix: 'auth/admin',
        guard: 'passportless-admin',
        authenticate: PassportlessSpaStaffAuthenticator::class,
        abilities: ['admin:read'],
    );
});

it('logs in refreshes and logs out through the spa route macro', function () {
    $login = $this->postJson('/auth/login', ['email' => 'user@example.test'])
        ->assertOk()
        ->assertJsonPath('token_type', 'Cookie')
        ->assertJsonStructure([
            'token_type',
            'access_expires_at',
            'refresh_expires_at',
            'csrf_token',
            'session' => ['id', 'name'],
        ])
        ->assertJsonMissingPath('access_token')
        ->assertJsonMissingPath('refresh_token');

    $cookies = app(PassportlessCookieManager::class);
    $access = cookieFromResponse($login, $cookies->accessCookieName());
    $refresh = cookieFromResponse($login, $cookies->refreshCookieName());
    $csrf = cookieFromResponse($login, $cookies->csrfCookieName());

    expect($access)->not->toBeNull()
        ->and($refresh)->not->toBeNull()
        ->and($csrf)->not->toBeNull()
        ->and($access?->isHttpOnly())->toBeTrue()
        ->and($refresh?->isHttpOnly())->toBeTrue()
        ->and($csrf?->isHttpOnly())->toBeFalse();

    $refreshResponse = $this->withCredentials()
        ->withUnencryptedCookie($cookies->refreshCookieName(), plainCookieValue($refresh))
        ->withUnencryptedCookie($cookies->csrfCookieName(), plainCookieValue($csrf))
        ->withHeader('X-CSRF-TOKEN', $login->json('csrf_token'))
        ->postJson('/auth/refresh')
        ->assertOk()
        ->assertJsonMissingPath('access_token')
        ->assertJsonMissingPath('refresh_token');

    $rotatedAccess = cookieFromResponse($refreshResponse, $cookies->accessCookieName());
    $rotatedRefresh = cookieFromResponse($refreshResponse, $cookies->refreshCookieName());
    $rotatedCsrf = cookieFromResponse($refreshResponse, $cookies->csrfCookieName());

    expect(plainCookieValue($rotatedRefresh))->not->toBe(plainCookieValue($refresh));

    $this->withCredentials()
        ->withUnencryptedCookie($cookies->accessCookieName(), plainCookieValue($rotatedAccess))
        ->withUnencryptedCookie($cookies->csrfCookieName(), plainCookieValue($rotatedCsrf))
        ->withHeader('X-CSRF-TOKEN', $refreshResponse->json('csrf_token'))
        ->postJson('/auth/logout')
        ->assertOk()
        ->assertJsonPath('message', 'Logged out.');

    expect(TokenSession::query()->whereNotNull('revoked_at')->count())->toBe(1)
        ->and(PersonalAccessToken::query()->whereNotNull('revoked_at')->count())->toBeGreaterThan(0)
        ->and(RefreshToken::query()->whereNotNull('revoked_at')->count())->toBeGreaterThan(0);
});

it('rejects invalid credentials with generic login failure', function () {
    $this->postJson('/auth/login', ['email' => 'wrong@example.test'])
        ->assertUnauthorized()
        ->assertJsonPath('message', 'Invalid credentials.');
});

it('rejects cross-origin login requests', function () {
    $this->withHeader('Origin', 'https://untrusted.example.test')
        ->postJson('/auth/login', ['email' => 'user@example.test'])
        ->assertForbidden();
});

it('accepts same-origin login requests with normalized origin casing and port', function () {
    $request = Request::create(
        'https://example.test/login',
        'POST',
        server: ['HTTP_ORIGIN' => 'https://EXAMPLE.TEST:443'],
    );

    $response = app(ValidateSameOrigin::class)->handle(
        $request,
        fn () => response()->noContent(),
    );

    expect($response->getStatusCode())->toBe(204);
});

it('rejects closure authentication handlers because routes must be cacheable', function () {
    expect(fn () => Route::passportlessSpaAuth(
        prefix: 'closure-auth',
        guard: 'passportless',
        authenticate: fn () => null,
    ))->toThrow(TypeError::class);
});

it('rejects missing refresh cookies and csrf mismatches', function () {
    $this->postJson('/auth/refresh')
        ->assertStatus(419);

    $login = $this->postJson('/auth/login', ['email' => 'user@example.test'])->assertOk();
    $cookies = app(PassportlessCookieManager::class);
    $refresh = cookieFromResponse($login, $cookies->refreshCookieName());
    $csrf = cookieFromResponse($login, $cookies->csrfCookieName());

    $this->withCredentials()
        ->withUnencryptedCookie($cookies->refreshCookieName(), plainCookieValue($refresh))
        ->withUnencryptedCookie($cookies->csrfCookieName(), plainCookieValue($csrf))
        ->withHeader('X-CSRF-TOKEN', 'wrong')
        ->postJson('/auth/refresh')
        ->assertStatus(419);

    $this->withCredentials()
        ->withUnencryptedCookie($cookies->refreshCookieName(), '')
        ->withUnencryptedCookie($cookies->csrfCookieName(), plainCookieValue($csrf))
        ->withHeader('X-CSRF-TOKEN', $login->json('csrf_token'))
        ->postJson('/auth/refresh')
        ->assertUnauthorized()
        ->assertJsonPath('message', 'Invalid token.');
});

it('isolates multi-guard refresh routes by expected guard', function () {
    $userLogin = $this->postJson('/auth/login', ['email' => 'user@example.test'])->assertOk();
    $adminLogin = $this->postJson('/auth/admin/login', ['email' => 'admin@example.test'])->assertOk();

    $userCookies = app(PassportlessCookieManager::class)->forGuard('passportless');
    $adminCookies = app(PassportlessCookieManager::class)->forGuard('passportless-admin');

    $userRefresh = cookieFromResponse($userLogin, $userCookies->refreshCookieName());
    $userCsrf = cookieFromResponse($userLogin, $userCookies->csrfCookieName());
    $adminRefresh = cookieFromResponse($adminLogin, $adminCookies->refreshCookieName());
    $adminCsrf = cookieFromResponse($adminLogin, $adminCookies->csrfCookieName());

    expect($userCookies->refreshCookieName())->not->toBe($adminCookies->refreshCookieName());

    $this->withCredentials()
        ->withUnencryptedCookie($adminCookies->refreshCookieName(), plainCookieValue($userRefresh))
        ->withUnencryptedCookie($adminCookies->csrfCookieName(), plainCookieValue($adminCsrf))
        ->withHeader('X-CSRF-TOKEN', $adminLogin->json('csrf_token'))
        ->postJson('/auth/admin/refresh')
        ->assertUnauthorized()
        ->assertJsonPath('message', 'Invalid token.');

    $this->withCredentials()
        ->withUnencryptedCookie($userCookies->refreshCookieName(), plainCookieValue($adminRefresh))
        ->withUnencryptedCookie($userCookies->csrfCookieName(), plainCookieValue($userCsrf))
        ->withHeader('X-CSRF-TOKEN', $userLogin->json('csrf_token'))
        ->postJson('/auth/refresh')
        ->assertUnauthorized()
        ->assertJsonPath('message', 'Invalid token.');

    $this->withCredentials()
        ->withUnencryptedCookie($adminCookies->refreshCookieName(), plainCookieValue($adminRefresh))
        ->withUnencryptedCookie($adminCookies->csrfCookieName(), plainCookieValue($adminCsrf))
        ->withHeader('X-CSRF-TOKEN', $adminLogin->json('csrf_token'))
        ->postJson('/auth/admin/refresh')
        ->assertOk();
});

it('revokes the session with the refresh cookie when no access cookie is present', function () {
    $login = $this->postJson('/auth/login', ['email' => 'user@example.test'])->assertOk();
    $cookies = app(PassportlessCookieManager::class);
    $refresh = cookieFromResponse($login, $cookies->refreshCookieName());
    $csrf = cookieFromResponse($login, $cookies->csrfCookieName());

    $this->withCredentials()
        ->withUnencryptedCookie($cookies->refreshCookieName(), plainCookieValue($refresh))
        ->withUnencryptedCookie($cookies->csrfCookieName(), plainCookieValue($csrf))
        ->withHeader('X-CSRF-TOKEN', $login->json('csrf_token'))
        ->postJson('/auth/logout')
        ->assertOk()
        ->assertJsonPath('message', 'Logged out.');

    expect(TokenSession::query()->whereNotNull('revoked_at')->count())->toBe(1)
        ->and(RefreshToken::query()->whereNotNull('revoked_at')->count())->toBe(1);
});

function cookieFromResponse($response, string $name): ?Cookie
{
    foreach ($response->headers->getCookies() as $cookie) {
        if ($cookie->getName() === $name) {
            return $cookie;
        }
    }

    return null;
}

function plainCookieValue(?Cookie $cookie): string
{
    return (string) $cookie?->getValue();
}

class PassportlessSpaUser extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_spa_users';
}

class PassportlessSpaStaff extends Tokenable
{
    public $timestamps = false;

    protected $guarded = [];

    protected $table = 'passportless_spa_staff';
}

class PassportlessSpaUserAuthenticator
{
    public function __invoke(Request $request): ?PassportlessSpaUser
    {
        $email = $request->input('email');

        if ($email !== 'user@example.test') {
            return null;
        }

        return PassportlessSpaUser::query()->firstOrCreate(['email' => $email]);
    }
}

class PassportlessSpaStaffAuthenticator
{
    public function __invoke(Request $request): ?PassportlessSpaStaff
    {
        $email = $request->input('email');

        if ($email !== 'admin@example.test') {
            return null;
        }

        return PassportlessSpaStaff::query()->firstOrCreate(['email' => $email]);
    }
}
