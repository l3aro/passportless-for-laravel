<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use l3aro\Passportless\Concerns\HasPassportless;

class PassportlessDoctorUser extends User
{
    use HasPassportless;
}

beforeEach(function () {
    config()->set('auth.providers.users.model', PassportlessDoctorUser::class);

    Schema::dropIfExists('passportless_refresh_tokens');
    Schema::dropIfExists('passportless_tokens');
    Schema::dropIfExists('passportless_token_sessions');

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

it('reports a healthy Passportless configuration', function () {
    $this->artisan('passportless:doctor')
        ->expectsOutput('Passportless doctor found no configuration errors.')
        ->assertSuccessful();
});

it('reports a provider model that does not use HasPassportless', function () {
    config()->set('auth.providers.users.model', User::class);

    $this->artisan('passportless:doctor')
        ->expectsOutput('FAIL: Passportless provider model ['.User::class.'] for guard [passportless] must use HasPassportless.')
        ->assertFailed();
});

it('reports missing operational migration columns', function () {
    Schema::table('passportless_refresh_tokens', function (Blueprint $table) {
        $table->dropColumn('rotated_at');
    });

    $this->artisan('passportless:doctor')
        ->expectsOutput('FAIL: Passportless table [passportless_refresh_tokens] is missing required column [rotated_at].')
        ->assertFailed();
});

it('reports refresh cookie paths that do not cover SPA refresh routes', function () {
    config()->set('passportless.cookie.refresh.path', '/different');

    Route::passportlessSpaAuth(
        prefix: 'auth',
        guard: 'passportless',
        authenticate: PassportlessDoctorUser::class,
    );

    $this->artisan('passportless:doctor')
        ->expectsOutput('FAIL: Refresh cookie path for guard [passportless] does not cover Passportless route [/auth/refresh].')
        ->assertFailed();
});

it('reports credentialed CORS with a wildcard origin', function () {
    config()->set('passportless.cookie.refresh.path', '/auth');

    Route::passportlessSpaAuth(
        prefix: 'auth',
        guard: 'passportless',
        authenticate: PassportlessDoctorUser::class,
    );
    config()->set('cors.allowed_origins', ['*']);
    config()->set('cors.supports_credentials', true);

    $this->artisan('passportless:doctor')
        ->expectsOutput('FAIL: Credentialed CORS must not use a wildcard allowed origin.')
        ->assertFailed();
});
