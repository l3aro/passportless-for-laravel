<?php

use l3aro\Passportless\PassportlessCookieManager;

it('is resolved as a singleton', function () {
    expect(app(PassportlessCookieManager::class))->toBe(app(PassportlessCookieManager::class));
});

it('creates default access refresh and csrf cookies', function () {
    config()->set('passportless.cookie.secure', false);

    $cookies = app(PassportlessCookieManager::class);
    $access = $cookies->createAccessCookie('access-token');
    $refresh = $cookies->createRefreshCookie('refresh-token');
    $csrf = $cookies->createCsrfCookie('csrf-token');

    expect($cookies->accessCookieName())->toBe('passportless_access_token')
        ->and($cookies->refreshCookieName())->toBe('passportless_refresh_token')
        ->and($cookies->csrfCookieName())->toBe('passportless_csrf_token')
        ->and($access->getValue())->toBe('access-token')
        ->and($access->getPath())->toBe('/')
        ->and($access->isSecure())->toBeFalse()
        ->and($access->isHttpOnly())->toBeTrue()
        ->and($access->getSameSite())->toBe('lax')
        ->and($refresh->getValue())->toBe('refresh-token')
        ->and($refresh->getPath())->toBe('/api/auth/refresh')
        ->and($refresh->isHttpOnly())->toBeTrue()
        ->and($csrf->getValue())->toBe('csrf-token')
        ->and($csrf->getPath())->toBe('/')
        ->and($csrf->isHttpOnly())->toBeFalse();
});

it('uses token expiration defaults for access refresh and csrf lifetimes', function () {
    config()->set('passportless.access_token.expiration', 7);
    config()->set('passportless.refresh_token.expiration', 11);

    $cookies = app(PassportlessCookieManager::class);
    $now = now();

    expect($cookies->createAccessCookie('access')->getExpiresTime())->toBeGreaterThanOrEqual($now->copy()->addMinutes(7)->subSecond()->getTimestamp())
        ->and($cookies->createAccessCookie('access')->getExpiresTime())->toBeLessThanOrEqual($now->copy()->addMinutes(7)->addSecond()->getTimestamp())
        ->and($cookies->createRefreshCookie('refresh')->getExpiresTime())->toBeGreaterThanOrEqual($now->copy()->addMinutes(11)->subSecond()->getTimestamp())
        ->and($cookies->createRefreshCookie('refresh')->getExpiresTime())->toBeLessThanOrEqual($now->copy()->addMinutes(11)->addSecond()->getTimestamp())
        ->and($cookies->createCsrfCookie('csrf')->getExpiresTime())->toBeGreaterThanOrEqual($now->copy()->addMinutes(11)->subSecond()->getTimestamp())
        ->and($cookies->createCsrfCookie('csrf')->getExpiresTime())->toBeLessThanOrEqual($now->copy()->addMinutes(11)->addSecond()->getTimestamp());
});

it('honors cookie overrides', function () {
    config()->set('passportless.cookie.domain', '.example.test');
    config()->set('passportless.cookie.secure', true);
    config()->set('passportless.cookie.same_site', 'none');
    config()->set('passportless.cookie.access.name', 'access_override');
    config()->set('passportless.cookie.access.path', '/api');
    config()->set('passportless.cookie.access.http_only', true);
    config()->set('passportless.cookie.refresh.name', 'refresh_override');
    config()->set('passportless.cookie.refresh.path', '/refresh');
    config()->set('passportless.cookie.refresh.http_only', true);
    config()->set('passportless.cookie.csrf.name', 'csrf_override');
    config()->set('passportless.cookie.csrf.path', '/csrf');
    config()->set('passportless.cookie.csrf.http_only', false);

    $cookies = app(PassportlessCookieManager::class);
    $access = $cookies->createAccessCookie('access');
    $refresh = $cookies->createRefreshCookie('refresh');
    $csrf = $cookies->createCsrfCookie('csrf');

    expect($cookies->accessCookieName())->toBe('access_override')
        ->and($cookies->refreshCookieName())->toBe('refresh_override')
        ->and($cookies->csrfCookieName())->toBe('csrf_override')
        ->and($access->getPath())->toBe('/api')
        ->and($access->getDomain())->toBe('.example.test')
        ->and($access->isSecure())->toBeTrue()
        ->and($access->isHttpOnly())->toBeTrue()
        ->and($access->getSameSite())->toBe('none')
        ->and($refresh->getPath())->toBe('/refresh')
        ->and($refresh->getDomain())->toBe('.example.test')
        ->and($refresh->isSecure())->toBeTrue()
        ->and($refresh->isHttpOnly())->toBeTrue()
        ->and($csrf->getPath())->toBe('/csrf')
        ->and($csrf->getDomain())->toBe('.example.test')
        ->and($csrf->isSecure())->toBeTrue()
        ->and($csrf->isHttpOnly())->toBeFalse();
});

it('forgets cookies with issue name path domain and security attributes', function () {
    config()->set('passportless.cookie.domain', '.example.test');
    config()->set('passportless.cookie.secure', true);
    config()->set('passportless.cookie.same_site', 'strict');
    config()->set('passportless.cookie.refresh.path', '/api/refresh');

    $cookies = app(PassportlessCookieManager::class);
    $issued = $cookies->createRefreshCookie('refresh');
    $forgotten = $cookies->forgetRefreshCookie();

    expect($forgotten->getName())->toBe($issued->getName())
        ->and($forgotten->getPath())->toBe($issued->getPath())
        ->and($forgotten->getDomain())->toBe($issued->getDomain())
        ->and($forgotten->isSecure())->toBe($issued->isSecure())
        ->and($forgotten->isHttpOnly())->toBe($issued->isHttpOnly())
        ->and($forgotten->getSameSite())->toBe($issued->getSameSite())
        ->and($forgotten->getValue())->toBeNull()
        ->and($forgotten->isCleared())->toBeTrue();
});

it('rejects unsafe cookie security configuration', function (string $key, mixed $value) {
    config()->set($key, $value);

    expect(fn () => app(PassportlessCookieManager::class))->toThrow(InvalidArgumentException::class);
})->with([
    'insecure SameSite none' => ['passportless.cookie.same_site', 'none'],
    'readable access token' => ['passportless.cookie.access.http_only', false],
    'readable refresh token' => ['passportless.cookie.refresh.http_only', false],
    'string secure flag' => ['passportless.cookie.secure', 'true'],
    'invalid SameSite value' => ['passportless.cookie.same_site', 'invalid'],
]);

it('rejects ambiguous cookie names and invalid paths', function (string $key, mixed $value) {
    config()->set($key, $value);

    expect(fn () => app(PassportlessCookieManager::class))->toThrow(InvalidArgumentException::class);
})->with([
    'duplicate name' => ['passportless.cookie.csrf.name', 'passportless_access_token'],
    'reserved name character' => ['passportless.cookie.access.name', 'access;token'],
    'relative path' => ['passportless.cookie.refresh.path', 'api/auth/refresh'],
    'empty domain' => ['passportless.cookie.domain', ''],
    'attribute injection domain' => ['passportless.cookie.domain', 'example.test; SameSite=None'],
    'invalid hostname' => ['passportless.cookie.domain', '-example.test'],
]);

it('rejects invalid token lifetimes', function (string $key, mixed $value) {
    config()->set($key, $value);

    expect(fn () => app(PassportlessCookieManager::class))->toThrow(InvalidArgumentException::class);
})->with([
    'zero access lifetime' => ['passportless.access_token.expiration', 0],
    'negative refresh lifetime' => ['passportless.refresh_token.expiration', -1],
    'fractional access lifetime' => ['passportless.access_token.expiration', 1.5],
]);
