<?php

use Illuminate\Http\Request;
use l3aro\Passportless\Http\Middleware\ValidateCsrfCookie;
use l3aro\Passportless\PassportlessCookieManager;
use Symfony\Component\HttpKernel\Exception\HttpException;

beforeEach(function () {
    config()->set('passportless.guard', 'passportless');
    config()->set('passportless.cookie.secure', false);
    config()->set('passportless.cookie.guards', []);
});

it('allows unsafe methods when csrf cookie matches x-csrf-token header', function () {
    $cookies = app(PassportlessCookieManager::class);
    $token = 'csrf-token-value';

    $request = Request::create('/profile', 'POST');
    $request->cookies->set($cookies->csrfCookieName(), $token);
    $request->headers->set('X-CSRF-TOKEN', $token);

    $response = app(ValidateCsrfCookie::class)->handle($request, fn() => response('ok'));

    expect($response->getContent())->toBe('ok');
});

it('allows csrf values that contain percent-encoded text when both sources match', function () {
    $cookies = app(PassportlessCookieManager::class);
    $token = 'csrf%2Ftoken%25value';

    $request = Request::create('/profile', 'POST');
    $request->cookies->set($cookies->csrfCookieName(), $token);
    $request->headers->set('X-CSRF-TOKEN', $token);

    $response = app(ValidateCsrfCookie::class)->handle($request, fn() => response('ok'));

    expect($response->getContent())->toBe('ok');
});

it('rejects missing csrf cookie with 419', function () {
    $request = Request::create('/profile', 'POST');
    $request->headers->set('X-CSRF-TOKEN', 'present');

    expect(fn() => app(ValidateCsrfCookie::class)->handle($request, fn() => response('ok')))
        ->toThrow(function (HttpException $exception) {
            expect($exception->getStatusCode())->toBe(419)
                ->and($exception->getMessage())->toBe('CSRF token mismatch.')
                ->and($exception->getMessage())->not->toContain('present');
        });
});

it('rejects missing x-csrf-token header with 419', function () {
    $cookies = app(PassportlessCookieManager::class);
    $token = 'csrf-token-value';

    $request = Request::create('/profile', 'POST');
    $request->cookies->set($cookies->csrfCookieName(), $token);

    expect(fn() => app(ValidateCsrfCookie::class)->handle($request, fn() => response('ok')))
        ->toThrow(function (HttpException $exception) use ($token) {
            expect($exception->getStatusCode())->toBe(419)
                ->and($exception->getMessage())->not->toContain($token);
        });
});

it('rejects empty csrf cookie or header with 419', function (string $cookieValue, string $headerValue) {
    $cookies = app(PassportlessCookieManager::class);

    $request = Request::create('/profile', 'POST');
    $request->cookies->set($cookies->csrfCookieName(), $cookieValue);
    $request->headers->set('X-CSRF-TOKEN', $headerValue);

    expect(fn() => app(ValidateCsrfCookie::class)->handle($request, fn() => response('ok')))
        ->toThrow(function (HttpException $exception) {
            expect($exception->getStatusCode())->toBe(419);
        });
})->with([
    'empty cookie' => ['', 'header-token'],
    'empty header' => ['cookie-token', ''],
    'both empty' => ['', ''],
]);

it('rejects mismatched csrf values with 419 without exposing tokens', function () {
    $cookies = app(PassportlessCookieManager::class);
    $cookieToken = 'cookie-secret-token';
    $headerToken = 'header-secret-token';

    $request = Request::create('/profile', 'POST');
    $request->cookies->set($cookies->csrfCookieName(), $cookieToken);
    $request->headers->set('X-CSRF-TOKEN', $headerToken);

    expect(fn() => app(ValidateCsrfCookie::class)->handle($request, fn() => response('ok')))
        ->toThrow(function (HttpException $exception) use ($cookieToken, $headerToken) {
            expect($exception->getStatusCode())->toBe(419)
                ->and($exception->getMessage())->toBe('CSRF token mismatch.')
                ->and($exception->getMessage())->not->toContain($cookieToken)
                ->and($exception->getMessage())->not->toContain($headerToken);
        });
});

it('bypasses csrf validation for safe methods', function (string $method) {
    $request = Request::create('/profile', $method);

    $response = app(ValidateCsrfCookie::class)->handle($request, fn() => response('ok'));

    expect($response->getContent())->toBe('ok');
})->with(['GET', 'HEAD', 'OPTIONS']);

it('uses guard-specific csrf cookie names', function () {
    config()->set('passportless.cookie.guards.passportless-admin', [
        'csrf' => [
            'name' => 'admin_csrf_token',
            'path' => '/api/auth/admin',
        ],
    ]);

    $token = 'admin-csrf-value';
    $adminCookies = app(PassportlessCookieManager::class)->forGuard('passportless-admin');

    $request = Request::create('/admin/profile', 'POST');
    $request->cookies->set($adminCookies->csrfCookieName(), $token);
    $request->headers->set('X-CSRF-TOKEN', $token);

    $response = app(ValidateCsrfCookie::class)->handle(
        $request,
        fn() => response('ok'),
        'passportless-admin',
    );

    expect($adminCookies->csrfCookieName())->toBe('admin_csrf_token')
        ->and($response->getContent())->toBe('ok');
});

it('rejects default csrf cookie when guard-scoped middleware expects admin cookie', function () {
    config()->set('passportless.cookie.guards.passportless-admin', [
        'csrf' => [
            'name' => 'admin_csrf_token',
            'path' => '/api/auth/admin',
        ],
    ]);

    $token = 'shared-csrf-value';
    $defaultCookies = app(PassportlessCookieManager::class);

    $request = Request::create('/admin/profile', 'POST');
    $request->cookies->set($defaultCookies->csrfCookieName(), $token);
    $request->headers->set('X-CSRF-TOKEN', $token);

    expect(fn() => app(ValidateCsrfCookie::class)->handle(
        $request,
        fn() => response('ok'),
        'passportless-admin',
    ))->toThrow(function (HttpException $exception) {
        expect($exception->getStatusCode())->toBe(419);
    });
});

it('registers the passportless.csrf middleware alias', function () {
    expect(app('router')->getMiddleware()['passportless.csrf'] ?? null)
        ->toBe(ValidateCsrfCookie::class);
});
