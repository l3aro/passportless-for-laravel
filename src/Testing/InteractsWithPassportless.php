<?php

namespace l3aro\Passportless\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Testing\TestCase;
use Illuminate\Testing\TestResponse;
use InvalidArgumentException;
use l3aro\Passportless\Passportless;
use l3aro\Passportless\PassportlessCookieManager;
use l3aro\Passportless\Support\AuthBindingResolver;
use PHPUnit\Framework\Assert;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * @mixin TestCase
 */
trait InteractsWithPassportless
{
    protected function actingAsPassportless(Authenticatable $user, string $guard = 'passportless'): static
    {
        $binding = app(AuthBindingResolver::class)->resolve($guard);

        if (! $user instanceof $binding->model) {
            throw new InvalidArgumentException("User model does not match Passportless guard [{$binding->guard}].");
        }

        return $this->actingAs($user, $guard);
    }

    protected function withPassportlessCookieSession(Model $user, string $guard = 'passportless'): static
    {
        $pair = app(Passportless::class)->createTokenPair(
            $user,
            'Passportless test session',
            guard: $guard,
        );
        $cookies = app(PassportlessCookieManager::class)->forGuard($guard);
        $csrf = bin2hex(random_bytes(20));

        $this->withUnencryptedCookies([
            $cookies->accessCookieName() => $pair->plainTextAccessToken(),
            $cookies->refreshCookieName() => $pair->plainTextRefreshToken(),
            $cookies->csrfCookieName() => $csrf,
        ]);
        $this->withHeader('X-CSRF-TOKEN', $csrf);

        return $this;
    }

    protected function assertPassportlessAuthCookiesQueued(TestResponse $response, string $guard = 'passportless'): static
    {
        $cookies = app(PassportlessCookieManager::class)->forGuard($guard);

        $this->assertCookieMatches($response, $cookies->createAccessCookie('ignored'));
        $this->assertCookieMatches($response, $cookies->createRefreshCookie('ignored'));
        $this->assertCookieMatches($response, $cookies->createCsrfCookie('ignored'));

        return $this;
    }

    protected function assertPassportlessAuthCookiesForgotten(TestResponse $response, string $guard = 'passportless'): static
    {
        $cookies = app(PassportlessCookieManager::class)->forGuard($guard);

        $this->assertForgottenCookieMatches($response, $cookies->forgetAccessCookie());
        $this->assertForgottenCookieMatches($response, $cookies->forgetRefreshCookie());
        $this->assertForgottenCookieMatches($response, $cookies->forgetCsrfCookie());

        return $this;
    }

    protected function assertCookieMatches(TestResponse $response, Cookie $expected): void
    {
        $response->assertPlainCookie($expected->getName());

        $actual = $response->getCookie($expected->getName(), false);

        Assert::assertNotNull($actual);
        Assert::assertSame($expected->getPath(), $actual->getPath());
        Assert::assertSame($expected->getDomain(), $actual->getDomain());
        Assert::assertSame($expected->isSecure(), $actual->isSecure());
        Assert::assertSame($expected->isHttpOnly(), $actual->isHttpOnly());
        Assert::assertSame($expected->getSameSite(), $actual->getSameSite());
    }

    protected function assertForgottenCookieMatches(TestResponse $response, Cookie $expected): void
    {
        $response->assertCookieExpired($expected->getName());

        $actual = $response->getCookie($expected->getName(), false);

        Assert::assertNotNull($actual);
        Assert::assertSame($expected->getPath(), $actual->getPath());
        Assert::assertSame($expected->getDomain(), $actual->getDomain());
        Assert::assertSame($expected->isSecure(), $actual->isSecure());
        Assert::assertSame($expected->isHttpOnly(), $actual->isHttpOnly());
        Assert::assertSame($expected->getSameSite(), $actual->getSameSite());
    }
}
