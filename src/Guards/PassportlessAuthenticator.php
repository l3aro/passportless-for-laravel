<?php

namespace l3aro\Passportless\Guards;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use InvalidArgumentException;
use l3aro\Passportless\Passportless;
use l3aro\Passportless\PassportlessCookieManager;

class PassportlessAuthenticator
{
    public function __construct(
        private readonly Passportless $passportless,
        private readonly PassportlessCookieManager $cookies,
    ) {}

    public function authenticate(Request $request, string $guardName): ?Model
    {
        $plainTextToken = $this->plainTextTokenFromRequest($request, $guardName);

        if ($plainTextToken === null) {
            return null;
        }

        $accessToken = $this->passportless->findToken($plainTextToken, $guardName);

        if (! $accessToken) {
            return null;
        }

        $tokenable = $accessToken->tokenable;

        if (! $tokenable instanceof Model || ! method_exists($tokenable, 'withAccessToken')) {
            return null;
        }

        $lastUsedAt = $accessToken->last_used_at;
        $updateInterval = (int) config('passportless.access_token.last_used_update_interval', 60);

        if ($lastUsedAt === null || $lastUsedAt->copy()->addSeconds($updateInterval)->isPast()) {
            $accessToken->recordUsage(now());
        }

        return $tokenable->withAccessToken($accessToken);
    }

    protected function plainTextTokenFromRequest(Request $request, string $guardName): ?string
    {
        $plainTextToken = $request->bearerToken();

        if (is_string($plainTextToken) && $plainTextToken !== '') {
            return $plainTextToken;
        }

        return $this->plainTextTokenFromAccessCookie($request, $guardName);
    }

    protected function plainTextTokenFromAccessCookie(Request $request, string $guardName): ?string
    {
        try {
            $defaultGuard = (string) config('passportless.guard', 'passportless');
            $cookieManager = $guardName === $defaultGuard
                ? $this->cookies
                : $this->cookies->forGuard($guardName);
        } catch (InvalidArgumentException) {
            return null;
        }

        $cookieToken = $request->cookie($cookieManager->accessCookieName());

        if (! is_string($cookieToken) || $cookieToken === '') {
            return null;
        }

        return rawurldecode($cookieToken);
    }
}
