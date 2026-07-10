<?php

namespace l3aro\Passportless\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use l3aro\Passportless\Passportless;
use l3aro\Passportless\PassportlessCookieManager;
use l3aro\Passportless\Support\SpaAuthRouteOptions;

class SpaLogoutController extends Controller
{
    public function __construct(
        protected Passportless $passportless,
        protected PassportlessCookieManager $cookies,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $options = SpaAuthRouteOptions::fromRequest($request);
        $cookies = $this->cookies->forGuard($options->guard);
        $accessToken = $request->cookie($cookies->accessCookieName());

        if (is_string($accessToken) && $accessToken !== '') {
            $this->passportless->revokeCurrentSession(
                rawurldecode($accessToken),
                $options->guard,
            );
        }

        $refreshToken = $request->cookie($cookies->refreshCookieName());

        if (is_string($refreshToken) && $refreshToken !== '') {
            $this->passportless->revokeCurrentSessionByRefreshToken(
                rawurldecode($refreshToken),
                $options->guard,
            );
        }

        return response()->json(['message' => 'Logged out.'])
            ->withCookie($cookies->forgetAccessCookie())
            ->withCookie($cookies->forgetRefreshCookie())
            ->withCookie($cookies->forgetCsrfCookie());
    }
}
