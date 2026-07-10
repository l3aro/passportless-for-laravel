<?php

namespace l3aro\Passportless\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use l3aro\Passportless\Passportless;
use l3aro\Passportless\PassportlessCookieManager;
use l3aro\Passportless\Support\SpaAuthRouteOptions;

class SpaRefreshController extends Controller
{
    public function __construct(
        protected Passportless $passportless,
        protected PassportlessCookieManager $cookies,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $options = SpaAuthRouteOptions::fromRequest($request);
        $cookies = $this->cookies->forGuard($options->guard);
        $refreshToken = $request->cookie($cookies->refreshCookieName());

        if (! is_string($refreshToken) || $refreshToken === '') {
            return response()->json(['message' => 'Invalid token.'], 401);
        }

        $pair = $this->passportless->refreshToken(
            rawurldecode($refreshToken),
            guard: $options->guard,
        );

        if ($pair === null) {
            return response()->json(['message' => 'Invalid token.'], 401);
        }

        $payload = [
            'token_type' => 'Cookie',
            'access_expires_at' => $pair->accessToken->accessToken->expires_at?->toIso8601String(),
            'refresh_expires_at' => $pair->refreshToken->expires_at->toIso8601String(),
            'session' => [
                'id' => $pair->session->getKey(),
                'name' => $pair->session->getAttribute('name'),
            ],
        ];

        if ($options->csrf) {
            $payload['csrf_token'] = bin2hex(random_bytes(20));
        }

        $response = response()->json($payload)
            ->withCookie($cookies->createAccessCookie($pair->plainTextAccessToken()))
            ->withCookie($cookies->createRefreshCookie($pair->plainTextRefreshToken()));

        if ($options->csrf) {
            $response = $response->withCookie($cookies->createCsrfCookie($payload['csrf_token']));
        }

        return $response;
    }
}
