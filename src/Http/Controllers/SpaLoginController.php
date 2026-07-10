<?php

namespace l3aro\Passportless\Http\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use l3aro\Passportless\Passportless;
use l3aro\Passportless\PassportlessCookieManager;
use l3aro\Passportless\Support\NewTokenPair;
use l3aro\Passportless\Support\SpaAuthRouteOptions;

class SpaLoginController extends Controller
{
    public function __construct(
        protected Passportless $passportless,
        protected PassportlessCookieManager $cookies,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $options = SpaAuthRouteOptions::fromRequest($request);
        $user = $options->resolveAuthenticate($request);

        if (! $user instanceof Model) {
            return response()->json(['message' => 'Invalid credentials.'], 401);
        }

        try {
            $pair = $this->passportless->createTokenPair(
                $user,
                $options->name,
                $options->abilities,
                $options->guard,
            );
        } catch (\InvalidArgumentException) {
            return response()->json(['message' => 'Invalid credentials.'], 401);
        }

        return $this->tokenPairResponse($pair, $options);
    }

    protected function tokenPairResponse(NewTokenPair $pair, SpaAuthRouteOptions $options): JsonResponse
    {
        $cookies = $this->cookies->forGuard($options->guard);
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
