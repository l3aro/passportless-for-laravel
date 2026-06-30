<?php

namespace l3aro\AuthToken\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckAbilities
{
    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        $user = $request->user();

        if (! $user || ! method_exists($user, 'tokenCan') || $abilities === []) {
            throw new AuthenticationException;
        }

        foreach ($abilities as $ability) {
            if (! $user->tokenCan($ability)) {
                abort(403);
            }
        }

        return $next($request);
    }
}
