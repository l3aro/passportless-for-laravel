<?php

namespace l3aro\Passportless\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use l3aro\Passportless\PassportlessCookieManager;
use Symfony\Component\HttpFoundation\Response;

class ValidateCsrfCookie
{
    public function __construct(private readonly PassportlessCookieManager $cookies) {}

    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        if (in_array(strtoupper($request->method()), ['GET', 'HEAD', 'OPTIONS'], true)) {
            return $next($request);
        }

        $cookies = ($guard === null || $guard === '')
            ? $this->cookies
            : $this->cookies->forGuard($guard);

        $cookieToken = $request->cookie($cookies->csrfCookieName());
        $headerToken = $request->headers->get('X-CSRF-TOKEN');

        if (! is_string($cookieToken)
            || ! is_string($headerToken)
            || $cookieToken === ''
            || $headerToken === ''
            || ! hash_equals($cookieToken, $headerToken)) {
            abort(419, 'CSRF token mismatch.');
        }

        return $next($request);
    }
}
