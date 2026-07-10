<?php

namespace l3aro\Passportless\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ValidateSameOrigin
{
    public function handle(Request $request, Closure $next): Response
    {
        $origin = $request->headers->get('Origin');

        if (is_string($origin) && $origin !== '' && ! $this->matchesRequestOrigin($origin, $request)) {
            abort(403, 'Origin mismatch.');
        }

        return $next($request);
    }

    protected function matchesRequestOrigin(string $origin, Request $request): bool
    {
        $parts = parse_url($origin);

        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || isset($parts['user'], $parts['pass'], $parts['path'], $parts['query'], $parts['fragment'])) {
            return false;
        }

        $originScheme = strtolower($parts['scheme']);
        $originHost = strtolower($parts['host']);
        $originPort = $parts['port'] ?? $this->defaultPort($originScheme);
        $requestScheme = strtolower($request->getScheme());
        $requestPort = $request->getPort();

        return $originScheme === $requestScheme
            && $originHost === strtolower($request->getHost())
            && $originPort === $requestPort;
    }

    protected function defaultPort(string $scheme): ?int
    {
        return match ($scheme) {
            'http' => 80,
            'https' => 443,
            default => null,
        };
    }
}
