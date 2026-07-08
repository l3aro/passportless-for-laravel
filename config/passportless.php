<?php

use l3aro\Passportless\Enums\RefreshTokenReuseDetection;

return [
    'access_tokens_table' => 'passportless_tokens',
    'refresh_tokens_table' => 'passportless_refresh_tokens',
    'sessions_table' => 'passportless_token_sessions',

    'guard' => 'passportless',
    'provider' => null,

    'access_token' => [
        'expiration' => 15,
        'last_used_update_interval' => 60,
    ],

    'refresh_token' => [
        'expiration' => 60 * 24 * 30,
        'reuse_detection' => RefreshTokenReuseDetection::REVOKE_FAMILY,
    ],

    'abilities' => [
        'default' => ['*'],
        'wildcard_enabled' => true,
    ],

    'token' => [
        'max_length' => 120,
    ],

    'cookie' => [
        'domain' => null,
        'secure' => null,
        'same_site' => 'lax',

        'access' => [
            'name' => 'passportless_access_token',
            'path' => '/',
            'http_only' => true,
        ],

        'refresh' => [
            'name' => 'passportless_refresh_token',
            'path' => '/api/auth/refresh',
            'http_only' => true,
        ],

        'csrf' => [
            'name' => 'passportless_csrf_token',
            'path' => '/',
            'http_only' => false,
        ],

        'guards' => [],
    ],
];
