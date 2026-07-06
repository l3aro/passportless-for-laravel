<?php

use l3aro\Passportless\Enums\RefreshTokenReuseDetection;

// Configuration for l3aro/Passportless
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
        'expiration' => 43200,
        'reuse_detection' => RefreshTokenReuseDetection::REVOKE_FAMILY,
    ],

    'abilities' => [
        'default' => ['*'],
        'wildcard_enabled' => true,
    ],

    'token' => [
        'max_length' => 120,
    ],
];
