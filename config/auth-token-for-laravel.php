<?php

// config for l3aro/AuthToken
return [
    'access_tokens_table' => 'auth_tokens',
    'refresh_tokens_table' => 'auth_refresh_tokens',
    'sessions_table' => 'auth_token_sessions',

    'guard' => 'auth-token',
    'provider' => null,

    'access_token' => [
        'expiration' => 15,
    ],

    'refresh_token' => [
        'expiration' => 43200,
        'reuse_detection' => 'revoke_family',
    ],

    'abilities' => [
        'default' => ['*'],
        'wildcard_enabled' => true,
    ],

    'token' => [
        'max_length' => 120,
    ],
];
