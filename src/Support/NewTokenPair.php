<?php

namespace l3aro\AuthToken\Support;

use l3aro\AuthToken\Models\RefreshToken;
use l3aro\AuthToken\Models\TokenSession;

class NewTokenPair
{
    public function __construct(
        public NewAccessToken $accessToken,
        public RefreshToken $refreshToken,
        public TokenSession $session,
        public string $plainTextRefreshToken,
    ) {}

    public function plainTextAccessToken(): string
    {
        return $this->accessToken->plainTextToken;
    }
}
