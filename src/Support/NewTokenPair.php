<?php

namespace l3aro\Passportless\Support;

use l3aro\Passportless\Models\RefreshToken;
use l3aro\Passportless\Models\TokenSession;

class NewTokenPair
{
    public function __construct(
        public NewAccessToken $accessToken,
        public RefreshToken $refreshToken,
        public TokenSession $session,
        protected string $plainTextRefreshToken,
    ) {}

    public function plainTextAccessToken(): string
    {
        return $this->accessToken->plainTextToken;
    }

    public function plainTextRefreshToken(): string
    {
        return $this->plainTextRefreshToken;
    }
}
