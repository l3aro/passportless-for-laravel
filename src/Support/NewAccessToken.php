<?php

namespace l3aro\AuthToken\Support;

use l3aro\AuthToken\Models\PersonalAccessToken;

class NewAccessToken
{
    public function __construct(
        public PersonalAccessToken $accessToken,
        public string $plainTextToken,
    ) {}
}
