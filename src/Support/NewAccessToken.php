<?php

namespace l3aro\Passportless\Support;

use l3aro\Passportless\Models\PersonalAccessToken;

class NewAccessToken
{
    public function __construct(
        public PersonalAccessToken $accessToken,
        public string $plainTextToken,
    ) {}
}
