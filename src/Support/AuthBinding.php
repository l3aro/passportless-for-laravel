<?php

namespace l3aro\Passportless\Support;

use Illuminate\Database\Eloquent\Model;

final readonly class AuthBinding
{
    /**
     * @param  class-string<Model>  $model
     */
    public function __construct(
        public string $guard,
        public string $provider,
        public string $model,
    ) {}
}
