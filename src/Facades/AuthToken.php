<?php

namespace l3aro\AuthToken\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \l3aro\AuthToken\AuthToken
 */
class AuthToken extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \l3aro\AuthToken\AuthToken::class;
    }
}
