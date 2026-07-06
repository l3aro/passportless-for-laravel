<?php

namespace l3aro\Passportless\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \l3aro\Passportless\Passportless
 */
class Passportless extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \l3aro\Passportless\Passportless::class;
    }
}
