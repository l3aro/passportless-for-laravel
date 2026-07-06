<?php

namespace l3aro\Passportless\Contracts;

interface HasAbilities
{
    public function can(string $ability): bool;

    public function cannot(string $ability): bool;
}
