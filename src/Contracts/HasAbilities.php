<?php

namespace l3aro\AuthToken\Contracts;

interface HasAbilities
{
    public function can(string $ability): bool;

    public function cannot(string $ability): bool;
}
