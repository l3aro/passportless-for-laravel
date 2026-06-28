<?php

namespace l3aro\AuthToken\Models;

use Illuminate\Database\Eloquent\Model;
use l3aro\AuthToken\Concerns\HasAuthTokens;

abstract class Tokenable extends Model
{
    use HasAuthTokens;
}
