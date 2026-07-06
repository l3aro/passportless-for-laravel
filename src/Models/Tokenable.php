<?php

namespace l3aro\Passportless\Models;

use Illuminate\Database\Eloquent\Model;
use l3aro\Passportless\Concerns\HasPassportless;

abstract class Tokenable extends Model
{
    use HasPassportless;
}
