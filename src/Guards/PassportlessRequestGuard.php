<?php

namespace l3aro\Passportless\Guards;

use Illuminate\Auth\RequestGuard;
use Illuminate\Http\Request;

class PassportlessRequestGuard extends RequestGuard
{
    public function setRequest(Request $request)
    {
        $this->user = null;

        return parent::setRequest($request);
    }
}
