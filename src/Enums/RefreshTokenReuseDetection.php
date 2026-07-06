<?php

namespace l3aro\Passportless\Enums;

enum RefreshTokenReuseDetection: string
{
    case REVOKE_FAMILY = 'revoke_family';
    case IGNORE = 'ignore';
}
