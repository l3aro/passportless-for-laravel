<?php

namespace l3aro\AuthToken\Enums;

enum RefreshTokenReuseDetection: string
{
    case REVOKE_FAMILY = 'revoke_family';
    case IGNORE = 'ignore';
}
