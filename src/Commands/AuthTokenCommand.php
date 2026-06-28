<?php

namespace l3aro\AuthToken\Commands;

use Illuminate\Console\Command;

class AuthTokenCommand extends Command
{
    public $signature = 'auth-token-for-laravel';

    public $description = 'My command';

    public function handle(): int
    {
        $this->comment('All done');

        return self::SUCCESS;
    }
}
