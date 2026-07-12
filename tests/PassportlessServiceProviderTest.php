<?php

use l3aro\Passportless\PassportlessServiceProvider;

it('boots without a published passportless auth guard', function () {
    config()->set('auth.guards.passportless', null);

    expect(fn() => app(PassportlessServiceProvider::class)->packageBooted())->not->toThrow(InvalidArgumentException::class);
});
