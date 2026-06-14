<?php

use App\Providers\AppServiceProvider;
use App\Providers\IdempotencyServiceProvider;

return [
    AppServiceProvider::class,
    IdempotencyServiceProvider::class,
];
