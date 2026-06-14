<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\Idempotency\IdempotencyService;
use App\Services\Idempotency\RequestFingerprint;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Log\LogManager;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;

final class IdempotencyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/idempotency.php', 'idempotency');

        $this->app->singleton(RequestFingerprint::class);

        $this->app->singleton(IdempotencyService::class, function ($app): IdempotencyService {
            /** @var LogManager $logs */
            $logs = $app->make(LoggerInterface::class);

            $channel = (string) $app->make(ConfigRepository::class)->get('idempotency.log_channel', 'stack');

            $logger = $logs instanceof LogManager
                ? $logs->channel($channel)
                : $logs;

            return new IdempotencyService(
                $app->make(CacheFactory::class),
                $app->make(ConfigRepository::class),
                $logger,
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../../config/idempotency.php' => config_path('idempotency.php'),
        ], 'idempotency-config');
    }
}
