<?php

declare(strict_types=1);

namespace App\Services\Idempotency;

use App\Services\Idempotency\Exceptions\IdempotencyLockTimeoutException;
use App\Services\Idempotency\Exceptions\InvalidIdempotencyKeyException;
use App\Services\Idempotency\Exceptions\MaxIdempotencyKeysException;
use Closure;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Central service for storing & retrieving idempotency records and
 * serializing concurrent duplicate requests through a Redis lock.
 *
 * Security posture:
 *   - Records are scoped to the authenticated user id (OWASP A01).
 *   - Only the SHA-256 fingerprint of the request is persisted alongside
 *     the response — never the raw payload (OWASP A02).
 *   - The header value is strictly validated before being concatenated
 *     into a cache key (OWASP A03).
 *   - TTL + fingerprint mismatch detection mitigates replay (OWASP A08).
 *   - Lock contention, conflicts, and replays are logged without payload
 *     content (OWASP A09).
 */
final class IdempotencyService
{
    public function __construct(
        private readonly CacheFactory $cacheFactory,
        private readonly ConfigRepository $config,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Run the critical section under a per-(user, key) Redis lock.
     *
     * The callback is invoked with the current cached record (or null)
     * after the lock is held — this is the canonical place to do the
     * double-check that prevents race conditions on first write. It MUST
     * return a 2-tuple `[Response, ?IdempotencyRecord]`: the second
     * element, when non-null, will be persisted before the lock is
     * released; pass null to deliberately skip caching (e.g. 5xx).
     *
     * @template TResponse
     * @param  Closure(?IdempotencyRecord): array{0: TResponse, 1: ?IdempotencyRecord}  $critical
     * @return TResponse
     */
    public function withLock(
        string $key,
        string|int|null $scope,
        Closure $critical,
    ): mixed {
        $this->assertValidKey($key);

        $cacheKey = $this->cacheKey($key, $scope);
        $lockKey  = $this->lockKey($key, $scope);
        $lock     = $this->cache()->lock($lockKey, $this->lockTtl());

        try {
            $lock->block($this->lockWait());
        } catch (LockTimeoutException $e) {
            $this->logger->warning('idempotency.lock_timeout', [
                'key_hash' => $this->hashForLog($key),
                'scope'    => $scope,
            ]);

            throw new IdempotencyLockTimeoutException(
                'Could not acquire idempotency lock within the allowed wait window.',
                previous: $e,
            );
        }

        try {
            $existing = $this->fetch($cacheKey);

            // Enforce the per-scope key cap for genuinely new keys only,
            // before the critical section runs any expensive work.
            if ($existing === null) {
                $this->assertUnderKeyLimit($scope);
            }

            [$response, $toStore] = $critical($existing);

            if ($toStore !== null) {
                $this->store($cacheKey, $toStore);
                $this->incrementKeyCount($scope);
            }

            return $response;
        } finally {
            try {
                $lock->release();
            } catch (Throwable) {
                // Lock may have auto-expired under load; release errors
                // must never mask the original outcome.
            }
        }
    }

    public function find(string $key, string|int|null $scope): ?IdempotencyRecord
    {
        $this->assertValidKey($key);

        return $this->fetch($this->cacheKey($key, $scope));
    }

    public function cacheKey(string $key, string|int|null $scope): string
    {
        $prefix = (string) $this->config->get('idempotency.prefix', 'idem');

        // The scope (authenticated user id, else session id) is part of the
        // key so an attacker who guesses another principal's idempotency
        // value cannot read or hijack the cached response (OWASP A01 —
        // Broken Access Control).
        return sprintf('%s:%s:%s', $prefix, $scope ?? 'anon', $key);
    }

    public function lockKey(string $key, string|int|null $scope): string
    {
        return $this->cacheKey($key, $scope).':lock';
    }

    /**
     * Per-scope counter key tracking how many distinct idempotency keys a
     * principal has registered within the current TTL window.
     */
    public function counterKey(string|int|null $scope): string
    {
        $prefix = (string) $this->config->get('idempotency.prefix', 'idem');

        return sprintf('%s:count:%s', $prefix, $scope ?? 'anon');
    }

    public function ttl(): int
    {
        return (int) $this->config->get('idempotency.ttl', 86_400);
    }

    public function lockTtl(): int
    {
        return (int) $this->config->get('idempotency.lock.ttl', 30);
    }

    public function lockWait(): int
    {
        return (int) $this->config->get('idempotency.lock.wait', 10);
    }

    public function shouldCacheStatus(int $status): bool
    {
        $min = (int) $this->config->get('idempotency.cache_status_codes.min', 200);
        $max = (int) $this->config->get('idempotency.cache_status_codes.max', 499);

        return $status >= $min && $status <= $max;
    }

    public function maxBodyBytes(): int
    {
        return (int) $this->config->get('idempotency.max_body_bytes', 1_048_576);
    }

    /**
     * Maximum distinct idempotency keys a single scope may register within
     * a TTL window. `<= 0` disables the cap entirely.
     */
    public function maxKeysPerUser(): int
    {
        return (int) $this->config->get('idempotency.max_keys_per_user', 1_000);
    }

    /**
     * Reject a brand-new key once the scope is at or above its cap.
     *
     * @throws MaxIdempotencyKeysException
     */
    public function assertUnderKeyLimit(string|int|null $scope): void
    {
        $max = $this->maxKeysPerUser();

        if ($max <= 0) {
            return;
        }

        $count = (int) ($this->cache()->get($this->counterKey($scope)) ?? 0);

        if ($count >= $max) {
            $this->logger->warning('idempotency.key_limit_exceeded', [
                'scope' => $scope,
                'count' => $count,
                'max'   => $max,
            ]);

            throw new MaxIdempotencyKeysException(
                'Idempotency key limit reached for this principal. Retry later.',
            );
        }
    }

    /**
     * Bump the per-scope key counter, (re)applying the TTL so it behaves as
     * a self-healing fixed window and can never grow unbounded.
     *
     * The read-modify-write is intentionally a soft limit: under heavy
     * concurrency it may over/undercount by a few, which is acceptable for
     * a coarse memory-safety guard and keeps the implementation portable
     * across every atomic-lock-capable cache store.
     */
    public function incrementKeyCount(string|int|null $scope): void
    {
        if ($this->maxKeysPerUser() <= 0) {
            return;
        }

        $counterKey = $this->counterKey($scope);
        $current = (int) ($this->cache()->get($counterKey) ?? 0);

        $this->cache()->put($counterKey, $current + 1, $this->ttl());
    }

    public function assertValidKey(string $key): void
    {
        $pattern = (string) $this->config->get('idempotency.key.pattern', '/^[A-Za-z0-9_\-:.]{8,255}$/');

        if (preg_match($pattern, $key) !== 1) {
            throw new InvalidIdempotencyKeyException('Idempotency-Key header has an invalid format.');
        }
    }

    /**
     * One-way hash used in logs so the raw key value is never persisted
     * in plaintext to log aggregators (OWASP A09).
     */
    public function hashForLog(string $key): string
    {
        return substr(hash('sha256', $key), 0, 16);
    }

    private function cache(): CacheRepository
    {
        $store = (string) $this->config->get('idempotency.store', 'redis');

        return $this->cacheFactory->store($store);
    }

    private function fetch(string $cacheKey): ?IdempotencyRecord
    {
        $raw = $this->cache()->get($cacheKey);

        if ($raw === null) {
            return null;
        }

        try {
            $data = is_array($raw)
                ? $raw
                : json_decode((string) $raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            $this->logger->error('idempotency.cache_decode_failure', [
                'cache_key' => $cacheKey,
                'error'     => $e->getMessage(),
            ]);

            return null;
        }

        return IdempotencyRecord::fromArray($data);
    }

    private function store(string $cacheKey, IdempotencyRecord $record): void
    {
        $payload = json_encode(
            $record->toArray(),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );

        $this->cache()->put($cacheKey, $payload, $this->ttl());
    }
}
