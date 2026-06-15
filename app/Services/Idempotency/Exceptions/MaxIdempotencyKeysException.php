<?php

declare(strict_types=1);

namespace App\Services\Idempotency\Exceptions;

use RuntimeException;

/**
 * Thrown when a single scope (user or session) attempts to register more
 * distinct idempotency keys than `idempotency.max_keys_per_user` allows
 * within a TTL window. Bounds Redis memory usage and blunts a key-flood
 * denial-of-service vector.
 */
final class MaxIdempotencyKeysException extends RuntimeException
{
}
