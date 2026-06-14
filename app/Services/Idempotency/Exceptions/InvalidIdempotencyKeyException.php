<?php

declare(strict_types=1);

namespace App\Services\Idempotency\Exceptions;

use RuntimeException;

final class InvalidIdempotencyKeyException extends RuntimeException
{
}
