<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Services\Idempotency\Exceptions\IdempotencyLockTimeoutException;
use App\Services\Idempotency\Exceptions\InvalidIdempotencyKeyException;
use App\Services\Idempotency\IdempotencyRecord;
use App\Services\Idempotency\IdempotencyService;
use App\Services\Idempotency\RequestFingerprint;
use Closure;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Enforces exactly-once execution semantics for mutating HTTP verbs.
 *
 * Flow:
 *   1. Bypass non-mutating methods.
 *   2. Require + validate the Idempotency-Key header (400 on miss/invalid).
 *   3. Compute SHA-256 fingerprint of the request.
 *   4. Pre-lock cache lookup (fast path for normal client retries).
 *        - fingerprint matches  → replay cached response.
 *        - fingerprint differs  → 409 Conflict.
 *   5. Otherwise acquire a Redis lock and execute the next pipeline.
 *        - inside the lock, re-check the cache (race protection).
 *        - cache the response (only successful 2xx–4xx by policy).
 *   6. On lock-wait timeout → 503 with Retry-After.
 */
final readonly class EnsureIdempotency
{
    public function __construct(
        private IdempotencyService $service,
        private RequestFingerprint $fingerprinter,
        private ConfigRepository   $config,
        private LoggerInterface    $logger,
    )
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (!$this->isMutating($request)) {
            return $next($request);
        }

        $headerName = (string)$this->config->get('idempotency.header', 'Idempotency-Key');
        $rawKey = $request->header($headerName);

        if (!is_string($rawKey) || trim($rawKey) === '') {
            return $this->problem(
                400,
                'idempotency_key_required',
                "The {$headerName} header is required for " . strtoupper($request->getMethod()) . ' requests.',
            );
        }

        $key = trim($rawKey);

        try {
            $this->service->assertValidKey($key);
        } catch (InvalidIdempotencyKeyException $e) {
            $this->logger->warning('idempotency.invalid_key', [
                'key_hash' => $this->service->hashForLog($key),
                'user_id' => $this->userId($request),
            ]);

            return $this->problem(400, 'idempotency_key_invalid', $e->getMessage());
        }

        $userId = $this->userId($request);
        $fingerprint = $this->fingerprinter->for($request);

        // Fast path: pre-lock lookup. Avoids spinning the lock for the
        // overwhelmingly common "client retried after seeing the original
        // response just fine" case.
        $existing = $this->service->find($key, $userId);
        if ($existing !== null) {
            return $this->replayOrConflict($existing, $fingerprint, $key, $userId);
        }

        try {
            return $this->service->withLock(
                $key,
                $userId,
                function (?IdempotencyRecord $existing) use ($next, $request, $key, $userId, $fingerprint): array {
                    // Double-check inside the lock: a peer worker may
                    // have populated the cache while we were blocked.
                    if ($existing !== null) {
                        return [$this->replayOrConflict($existing, $fingerprint, $key, $userId), null];
                    }

                    /** @var Response $response */
                    $response = $next($request);

                    $record = $this->buildRecord($response, $key, $userId, $fingerprint);

                    // Storage policy: skip 5xx so transient server
                    // failures stay legitimately retryable, and skip
                    // oversize bodies to bound Redis memory usage.
                    $shouldStore = $this->service->shouldCacheStatus($response->getStatusCode())
                        && strlen((string)$response->getContent()) <= $this->service->maxBodyBytes();

                    if (!$shouldStore) {
                        $this->logger->info('idempotency.bypass_cache', [
                            'key_hash' => $this->service->hashForLog($key),
                            'user_id' => $userId,
                            'status' => $response->getStatusCode(),
                            'body_size' => strlen((string)$response->getContent()),
                        ]);
                    } else {
                        $this->logger->info('idempotency.stored', [
                            'key_hash' => $this->service->hashForLog($key),
                            'user_id' => $userId,
                            'status' => $response->getStatusCode(),
                        ]);
                    }

                    return [$response, $shouldStore ? $record : null];
                },
            );
        } catch (IdempotencyLockTimeoutException) {
            return $this->problem(
                503,
                'idempotency_lock_timeout',
                'A request with this Idempotency-Key is still in progress. Please retry.',
                ['Retry-After' => (string)$this->service->lockWait()],
            );
        }
    }

    private function isMutating(Request $request): bool
    {
        $methods = (array)$this->config->get('idempotency.methods', ['POST', 'PUT', 'PATCH', 'DELETE']);

        return in_array(strtoupper($request->getMethod()), array_map('strtoupper', $methods), true);
    }

    /**
     * RFC 7807-style JSON error response, formatted identically for
     * every failure mode so client SDKs can pattern-match cleanly.
     *
     * @param array<string,string> $headers
     */
    private function problem(int $status, string $code, string $detail, array $headers = []): JsonResponse
    {
        return new JsonResponse(
            [
                'error' => [
                    'code' => $code,
                    'message' => $detail,
                    'status' => $status,
                ],
            ],
            $status,
            $headers,
        );
    }

    private function userId(Request $request): string|int|null
    {
        $user = $request->user();

        if ($user === null) {
            return null;
        }

        return $user->getAuthIdentifier();
    }

    private function replayOrConflict(
        IdempotencyRecord $record,
        string            $fingerprint,
        string            $key,
        string|int|null   $userId,
    ): Response
    {
        // hash_equals — constant-time comparison defends against timing
        // oracles on the fingerprint (OWASP A02 mitigation).
        if (!hash_equals($record->fingerprint, $fingerprint)) {
            $this->logger->warning('idempotency.fingerprint_conflict', [
                'key_hash' => $this->service->hashForLog($key),
                'user_id' => $userId,
            ]);

            return $this->problem(
                409,
                'idempotency_key_conflict',
                'This Idempotency-Key was previously used with a different request payload.',
            );
        }

        $this->logger->info('idempotency.replay', [
            'key_hash' => $this->service->hashForLog($key),
            'user_id' => $userId,
            'status' => $record->status,
        ]);

        $response = new Response($record->responseBody, $record->status, $record->headers);
        $response->headers->set('Idempotent-Replayed', 'true');
        $response->headers->set('Idempotency-Key', $key);

        return $response;
    }

    private function buildRecord(
        Response        $response,
        string          $key,
        string|int|null $userId,
        string          $fingerprint,
    ): IdempotencyRecord
    {
        $now = time();

        return new IdempotencyRecord(
            key: $key,
            userId: $userId,
            fingerprint: $fingerprint,
            status: $response->getStatusCode(),
            responseBody: (string)$response->getContent(),
            headers: $this->safeHeaders($response),
            createdAt: $now,
            expiresAt: $now + $this->service->ttl(),
        );
    }

    /**
     * Strip hop-by-hop & framework-managed headers; preserve only what
     * is safe and necessary for the client to parse the replayed body.
     *
     * @return array<string,string>
     */
    private function safeHeaders(Response $response): array
    {
        $allow = ['content-type', 'content-language', 'cache-control', 'etag', 'location'];
        $out = [];

        foreach ($allow as $name) {
            $value = $response->headers->get($name);
            if ($value !== null) {
                $out[$name] = $value;
            }
        }

        return $out;
    }
}
