<?php

declare(strict_types=1);

namespace App\Services\Idempotency;

/**
 * Immutable value object representing a stored idempotency record.
 *
 * Note: `responseBody` holds the already-rendered HTTP response body. It is
 * the caller's responsibility to ensure no secret material (tokens, raw
 * credentials, PII flagged sensitive) is included in responses cached for
 * replay. Cf. OWASP A02 — Cryptographic Failures.
 */
final readonly class IdempotencyRecord
{
    /**
     * @param  array<string,string>  $headers
     */
    public function __construct(
        public string $key,
        public string|int|null $userId,
        public string $fingerprint,
        public int $status,
        public string $responseBody,
        public array $headers,
        public int $createdAt,
        public int $expiresAt,
    ) {
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'key'           => $this->key,
            'user_id'       => $this->userId,
            'fingerprint'   => $this->fingerprint,
            'status'        => $this->status,
            'response_body' => $this->responseBody,
            'headers'       => $this->headers,
            'created_at'    => $this->createdAt,
            'expires_at'    => $this->expiresAt,
        ];
    }

    /**
     * @param  array<string,mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            key:          (string) $data['key'],
            userId:       $data['user_id'] ?? null,
            fingerprint:  (string) $data['fingerprint'],
            status:       (int) $data['status'],
            responseBody: (string) $data['response_body'],
            headers:      (array) ($data['headers'] ?? []),
            createdAt:    (int) $data['created_at'],
            expiresAt:    (int) $data['expires_at'],
        );
    }
}
