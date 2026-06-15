<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Idempotency Header
    |--------------------------------------------------------------------------
    |
    | The HTTP header clients must send to identify a logical request. Any
    | mutating verb without this header will be rejected with 400.
    |
    */
    'header' => env('IDEMPOTENCY_HEADER', 'Idempotency-Key'),

    /*
    |--------------------------------------------------------------------------
    | Mutating HTTP Methods
    |--------------------------------------------------------------------------
    |
    | Methods that have side effects and therefore must be guarded by the
    | idempotency middleware. GET / HEAD / OPTIONS bypass the middleware.
    |
    */
    'methods' => ['POST', 'PUT', 'PATCH', 'DELETE'],

    /*
    |--------------------------------------------------------------------------
    | Storage TTL
    |--------------------------------------------------------------------------
    |
    | How long (in seconds) a successfully replayed response is retained.
    | Defaults to 24h. After expiry the same key is treated as a brand new
    | request (mitigates replay risk — OWASP A08).
    |
    */
    'ttl' => (int) env('IDEMPOTENCY_TTL', 86_400),

    /*
    |--------------------------------------------------------------------------
    | Lock Configuration
    |--------------------------------------------------------------------------
    |
    | Atomic Redis lock used to serialize concurrent requests sharing the
    | same idempotency key. `wait` is the maximum number of seconds a
    | duplicate request will block waiting for the in-flight original to
    | finish before returning the freshly cached response.
    |
    */
    'lock' => [
        'ttl'  => (int) env('IDEMPOTENCY_LOCK_TTL', 30),
        'wait' => (int) env('IDEMPOTENCY_LOCK_WAIT', 10),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Store
    |--------------------------------------------------------------------------
    |
    | The cache store backing both the record cache and the atomic lock.
    | MUST be a store that supports atomic locks across instances (Redis,
    | DynamoDB, Memcached). `array` / `file` stores are unsafe and refused.
    |
    */
    'store' => env('IDEMPOTENCY_STORE', 'redis'),

    /*
    |--------------------------------------------------------------------------
    | Key Prefix
    |--------------------------------------------------------------------------
    */
    'prefix' => env('IDEMPOTENCY_PREFIX', 'idem'),

    /*
    |--------------------------------------------------------------------------
    | Key Format Validation (OWASP A03 — Injection)
    |--------------------------------------------------------------------------
    |
    | Strict allow-list pattern applied to the raw header value before it
    | ever touches the cache backend. Rejects control chars, CRLF, and
    | anything outside the allow-listed character set.
    |
    */
    'key' => [
        'min'     => 8,
        'max'     => 255,
        'pattern' => '/^[A-Za-z0-9_\-:.]{8,255}$/',
    ],

    /*
    |--------------------------------------------------------------------------
    | Replay Policy
    |--------------------------------------------------------------------------
    |
    | Which response status codes should be cached and replayed. By default
    | only 2xx and 4xx (client-attributable) responses are stored — 5xx
    | failures are NOT replayed so the client can legitimately retry after
    | a transient server fault.
    |
    */
    'cache_status_codes' => [
        'min' => 200,
        'max' => 499,
    ],

    /*
    |--------------------------------------------------------------------------
    | Response Body Size Limit
    |--------------------------------------------------------------------------
    |
    | Maximum response body (in bytes) that will be cached. Larger
    | responses bypass caching to avoid pathological Redis memory usage.
    |
    */
    'max_body_bytes' => (int) env('IDEMPOTENCY_MAX_BODY', 1_048_576),

    /*
    |--------------------------------------------------------------------------
    | Max Keys Per Scope (DoS guard)
    |--------------------------------------------------------------------------
    |
    | Maximum number of distinct idempotency keys a single scope (authenticated
    | user, else session) may register within one TTL window. Exceeding it
    | returns 429. Bounds Redis memory and blunts a key-flood DoS. Set to 0 to
    | disable the cap entirely.
    |
    */
    'max_keys_per_user' => (int) env('IDEMPOTENCY_MAX_KEYS_PER_USER', 1_000),

    /*
    |--------------------------------------------------------------------------
    | Logging Channel (OWASP A09)
    |--------------------------------------------------------------------------
    |
    | Channel used to record key lifecycle events. Sensitive payload data
    | is NEVER written — only key fingerprint, user id, and outcome.
    |
    */
    'log_channel' => env('IDEMPOTENCY_LOG_CHANNEL', 'stack'),

];
