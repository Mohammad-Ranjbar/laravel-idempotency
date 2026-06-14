<?php

declare(strict_types=1);

namespace App\Services\Idempotency;

use Illuminate\Http\Request;

/**
 * Deterministic SHA-256 fingerprint for an HTTP request.
 *
 * The fingerprint protects against the "same key / different payload" attack
 * vector (OWASP A08 — Software & Data Integrity Failures) by detecting any
 * divergence in method, URL, query string, or body between an original and
 * a retried request reusing the same Idempotency-Key.
 */
final class RequestFingerprint
{
    public function for(Request $request): string
    {
        $payload = [
            'method' => strtoupper($request->getMethod()),
            'url'    => $this->normalizeUrl($request),
            'body'   => $this->normalizeBody($request),
        ];

        $canonical = json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );

        return hash('sha256', $canonical);
    }

    /**
     * Scheme + host + path + sorted query parameters. Fragment is ignored
     * (never reaches the server) and host casing is normalized.
     */
    private function normalizeUrl(Request $request): string
    {
        $query = $request->query();

        if (is_array($query)) {
            $query = $this->recursiveKsort($query);
        }

        $queryString = is_array($query) && $query !== []
            ? '?'.http_build_query($query, '', '&', PHP_QUERY_RFC3986)
            : '';

        return strtolower($request->getSchemeAndHttpHost()).$request->getPathInfo().$queryString;
    }

    /**
     * @return array<string,mixed>|string
     */
    private function normalizeBody(Request $request): array|string
    {
        // Prefer the parsed JSON / form body — semantics over byte layout.
        $body = $request->all();

        if ($body === [] && $request->getContent() !== '') {
            // Non-JSON / non-form payload (e.g. raw text, binary). Hash the
            // raw bytes so we still detect tampering, but never echo them.
            return hash('sha256', $request->getContent());
        }

        return $this->recursiveKsort($body);
    }

    /**
     * @param  array<array-key,mixed>  $data
     * @return array<array-key,mixed>
     */
    private function recursiveKsort(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->recursiveKsort($value);
            }
        }

        ksort($data, SORT_STRING);

        return $data;
    }
}
