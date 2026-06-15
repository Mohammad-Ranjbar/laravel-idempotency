<?php

declare(strict_types=1);

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
|--------------------------------------------------------------------------
| Idempotency middleware feature suite
|--------------------------------------------------------------------------
|
| Exercises the EnsureIdempotency middleware end-to-end through the example
| /api/payments endpoints: key validation, replay, fingerprint conflict,
| canonicalization (object-key order vs. array-element order), per-scope
| isolation, and the per-scope key-count cap.
|
*/

beforeEach(function (): void {
    // The default redis store isn't available in CI; the array store
    // supports the atomic locks the middleware relies on.
    config()->set('idempotency.store', 'array');
    config()->set('idempotency.max_keys_per_user', 1_000);

    cache()->store('array')->flush();
});

/** A syntactically valid Idempotency-Key (matches the config allow-list). */
function idemKey(string $suffix = 'alpha'): string
{
    return 'idem-key-'.$suffix;
}

/** A valid payment payload the example controller accepts. */
function payment(array $overrides = []): array
{
    return array_merge(['amount' => 1_000, 'currency' => 'USD'], $overrides);
}

it('rejects a mutating request without an Idempotency-Key header', function (): void {
    $response = $this->postJson('/api/payments', payment());

    $response->assertStatus(400)
        ->assertJsonPath('error.code', 'idempotency_key_required');
});

it('rejects a malformed Idempotency-Key', function (): void {
    $response = $this->postJson('/api/payments', payment(), [
        'Idempotency-Key' => 'bad key!', // space + "!" are outside the allow-list
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error.code', 'idempotency_key_invalid');
});

it('executes the original request and stores the response', function (): void {
    $response = $this->postJson('/api/payments', payment(), [
        'Idempotency-Key' => idemKey(),
    ]);

    $response->assertStatus(201)
        ->assertJsonPath('status', 'captured');
    expect($response->headers->get('Idempotent-Replayed'))->toBeNull();
});

it('replays the cached response on an identical retry', function (): void {
    $headers = ['Idempotency-Key' => idemKey()];

    $first = $this->postJson('/api/payments', payment(), $headers);
    $second = $this->postJson('/api/payments', payment(), $headers);

    $first->assertStatus(201);
    $second->assertStatus(201);

    // Same generated payment id proves the controller ran only once.
    expect($second->json('id'))->toBe($first->json('id'));
    expect($second->headers->get('Idempotent-Replayed'))->toBe('true');
    expect($second->headers->get('Idempotency-Key'))->toBe(idemKey());
});

it('returns 409 when the same key is reused with a different payload', function (): void {
    $headers = ['Idempotency-Key' => idemKey()];

    $this->postJson('/api/payments', payment(['amount' => 1_000]), $headers)
        ->assertStatus(201);

    $this->postJson('/api/payments', payment(['amount' => 9_999]), $headers)
        ->assertStatus(409)
        ->assertJsonPath('error.code', 'idempotency_key_conflict');
});

it('canonicalizes object key order (member order is insignificant)', function (): void {
    $headers = ['Idempotency-Key' => idemKey()];

    $first = $this->postJson('/api/payments', ['amount' => 1_000, 'currency' => 'USD'], $headers);
    // Same data, keys in the opposite order — must fingerprint identically.
    $second = $this->postJson('/api/payments', ['currency' => 'USD', 'amount' => 1_000], $headers);

    $first->assertStatus(201);
    $second->assertStatus(201);
    expect($second->headers->get('Idempotent-Replayed'))->toBe('true');
    expect($second->json('id'))->toBe($first->json('id'));
});

it('treats array element order as significant (lists are not sorted)', function (): void {
    $headers = ['Idempotency-Key' => idemKey()];

    // `tags` is ignored by validation but still part of the fingerprint.
    $this->postJson('/api/payments', payment(['tags' => ['a', 'b', 'c']]), $headers)
        ->assertStatus(201);

    $this->postJson('/api/payments', payment(['tags' => ['c', 'b', 'a']]), $headers)
        ->assertStatus(409)
        ->assertJsonPath('error.code', 'idempotency_key_conflict');
});

it('preserves order for lists of 11+ elements without restructuring', function (): void {
    $headers = ['Idempotency-Key' => idemKey()];

    // 11 elements: a string-key sort would reorder index 10 before 2 and
    // re-encode the array as an object — the fix must keep it a list, so
    // an identical retry replays cleanly rather than conflicting.
    $eleven = range(1, 11);

    $first = $this->postJson('/api/payments', payment(['items' => $eleven]), $headers);
    $second = $this->postJson('/api/payments', payment(['items' => $eleven]), $headers);

    $first->assertStatus(201);
    $second->assertStatus(201);
    expect($second->headers->get('Idempotent-Replayed'))->toBe('true');
    expect($second->json('id'))->toBe($first->json('id'));
});

it('isolates idempotency records per authenticated user scope', function (): void {
    $alice = User::factory()->create();
    $bob = User::factory()->create();
    $headers = ['Idempotency-Key' => idemKey('shared')];

    $aliceResponse = $this->actingAs($alice)
        ->postJson('/api/payments', payment(['amount' => 1_000]), $headers);

    // Bob reuses the same key with a different payload: a different scope,
    // so it must NOT collide with Alice's record (no 409, fresh execution).
    $bobResponse = $this->actingAs($bob)
        ->postJson('/api/payments', payment(['amount' => 5_000]), $headers);

    $aliceResponse->assertStatus(201);
    $bobResponse->assertStatus(201);
    expect($bobResponse->headers->get('Idempotent-Replayed'))->toBeNull();
    expect($bobResponse->json('id'))->not->toBe($aliceResponse->json('id'));
});

it('enforces the max keys per user limit with a 429', function (): void {
    config()->set('idempotency.max_keys_per_user', 2);

    $this->postJson('/api/payments', payment(), ['Idempotency-Key' => idemKey('one')])
        ->assertStatus(201);
    $this->postJson('/api/payments', payment(), ['Idempotency-Key' => idemKey('two')])
        ->assertStatus(201);

    $response = $this->postJson('/api/payments', payment(), ['Idempotency-Key' => idemKey('three')]);

    $response->assertStatus(429)
        ->assertJsonPath('error.code', 'idempotency_key_limit_exceeded');
    expect($response->headers->get('Retry-After'))->not->toBeNull();
});

it('does not count a replayed key against the limit', function (): void {
    config()->set('idempotency.max_keys_per_user', 2);

    $headers = ['Idempotency-Key' => idemKey('repeat')];
    $this->postJson('/api/payments', payment(), $headers)->assertStatus(201);
    // Replaying the same key must not consume an additional slot.
    $this->postJson('/api/payments', payment(), $headers)->assertStatus(201);

    $this->postJson('/api/payments', payment(), ['Idempotency-Key' => idemKey('second')])
        ->assertStatus(201);
});
