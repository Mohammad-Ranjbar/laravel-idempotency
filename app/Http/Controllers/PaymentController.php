<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

/**
 * Example controller demonstrating use of the `idempotent` middleware.
 *
 * Note that the controller itself does NOT need to know anything about
 * idempotency — the middleware handles fingerprinting, locking, replay,
 * and conflict detection transparently. Every action below produces a
 * fresh DB write on first call and a replayed response on retry.
 */
final class PaymentController extends Controller
{
    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'amount'   => ['required', 'integer', 'min:1', 'max:1_000_000_00'],
            'currency' => ['required', 'string', 'size:3', Rule::in(['USD', 'EUR', 'GBP'])],
        ]);

        // Real implementation would persist + charge a PSP here. The
        // middleware guarantees this block runs at most once per
        // (user, Idempotency-Key) pair.
        $paymentId = (string) Str::ulid();

        return new JsonResponse(
            [
                'id'       => $paymentId,
                'amount'   => $data['amount'],
                'currency' => $data['currency'],
                'status'   => 'captured',
            ],
            201,
        );
    }

    public function destroy(string $id): JsonResponse
    {
        // DELETE is inherently idempotent at the resource level, but
        // middleware-level idempotency still protects against the
        // "delete + immediate replay returns 404 instead of 204" race.
        return new JsonResponse(['id' => $id, 'status' => 'deleted'], 200);
    }
}
