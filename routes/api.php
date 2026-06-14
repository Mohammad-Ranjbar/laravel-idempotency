<?php

declare(strict_types=1);

use App\Http\Controllers\PaymentController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Example wiring: any mutating endpoint that needs exactly-once semantics
| simply chains the `idempotent` middleware alias. The alias resolves to
| App\Http\Middleware\EnsureIdempotency (registered in bootstrap/app.php).
|
*/

Route::middleware(['auth:sanctum', 'idempotent'])->group(function (): void {
    Route::post('/payments', [PaymentController::class, 'store']);
    Route::delete('/payments/{id}', [PaymentController::class, 'destroy']);
});
