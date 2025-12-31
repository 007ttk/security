<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Compliance\Middleware;

use ArtisanPackUI\Security\Compliance\Minimization\DataMinimizerService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class DataMinimizationMiddleware
{
    public function __construct(protected DataMinimizerService $minimizer) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, string $purpose): Response
    {
        // Validate collection if configured
        if (config('security-compliance.compliance.minimization.enforce_collection_policies', true)) {
            $validation = $this->minimizer->validateCollection(
                $request->all(),
                $purpose
            );

            if (! $validation->isValid) {
                return response()->json([
                    'error' => 'data_minimization_violation',
                    'message' => 'Request contains prohibited or unnecessary data.',
                    'errors' => $validation->errors,
                ], 422);
            }

            // Filter request data to allowed fields only
            $filteredData = $this->minimizer->applyCollectionPolicy(
                $request->all(),
                $purpose
            );

            $request->replace($filteredData);
        }

        return $next($request);
    }
}
