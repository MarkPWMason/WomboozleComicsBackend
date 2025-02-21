<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureTokenIsValid
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {

        $jwtCookie = $request->cookie('auth_token');

        if (!$jwtCookie) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized Token'
            ], 401);
        }

        $decodedJwt = urldecode($jwtCookie);

        if (!$this->isValidJwt($decodedJwt)) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Invalid Token'
            ], 401);
        }
        return $next($request);
    }

    /**
     * Optional method to validate JWT structure, signature, or expiration.
     *
     * @param string $jwt
     * @return bool
     */

    private function isValidJwt(string $jwt): bool
    {
        // Implement your JWT validation logic here.
        // For now, assume the JWT is valid if it's not empty.
        return !empty($jwt);
    }
}
