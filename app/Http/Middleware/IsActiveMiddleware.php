<?php

namespace App\Http\Middleware;

use Closure;

/**
 * Inactive user is logged out
 */
class IsActiveMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if(auth()->user() and auth()->user()->status == 'I'){
            auth()->logout();
            return response()->json(['message' => 'Not authorized'], 403);
        }
        return $next($request);
    }
}