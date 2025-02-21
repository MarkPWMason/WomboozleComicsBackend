<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class UserController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'username' => 'required|string|regex:/\w*$/|max:255|exists:users,username',
            'password' => 'required',
        ]);

        if (!Auth::attempt($request->only('username', 'password'))) {
            return response([
                'status' => false,
                'message' => 'Invalid Credentials'
            ], 500);
        }

        $user = User::where('username', $request->username)->first();
        if (!$user || !Hash::check($request->password, $user->password)) {
            return [
                'message' => 'The Provided credentials are incorrect'
            ];
        }

        $token = $user->createToken($user->username)->plainTextToken;

        // Set the token in an HTTPOnly cookie
        $cookie = cookie('auth_token', $token, 60, null, null, false, true); // 7 days

        return response([
            'user' => $user,
            'token' => $token
        ])->withCookie($cookie);
    }

    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'username' => 'required|string|regex:/\w*$/|max:255|unique:users,username',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|confirmed',
        ]);

        $user = User::create($validatedData);

        $token = $user->createToken($request->username)->plainTextToken;

        // Set the token in an HTTPOnly cookie
        $cookie = cookie('auth_token', $token, 60, null, null, false, true); // 7 days

        return response([
            'user' => $user,
            'token' => $token
        ])->withCookie($cookie);
    }
    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        // Clear the HTTPOnly cookie
        $cookie = cookie()->forget('auth_token');

        return response([
            'message' => 'You are logged out'
        ])->withCookie($cookie);
    }
}
