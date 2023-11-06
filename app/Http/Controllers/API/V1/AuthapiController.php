<?php

namespace App\Http\Controllers\API\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Laravel\Sanctum\Sanctum;

class AuthapiController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json(['message' => 'User registered successfully'], 201);
    }

    public function login(Request $request)
    {
//        $credentials = $request->only('email', 'password');
//
//        if (Auth::attempt($credentials)) {
//            $user = Auth::user();
//            $token = $user->createToken('Sage - PED')->accessToken;
//
//            return response()->json(['token' => $token], 200);
//        } else {
//            return response()->json(['message' => 'Unauthorized'], 401);
//        }

//        return response()->json(['message' => 'Am working'], 201);

        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (Auth::attempt($request->only('email', 'password'))) {
            $user = Auth::user();
            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json(['token' => $token], 200);
        }

//        throw ValidationException::withMessages(['email' => 'Invalid login credentials']);
     else {
            return response()->json(['message' => 'Unauthorized'], 401);
        }
    }


    public function testapi(){
        return response()->json(['message' => 'Am working'], 201);
    }
}
