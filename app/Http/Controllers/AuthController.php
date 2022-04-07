<?php

namespace App\Http\Controllers;

use Validator;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use App\Http\Resources\User as UserResource;

class AuthController extends Controller
{
    public function register(Request $request)
        
    {
        $validatedData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
            'confirm_password' => 'required|same:password',
        ]);
        
        $user = User::create([
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => Hash::make($validatedData['password']),
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;
        
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }
    
    public function login(Request $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'message' => 'Invalid login details'
            ], 401);
        }
        
        $user = User::where('email', $request['email'])->firstOrFail();
        
        $token = $user->createToken('auth_token')->plainTextToken;
        
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
        
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Tokens Revoked'
        ];
    }

    public function index()
    {
        $users = User::all();
        return response()->json([
            UserResource::collection($users)
        ]);
    }

    public function destroy(User $user)
    {   
        $user->delete();
        return response()->json([
            "User deleted"
        ]);
    }

    public function show($id)
    {
        $user = User::find($id);
        if (is_null($user)) {
            return $this->sendError('Post does not exist.');
        }
        return response()->json([new UserResource($user), 'Post fetched.']);
    }

    public function update(Request $request, User $user)
    {
        $input = $request->all();

        $validator = Validator::make($input, [
            'name' => 'string|max:255',
            'email' => 'string|email|max:255|unique:users',
            'password' => 'string|min:8',
            'confirm_password' => 'same:password'
        ]);

        if($validator->fails()){
            return response()->json([$validator->errors()]);       
        }

        if (isset($input['name'])){
            $user->name = $input['name'];
        }

        if (isset($input['email'])){
            $user->email = $input['email'];
        }

        if (isset($input['password'])){
            $user->password = $input['password'];
        }

        $user->save();
        
        return response()->json([new UserResource($user), 'Post updated.']);
    }
}
