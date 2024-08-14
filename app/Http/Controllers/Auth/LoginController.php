<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Validation\ValidationException;

use Illuminate\Http\Request;

use function Laravel\Prompts\password;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    // private $fieldBd = 'email';

    
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->middleware('auth')->only('logout');
    }
    public function login(Request $request)
    {
        $this->validateLogin($request);

        // If the class is using the ThrottlesLogins trait, we can automatically throttle
        // the login attempts for this application. We'll key this by the username and
        // the IP address of the client making these requests into this application.
        if (method_exists($this, 'hasTooManyLoginAttempts') &&
            $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptLogin($request)) {
            if ($request->hasSession()) {
                $request->session()->put('auth.password_confirmed_at', time());
            }

            return $this->sendLoginResponse($request);
        }

        // If the login attempt was unsuccessful we will increment the number of attempts
        // to login and redirect the user back to the login form. Of course, when this
        // user surpasses their maximum number of attempts they will get locked out.
        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }
    protected function validateLogin(Request $request)
    {
        $request->validate([
            $this->username() => 'required|string',
            'password' => 'required|string|min:6',
        ], 

        [
            $this->username().'.required' => 'Tên đăng nhập bắt buộc phải nhập',
            $this->username().'.string' => 'Kiểu dữ liệu tên đăng nhập không hợp lệ',
            $this->username().'.email' => 'Tên phải đúng định dạng email', 
            'password.required' => 'Mật khẩu bắt buộc phải  nhập',
            'password.string' => 'Kiểu dữ liệu mật khẩu không hợp lệ',
            'password.min' => 'Mật khẩu phải từ :min  ký tự'
        ]
    );
    }

    protected function sendFailedLoginResponse(Request $request)
    {
        throw ValidationException::withMessages([
            $this->username() => ['Tên đăng nhập hoặc mật khẩu không hợp lệ'],
        ]);
    }

    public function username()
    {
        // return $this->fieldBd;
        return 'username';
    }

    protected function credentials(Request $request)
    {
        if( filter_var($request -> username, FILTER_VALIDATE_EMAIL)){
            $fieldBd = 'email';
        } else {
            $fieldBd = 'username';
        }

        $dataArr = [    
            $fieldBd => $request -> username,
            'password' => $request -> password
        ];

        return $dataArr;
        // return $request->only($username, 'password');
    }
}
