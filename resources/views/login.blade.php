<!DOCTYPE html>
<html>
<head>
    <title>Login - {{ config('app.name') }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 400px; 
            margin: 100px auto; 
            padding: 20px; 
            text-align: center;
        }
        .login-btn {
            display: inline-block;
            background: #0078d4;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 4px;
            margin: 20px 0;
        }
        .login-btn:hover { background: #106ebe; }
    </style>
</head>
<body>
    <h1>Welcome to {{ config('app.name') }}</h1>
    <p>Please sign in with your Microsoft account to continue.</p>
    
    <a href="{{ $loginUrl }}" class="login-btn">
        Sign in with Microsoft
    </a>
    
    <p><small>You'll be redirected to Microsoft to authenticate, then back here.</small></p>
</body>
</html>