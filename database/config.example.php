<?php
declare(strict_types=1);
// Copy to /database/config.php privately and fill in real values there.
// This safe example intentionally has no working credentials or setup key.
return [
    'app_name' => 'FORTUNE APEX',
    'base_url' => 'https://your-domain.example',
    'timezone' => 'Asia/Kolkata',
    'setup_key' => 'REPLACE_WITH_A_LONG_RANDOM_VALUE',
    'db' => [
        'host' => 'mysql.example.invalid',
        'name' => 'database_name',
        'user' => 'database_user',
        'pass' => 'REPLACE_WITH_DATABASE_PASSWORD',
        'charset' => 'utf8mb4',
    ],
    'mail' => [
        'host' => 'smtp.gmail.com',
        'port' => 587,
        'encryption' => 'tls',
        'username' => 'you@example.com',
        'password' => 'REPLACE_WITH_EMAIL_APP_PASSWORD',
        'from_email' => 'you@example.com',
        'from_name' => 'Fortune Apex',
        'admin_email' => 'you@example.com',
    ],
];