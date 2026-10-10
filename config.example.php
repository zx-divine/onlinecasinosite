<?php
declare(strict_types=1);
/**
 * Safe example only. Copy this file to config.php on the server and edit it privately.
 * Never commit config.php or real credentials.
 */
return [
    'app_name' => 'FORTUNE APEX',
    'base_url' => 'https://your-domain.example',
    'timezone' => 'Asia/Kolkata',
    'setup_key' => 'CHANGE-THIS-TO-A-NEW-64-CHAR-RANDOM-HEX-STRING',
    'db' => [
        'host' => 'mysql.example.invalid',
        'name' => 'database_name',
        'user' => 'database_user',
        'pass' => 'ENTER_NEW_DATABASE_PASSWORD_HERE',
        'charset' => 'utf8mb4',
    ],
    'mail' => [
        'host' => 'smtp.gmail.com',
        'port' => 587,
        'encryption' => 'tls',
        'username' => 'you@example.com',
        'password' => 'ENTER_NEW_GOOGLE_APP_PASSWORD_HERE',
        'from_email' => 'you@example.com',
        'from_name' => 'Fortune Apex',
        'admin_email' => '',
    ],
];