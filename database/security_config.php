<?php
declare(strict_types=1);
// Security policy values. No credentials or person-specific information belong here.
return [
    'headers' => [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'no-referrer',
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()',
        'Cross-Origin-Opener-Policy' => 'same-origin',
        'Cross-Origin-Resource-Policy' => 'same-origin',
        'Content-Security-Policy' => "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; upgrade-insecure-requests",
    ],
    'session' => [
        'name' => 'FA_SESSION',
        'idle_timeout_seconds' => 1800,
        'absolute_timeout_seconds' => 43200,
        'cookie_lifetime_seconds' => 0,
        'same_site' => 'Lax',
        'secure_cookie' => true,
        'http_only_cookie' => true,
    ],
    'csrf' => [
        'token_ttl_seconds' => 7200,
        'max_tokens_per_session' => 100,
    ],
    'rate_limits' => [
        'login_ip_max' => 10,
        'login_ip_window_seconds' => 900,
        'login_identity_max' => 6,
        'login_identity_window_seconds' => 900,
        'registration_max' => 5,
        'registration_window_seconds' => 3600,
        'forgot_password_max' => 5,
        'forgot_password_window_seconds' => 3600,
    ],
    'password' => [
        'minimum_length_bytes' => 6,
        'maximum_length_bytes' => 200,
    ],
];