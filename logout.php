<?php
declare(strict_types=1);
require_once __DIR__ . '/server/includes/bootstrap.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    fa_security_error_page(403);
}
verify_csrf();
$userId = isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : null;
if ($userId) audit($pdo, $userId, 'LOGOUT', 'User signed out');
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $params['path'] ?: '/',
        'domain' => $params['domain'] ?? '',
        'secure' => (bool)$params['secure'],
        'httponly' => (bool)$params['httponly'],
        'samesite' => (string)($params['samesite'] ?? 'Lax'),
    ]);
}
session_destroy();
header('Location: /index.html', true, 303);
exit;