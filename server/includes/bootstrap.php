<?php
declare(strict_types=1);

// Central entry point for every dynamic route. Configuration is outside the public source tree
// and served only through PHP; database/.htaccess blocks direct HTTP reads.
$faRoot = dirname(__DIR__, 2);
$faDatabaseDir = $faRoot . '/database';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// Keep application logs under the protected data directory where possible; rotate at 2 MiB.
$faLogDir = $faDatabaseDir . '/logs';
$faLogFile = $faLogDir . '/php_errors.log';
if (is_dir($faLogDir) && is_writable($faLogDir)) {
    if (is_file($faLogFile) && (int)@filesize($faLogFile) > 2 * 1024 * 1024) {
        @unlink($faLogFile . '.3'); @rename($faLogFile . '.2', $faLogFile . '.3');
        @rename($faLogFile . '.1', $faLogFile . '.2'); @rename($faLogFile, $faLogFile . '.1');
    }
    @ini_set('error_log', $faLogFile);
}

function fa_security_error_page(int $status): never
{
    $allowed = [400, 401, 403, 404, 500, 503];
    if (!in_array($status, $allowed, true)) $status = 500;
    if (!headers_sent()) {
        http_response_code($status);
        header('Cache-Control: no-store, max-age=0');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'");
    }
    $root = dirname(__DIR__, 2);
    $page = $root . '/' . $status . '.html';
    if (is_file($page) && is_readable($page)) {
        readfile($page);
    } else {
        echo 'Request could not be completed.';
    }
    exit;
}

if (!is_file($faDatabaseDir . '/env.php') || !is_file($faDatabaseDir . '/security_config.php')) {
    error_log('[Fortune Apex] Required private runtime files are missing.');
    fa_security_error_page(503);
}
$faEnv = require $faDatabaseDir . '/env.php';
$security = require $faDatabaseDir . '/security_config.php';
$configFile = $faDatabaseDir . '/config.php';
if (!is_file($configFile) || !is_readable($configFile)) {
    error_log('[Fortune Apex] Private deployment configuration is missing or unreadable.');
    fa_security_error_page(503);
}
$config = require $configFile;
if (!is_array($config) || !isset($config['db'], $config['base_url'])) {
    error_log('[Fortune Apex] Private deployment configuration failed validation.');
    fa_security_error_page(503);
}

$baseUrl = (string)$config['base_url'];
$baseParts = parse_url($baseUrl);
if (!is_array($baseParts) || strtolower((string)($baseParts['scheme'] ?? '')) !== 'https' || empty($baseParts['host'])) {
    error_log('[Fortune Apex] Production base_url must be a valid HTTPS URL.');
    fa_security_error_page(503);
}
$expectedHost = strtolower((string)$baseParts['host']);
$incomingHost = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
$incomingHostOnly = preg_replace('/:\d+$/', '', $incomingHost) ?? '';
if ($incomingHostOnly !== '' && $incomingHostOnly !== $expectedHost) {
    error_log('[Fortune Apex] Rejected a request with an unexpected Host header.');
    fa_security_error_page(400);
}
$isHttps = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off');
if (!$isHttps && $incomingHostOnly === $expectedHost) {
    $requestUri = (string)($_SERVER['REQUEST_URI'] ?? '/');
    if ($requestUri === '' || $requestUri[0] !== '/' || str_starts_with($requestUri, '//') || str_contains($requestUri, "\r") || str_contains($requestUri, "\n")) {
        $requestUri = '/';
    }
    header('Location: ' . rtrim($baseUrl, '/') . $requestUri, true, 301);
    exit;
}

foreach (($security['headers'] ?? []) as $headerName => $headerValue) {
    if (is_string($headerName) && is_string($headerValue) && !headers_sent()) {
        header($headerName . ': ' . $headerValue);
    }
}
if ($isHttps && !headers_sent()) {
    header('Strict-Transport-Security: max-age=15552000');
}
if (!headers_sent()) {
    header('Cache-Control: no-store, max-age=0');
    header('Pragma: no-cache');
}
date_default_timezone_set((string)($config['timezone'] ?? 'Asia/Kolkata'));

$sessionPolicy = $security['session'] ?? [];
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name((string)($sessionPolicy['name'] ?? 'FA_SESSION'));
    session_set_cookie_params([
        'lifetime' => (int)($sessionPolicy['cookie_lifetime_seconds'] ?? 0),
        'path' => '/',
        'secure' => $isHttps && !empty($sessionPolicy['secure_cookie']),
        'httponly' => !empty($sessionPolicy['http_only_cookie']),
        'samesite' => (string)($sessionPolicy['same_site'] ?? 'Lax'),
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', (string)($sessionPolicy['same_site'] ?? 'Lax'));
    session_start();
    $now = time();
    $idleTimeout = max(300, (int)($sessionPolicy['idle_timeout_seconds'] ?? 1800));
    $absoluteTimeout = max($idleTimeout, (int)($sessionPolicy['absolute_timeout_seconds'] ?? 43200));
    $expired = (!empty($_SESSION['_fa_last_seen']) && ($now - (int)$_SESSION['_fa_last_seen']) > $idleTimeout)
        || (!empty($_SESSION['_fa_created']) && ($now - (int)$_SESSION['_fa_created']) > $absoluteTimeout);
    if ($expired) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    if (empty($_SESSION['_fa_created'])) $_SESSION['_fa_created'] = $now;
    $_SESSION['_fa_last_seen'] = $now;
}

require_once __DIR__ . '/functions.php';
try {
    $pdo = require $faDatabaseDir . '/db_connect.php';
} catch (Throwable $dbError) {
    error_log('[Fortune Apex DB] Connection failed (' . get_class($dbError) . ', code ' . (string)$dbError->getCode() . ').');
    fa_security_error_page(503);
}

// Safe, backward-compatible schema migration for old installations. It runs only when
// the users table exists, changes no existing role, and assigns the first active admin as
// Owner only if the database has no Owner flagged yet.
try {
    $usersExists = (int)$pdo->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='users'")->fetchColumn() > 0;
    if ($usersExists) {
        $ownerColumn = $pdo->query("SHOW COLUMNS FROM users LIKE 'is_owner'")->fetch();
        if (!$ownerColumn) $pdo->exec("ALTER TABLE users ADD COLUMN is_owner TINYINT(1) NOT NULL DEFAULT 0 AFTER role");
        $sessionVersionColumn = $pdo->query("SHOW COLUMNS FROM users LIKE 'session_version'")->fetch();
        if (!$sessionVersionColumn) $pdo->exec("ALTER TABLE users ADD COLUMN session_version INT UNSIGNED NOT NULL DEFAULT 1 AFTER is_owner");
        if ((int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='admin' AND is_owner=1")->fetchColumn() === 0) {
            $legacyOwner = $pdo->query("SELECT id FROM users WHERE role='admin' AND status='active' ORDER BY id ASC LIMIT 1")->fetchColumn();
            if ($legacyOwner) {
                $ownerUpdate = $pdo->prepare("UPDATE users SET is_owner=1 WHERE id=? AND role='admin' AND status='active'");
                $ownerUpdate->execute([(int)$legacyOwner]);
            }
        }
    }
} catch (Throwable $migrationError) {
    error_log('[Fortune Apex migration] Owner access migration failed (' . get_class($migrationError) . ', code ' . (string)$migrationError->getCode() . ').');
    fa_security_error_page(500);
}
require_once __DIR__ . '/mailer.php';