<?php
declare(strict_types=1);
$configFile = dirname(__DIR__, 2) . '/config.php';
if (!is_file($configFile)) {
    http_response_code(500);
    exit('Setup needed: copy config.php from config.example.php and fill in your database settings.');
}
$config = require $configFile;
// Emit headers from PHP instead of .htaccess because some InfinityFree configurations reject Header directives.
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
}
date_default_timezone_set($config['timezone'] ?? 'UTC');
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('FA_SESSION');
    session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>$isHttps,'httponly'=>true,'samesite'=>'Lax']);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Lax');
    session_start();
    if (!empty($_SESSION['last_seen']) && time() - (int)$_SESSION['last_seen'] > 7200) { $_SESSION = []; session_regenerate_id(true); }
    $_SESSION['last_seen'] = time();
}
require_once __DIR__ . '/functions.php';
try {
    $db = $config['db'];
    $dsn = 'mysql:host='.$db['host'].';dbname='.$db['name'].';charset='.($db['charset'] ?? 'utf8mb4');
    $pdo = new PDO($dsn, $db['user'], $db['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (Throwable $e) {
    error_log('[Fortune Apex DB] '.$e->getMessage());
    http_response_code(503);
    exit('Fortune Apex is not connected to its database yet. Check config.php and follow README.md setup instructions.');
}
// Small forward-compatible migration: add the owner flag to installations created by an older build.
// Preserve an existing Owner flag; otherwise assign the earliest administrator as Owner on legacy installations.
try {
    $usersExists=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='users'")->fetchColumn()>0;
    if ($usersExists) {
        $ownerColumn=$pdo->query("SHOW COLUMNS FROM users LIKE 'is_owner'")->fetch();
        if (!$ownerColumn) $pdo->exec("ALTER TABLE users ADD COLUMN is_owner TINYINT(1) NOT NULL DEFAULT 0 AFTER role");
        if ((int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='admin' AND is_owner=1")->fetchColumn()===0) {
            $legacyOwner=$pdo->query("SELECT id FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1")->fetchColumn();
            if ($legacyOwner) { $qOwner=$pdo->prepare("UPDATE users SET is_owner=1 WHERE id=? AND role='admin'"); $qOwner->execute([(int)$legacyOwner]); }
        }
    }
} catch (Throwable $migrationError) {
    error_log('[Fortune Apex owner migration] '.$migrationError->getMessage());
    http_response_code(500);
    exit('Fortune Apex could not initialize the Owner access flag. Check database permissions and the hosting error log.');
}
require_once __DIR__ . '/mailer.php';