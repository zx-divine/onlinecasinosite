<?php
declare(strict_types=1);
// Loaded only by server-side PHP after database/.htaccess has been installed.
if (!isset($config) || !is_array($config) || !isset($config['db']) || !is_array($config['db'])) {
    throw new RuntimeException('Database configuration is unavailable.');
}
$db = $config['db'];
$host = (string)($db['host'] ?? '');
$name = (string)($db['name'] ?? '');
$user = (string)($db['user'] ?? '');
$pass = (string)($db['pass'] ?? '');
$charset = (string)($db['charset'] ?? 'utf8mb4');
if (!preg_match('/^[A-Za-z0-9.-]{1,190}$/', $host) ||
    !preg_match('/^[A-Za-z0-9_]{1,190}$/', $name) ||
    !preg_match('/^[A-Za-z0-9_]{1,190}$/', $user) ||
    !in_array($charset, ['utf8mb4', 'utf8'], true) || $pass === '') {
    throw new RuntimeException('Database configuration validation failed.');
}
$dsn = 'mysql:host=' . $host . ';port=3306;dbname=' . $name . ';charset=' . $charset;
return new PDO($dsn, $user, $pass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::ATTR_TIMEOUT => 8,
]);