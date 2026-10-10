<?php
declare(strict_types=1);

// One-time installer. Keep this file only while initial Owner setup is being completed.
$faRoot = __DIR__;
$databaseDir = $faRoot . '/database';
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
$faSetupLogDir = $databaseDir . '/logs';
$faSetupLogFile = $faSetupLogDir . '/php_errors.log';
if (is_dir($faSetupLogDir) && is_writable($faSetupLogDir)) {
    if (is_file($faSetupLogFile) && (int)@filesize($faSetupLogFile) > 2 * 1024 * 1024) {
        @unlink($faSetupLogFile . '.3'); @rename($faSetupLogFile . '.2', $faSetupLogFile . '.3');
        @rename($faSetupLogFile . '.1', $faSetupLogFile . '.2'); @rename($faSetupLogFile, $faSetupLogFile . '.1');
    }
    @ini_set('error_log', $faSetupLogFile);
}

function fa_setup_error_page(int $status): never {
    if (!in_array($status, [400, 401, 403, 404, 500, 503], true)) $status = 500;
    http_response_code($status);
    if (!headers_sent()) {
        header('Cache-Control: no-store, max-age=0');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'");
    }
    $page = __DIR__ . '/' . $status . '.html';
    if (is_file($page) && is_readable($page)) readfile($page); else echo 'Request could not be completed.';
    exit;
}

$configFile = $databaseDir . '/config.php';
if (!is_file($configFile) || !is_readable($configFile)) {
    error_log('[Fortune Apex setup] Private configuration is missing or unreadable.');
    fa_setup_error_page(503);
}
$config = require $configFile;
$security = is_file($databaseDir . '/security_config.php') ? require $databaseDir . '/security_config.php' : [];
if (!is_array($config) || !isset($config['base_url'], $config['db'])) {
    error_log('[Fortune Apex setup] Private configuration failed validation.');
    fa_setup_error_page(503);
}
$baseUrl = (string)$config['base_url'];
$baseParts = parse_url($baseUrl);
if (!is_array($baseParts) || strtolower((string)($baseParts['scheme'] ?? '')) !== 'https' || empty($baseParts['host'])) {
    error_log('[Fortune Apex setup] Production base_url must be a valid HTTPS URL.');
    fa_setup_error_page(503);
}
$expectedHost = strtolower((string)$baseParts['host']);
$incomingHost = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
$incomingHostOnly = preg_replace('/:\d+$/', '', $incomingHost) ?? '';
if ($incomingHostOnly !== '' && $incomingHostOnly !== $expectedHost) {
    error_log('[Fortune Apex setup] Rejected an unexpected Host header.');
    fa_setup_error_page(400);
}
$isHttps = !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off';
if (!$isHttps && $incomingHostOnly === $expectedHost) {
    $requestUri = (string)($_SERVER['REQUEST_URI'] ?? '/setup.php');
    if ($requestUri === '' || $requestUri[0] !== '/' || str_starts_with($requestUri, '//') || str_contains($requestUri, "\r") || str_contains($requestUri, "\n")) $requestUri = '/setup.php';
    header('Location: ' . rtrim($baseUrl, '/') . $requestUri, true, 301);
    exit;
}
foreach (($security['headers'] ?? []) as $headerName => $headerValue) {
    if (is_string($headerName) && is_string($headerValue) && !headers_sent()) header($headerName . ': ' . $headerValue);
}
if ($isHttps && !headers_sent()) header('Strict-Transport-Security: max-age=15552000');
if (!headers_sent()) { header('Cache-Control: no-store, max-age=0'); header('Pragma: no-cache'); }
date_default_timezone_set((string)($config['timezone'] ?? 'Asia/Kolkata'));

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name((string)($security['session']['name'] ?? 'FA_SESSION'));
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => $isHttps,
        'httponly' => true, 'samesite' => 'Lax',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_start();
    $now = time();
    $last = (int)($_SESSION['_fa_setup_last_seen'] ?? $now);
    $created = (int)($_SESSION['_fa_setup_created'] ?? $now);
    if (($now - $last) > 1800 || ($now - $created) > 43200) {
        $_SESSION = [];
        session_regenerate_id(true);
        $created = $now;
    }
    $_SESSION['_fa_setup_created'] = $created;
    $_SESSION['_fa_setup_last_seen'] = $now;
}
if (empty($_SESSION['_fa_setup_csrf']) || empty($_SESSION['_fa_setup_csrf_at']) || time() - (int)$_SESSION['_fa_setup_csrf_at'] > 7200) {
    $_SESSION['_fa_setup_csrf'] = bin2hex(random_bytes(32));
    $_SESSION['_fa_setup_csrf_at'] = time();
}

function fa_setup_e(mixed $value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function fa_setup_post(string $key, int $limit = 200): string {
    $value = $_POST[$key] ?? '';
    if (!is_string($value)) return '';
    $value = trim(str_replace("\0", '', $value));
    return function_exists('mb_substr') ? mb_substr($value, 0, $limit, 'UTF-8') : substr($value, 0, $limit);
}
function fa_setup_is_placeholder(string $value): bool {
    return trim($value) === '' || str_contains($value, 'ENTER_NEW_DATABASE_PASSWORD_HERE') || str_contains($value, 'REPLACE_WITH') || str_contains($value, 'CHANGE-THIS');
}
function fa_setup_connection(array $db): PDO {
    $host = (string)($db['host'] ?? ''); $name = (string)($db['name'] ?? ''); $user = (string)($db['user'] ?? ''); $pass = (string)($db['pass'] ?? '');
    if (!preg_match('/^[A-Za-z0-9.-]{1,190}$/', $host) || !preg_match('/^[A-Za-z0-9_]{1,190}$/', $name) || !preg_match('/^[A-Za-z0-9_]{1,190}$/', $user) || $pass === '') throw new RuntimeException('Database configuration is incomplete.');
    $dsn = 'mysql:host=' . $host . ';port=3306;dbname=' . $name . ';charset=' . ($db['charset'] ?? 'utf8mb4');
    return new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>false, PDO::ATTR_TIMEOUT=>8]);
}

// Persistent setup-key attempt limit. Stores only a hash of REMOTE_ADDR, never the address itself.
function fa_setup_attempt_state(bool $failed = false, bool $success = false): bool {
    // Persistent lockout is required because the requested deployment key is intentionally retained.
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $key = hash('sha256', $ip);
    $dir = __DIR__ . '/database/keys';
    $file = $dir . '/setup-attempts.json';
    $now = time();
    if (!is_dir($dir) || !is_writable($dir)) {
        error_log('[Fortune Apex setup] Setup lockout storage is unavailable.');
        return false;
    }
    $fp = @fopen($file, 'c+');
    if (!is_resource($fp)) {
        error_log('[Fortune Apex setup] Setup lockout storage could not be opened.');
        return false;
    }
    try {
        if (!flock($fp, LOCK_EX)) return false;
        $stat = fstat($fp);
        if (is_array($stat) && (int)($stat['size'] ?? 0) > 1024 * 1024) {
            // Refuse an unexpectedly large lockout file instead of consuming unbounded memory.
            error_log('[Fortune Apex setup] Setup lockout state exceeded the safe size limit.');
            return false;
        }
        rewind($fp);
        $raw = stream_get_contents($fp);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)) $data = [];
        foreach ($data as $storedKey => $entry) {
            if (!is_array($entry) || $now - (int)($entry['start'] ?? 0) > 900) unset($data[$storedKey]);
        }
        $entry = $data[$key] ?? ['count' => 0, 'start' => $now];
        if ($success) {
            unset($data[$key]);
        } elseif ((int)($entry['count'] ?? 0) >= 5 && $now - (int)($entry['start'] ?? 0) <= 900) {
            // Persist pruned entries before refusing the request.
            ftruncate($fp, 0); rewind($fp);
            fwrite($fp, json_encode($data, JSON_THROW_ON_ERROR)); fflush($fp);
            @chmod($file, 0600);
            return false;
        } elseif ($failed) {
            if ($now - (int)($entry['start'] ?? 0) > 900) $entry = ['count' => 0, 'start' => $now];
            $entry['count'] = (int)($entry['count'] ?? 0) + 1;
            $entry['start'] = (int)($entry['start'] ?? $now);
            $data[$key] = $entry;
        }
        // Bound storage even if many distinct source addresses hit the setup page.
        if (count($data) > 2000) {
            uasort($data, static fn($a, $b) => (int)($a['start'] ?? 0) <=> (int)($b['start'] ?? 0));
            $data = array_slice($data, -2000, null, true);
        }
        ftruncate($fp, 0); rewind($fp);
        fwrite($fp, json_encode($data, JSON_THROW_ON_ERROR)); fflush($fp);
        @chmod($file, 0600);
        return true;
    } catch (Throwable $exception) {
        error_log('[Fortune Apex setup] Setup lockout state could not be updated.');
        return false;
    } finally {
        if (is_resource($fp)) { @flock($fp, LOCK_UN); fclose($fp); }
    }
}
function fa_setup_verify_key(string $submitted, array $config): bool {
    if (!fa_setup_attempt_state()) return false;
    $expected = (string)($config['setup_key'] ?? '');
    if ($expected === '' || fa_setup_is_placeholder($expected) || $submitted === '' || !hash_equals($expected, $submitted)) {
        fa_setup_attempt_state(true, false);
        return false;
    }
    fa_setup_attempt_state(false, true);
    return true;
}

require_once __DIR__ . '/server/includes/mailer.php';

$probeError = '';
$probe = null;
try {
    $dbNow = $config['db'] ?? [];
    if (!fa_setup_is_placeholder((string)($dbNow['pass'] ?? ''))) {
        $probe = fa_setup_connection($dbNow);
    } else {
        $probeError = 'Database password is not configured yet. Enter your current database password below.';
    }
} catch (Throwable $ex) {
    error_log('[Fortune Apex setup connection test] ' . get_class($ex) . ' / code ' . (string)$ex->getCode());
    $code = (string)$ex->getCode();
    if (str_contains($ex->getMessage(), '[1045]') || $code === '1045') {
        $probeError = 'MySQL rejected the credentials. Check the database password, username and database name.';
    } elseif (str_contains($ex->getMessage(), '[1049]') || $code === '1049') {
        $probeError = 'MySQL could not find that database name. Copy the exact name shown under MySQL Databases.';
    } elseif (str_contains($ex->getMessage(), '[2002]') || str_contains(strtolower($ex->getMessage()), 'getaddrinfo')) {
        $probeError = 'Could not reach that database host. Copy the exact MySQL Host Name from InfinityFree Control Panel.';
    } else {
        $probeError = 'The database connection failed. Re-check the host, database name, username and password.';
    }
}

if (!$probe instanceof PDO) {
    $wizardError = '';
    $values = [
        'db_host' => (string)($config['db']['host'] ?? ''),
        'db_name' => (string)($config['db']['name'] ?? ''),
        'db_user' => (string)($config['db']['user'] ?? ''),
        'mail_host' => (string)($config['mail']['host'] ?? 'smtp.gmail.com'),
        'mail_port' => (string)($config['mail']['port'] ?? '587'),
        'mail_encryption' => (string)($config['mail']['encryption'] ?? 'tls'),
        'mail_username' => (string)($config['mail']['username'] ?? ''),
        'mail_from_email' => (string)($config['mail']['from_email'] ?? ''),
        'mail_from_name' => (string)($config['mail']['from_name'] ?? 'Fortune Apex'),
        'mail_admin_email' => (string)($config['mail']['admin_email'] ?? ''),
    ];
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $postedCsrfRaw = $_POST['_fa_setup_csrf'] ?? '';
        $postedCsrf = is_string($postedCsrfRaw) ? $postedCsrfRaw : ''; 
        $setupKeyRaw = $_POST['setup_key'] ?? '';
        $setupKey = is_string($setupKeyRaw) ? $setupKeyRaw : '';
        if ($postedCsrf === '' || !hash_equals((string)$_SESSION['_fa_setup_csrf'], $postedCsrf)) {
            $wizardError = 'This setup form expired. Refresh the page and try again.';
        } elseif (!fa_setup_verify_key($setupKey, $config)) {
            $wizardError = 'The setup key did not match or the attempt limit has been reached. Wait 15 minutes before retrying.';
        } else {
            $values['db_host'] = fa_setup_post('db_host', 190);
            $values['db_name'] = fa_setup_post('db_name', 190);
            $values['db_user'] = fa_setup_post('db_user', 190);
            $dbPasswordRaw = $_POST['db_pass'] ?? '';
            $dbPassword = is_string($dbPasswordRaw) ? $dbPasswordRaw : ''; 
            $values['mail_host'] = fa_setup_post('mail_host', 190);
            $values['mail_port'] = fa_setup_post('mail_port', 5);
            $values['mail_encryption'] = fa_setup_post('mail_encryption', 10);
            $values['mail_username'] = strtolower(fa_setup_post('mail_username', 190));
            $mailPasswordRaw = $_POST['mail_password'] ?? '';
            $mailPassword = is_string($mailPasswordRaw) ? (preg_replace('/\s+/', '', $mailPasswordRaw) ?? '') : ''; 
            $values['mail_from_email'] = strtolower(fa_setup_post('mail_from_email', 190));
            $values['mail_from_name'] = fa_setup_post('mail_from_name', 100);
            $values['mail_admin_email'] = strtolower(fa_setup_post('mail_admin_email', 190));

            if (!preg_match('/^[A-Za-z0-9.-]{1,190}$/', $values['db_host']) || !preg_match('/^[A-Za-z0-9_]{1,190}$/', $values['db_name']) || !preg_match('/^[A-Za-z0-9_]{1,190}$/', $values['db_user'])) {
                $wizardError = 'Check the database host, database name and username formats.';
            } elseif ($dbPassword === '') {
                $wizardError = 'Enter the current database password. It is sent to this site over HTTPS and is not shown back to you.';
            } elseif ($mailPassword === '') {
                $wizardError = 'Enter a newly generated Google App Password so password-reset emails can be enabled during setup.';
            } elseif (!preg_match('/^[A-Za-z0-9.-]{1,190}$/', $values['mail_host'])) {
                $wizardError = 'Enter a valid SMTP host name.';
            } elseif (!in_array($values['mail_encryption'], ['tls','ssl'], true) || !ctype_digit($values['mail_port']) || (int)$values['mail_port'] < 1 || (int)$values['mail_port'] > 65535) {
                $wizardError = 'Check the SMTP port and encryption selection.';
            } elseif (!filter_var($values['mail_username'], FILTER_VALIDATE_EMAIL) || !filter_var($values['mail_from_email'], FILTER_VALIDATE_EMAIL) || !filter_var($values['mail_admin_email'], FILTER_VALIDATE_EMAIL)) {
                $wizardError = 'Enter valid email addresses for SMTP username, From email and admin notifications.';
            } else {
                $newConfig = $config;
                $newConfig['db'] = [
                    'host'=>$values['db_host'], 'name'=>$values['db_name'], 'user'=>$values['db_user'],
                    'pass'=>$dbPassword, 'charset'=>'utf8mb4'
                ];
                $newConfig['mail']['host'] = $values['mail_host'];
                $newConfig['mail']['port'] = (int)$values['mail_port'];
                $newConfig['mail']['encryption'] = $values['mail_encryption'];
                $newConfig['mail']['username'] = $values['mail_username'];
                $newConfig['mail']['from_email'] = $values['mail_from_email'];
                $newConfig['mail']['from_name'] = $values['mail_from_name'] !== '' ? $values['mail_from_name'] : 'Fortune Apex';
                $newConfig['mail']['admin_email'] = $values['mail_admin_email'];
                if ($mailPassword !== '') $newConfig['mail']['password'] = $mailPassword;
                $stage = 'database';
                try {
                    // Prove the DB settings before persisting any credentials.
                    $newPdo = fa_setup_connection($newConfig['db']);
                    $stage = 'smtp';
                    // Confirm SMTP authentication and delivery before saving the configuration.
                    send_app_mail(
                        $newConfig,
                        $values['mail_admin_email'],
                        'Fortune Apex email setup test',
                        "This test confirms that Fortune Apex can send email through the configured SMTP provider. If you received this message, password-reset email delivery is ready for the next installation step."
                    );
                    $stage = 'save';
                    $serialized = "<?php\ndeclare(strict_types=1);\n// Private deployment configuration. Do not upload this file publicly or commit it to Git.\nreturn " . var_export($newConfig, true) . ";\n";
                    $tmpConfig = $configFile . '.new';
                    if (file_put_contents($tmpConfig, $serialized, LOCK_EX) === false) {
                        throw new RuntimeException('The hosting server could not write a temporary config file.');
                    }
                    // Restrict the temporary file before it becomes the live config.
                    @chmod($tmpConfig, 0600);
                    if (!@rename($tmpConfig, $configFile)) {
                        @unlink($tmpConfig);
                        throw new RuntimeException('The hosting server could not update config.php. Check file permissions in File Manager.');
                    }
                    // Restrictive mode is best effort; never grant broad permissions like 0777.
                    @chmod($configFile, 0600);
                    // Use saved config only after write succeeded and set a success notice for the next page.
                    $_SESSION['_fa_db_configured'] = true;
                    $_SESSION['_fa_setup_csrf'] = bin2hex(random_bytes(32));
                    session_regenerate_id(true);
                    header('Location: setup.php', true, 303);
                    exit;
                } catch (Throwable $saveEx) {
                    error_log('[Fortune Apex setup save/probe] ' . get_class($saveEx) . ' / code ' . (string)$saveEx->getCode());
                    if ($saveEx instanceof PDOException) {
                        $message = $saveEx->getMessage();
                        if (str_contains($message, '[1045]') || (string)$saveEx->getCode() === '1045') $wizardError = 'The host was reached, but MySQL rejected the credentials. Check the password, username and database name.';
                        elseif (str_contains($message, '[1049]') || (string)$saveEx->getCode() === '1049') $wizardError = 'That database name was not found. Copy the exact MySQL DB Name from InfinityFree.';
                        elseif (str_contains($message, '[2002]') || str_contains(strtolower($message), 'getaddrinfo')) $wizardError = 'The database host could not be reached. Copy the exact MySQL Host Name from InfinityFree.';
                        else $wizardError = 'The database connection test failed. Re-check all database details in InfinityFree.';
                    } elseif ($stage === 'smtp') {
                        $wizardError = 'The database connected, but the SMTP test email failed. Check the new Google App Password, SMTP email address, and TLS/port settings; nothing was saved yet.';
                    } else {
                        $wizardError = 'The connection and email test worked, but private configuration could not be saved. Check file permissions in File Manager; do not use 777 permissions.';
                    }
                }
            }
        }
    }

    http_response_code(200);
    ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Connect Fortune Apex</title><link rel="stylesheet" href="assets/site.css"></head><body><main class="auth-wrap"><section class="auth-card"><div class="eyebrow">One-time deployment wizard</div><h1>Connect Fortune Apex</h1><p>The homepage is static, but login, admin tools and account features need a working database. Enter the details below once; you do not need to edit private configuration files manually.</p><div class="notice">Database connection status: <?=fa_setup_e($probeError)?><br>Use the exact values shown in your hosting control panel. This page must be accessed over HTTPS.</div><?php if ($wizardError !== ''): ?><div class="flash error"><?=fa_setup_e($wizardError)?></div><?php endif; ?><form method="post" autocomplete="off"><input type="hidden" name="_fa_setup_csrf" value="<?=fa_setup_e($_SESSION['_fa_setup_csrf'])?>"><label class="field">Private setup key<input type="password" name="setup_key" autocomplete="off" required></label><h2>Database connection</h2><label class="field">MySQL host<input name="db_host" value="<?=fa_setup_e($values['db_host'])?>" maxlength="190" required></label><div class="split"><label class="field">Database name<input name="db_name" value="<?=fa_setup_e($values['db_name'])?>" maxlength="190" required></label><label class="field">Database username<input name="db_user" value="<?=fa_setup_e($values['db_user'])?>" maxlength="190" required></label></div><label class="field">Current database password<input type="password" name="db_pass" autocomplete="new-password" required></label><h2>Email delivery <span class="hint">(tested now; required for password reset)</span></h2><div class="split"><label class="field">SMTP host<input name="mail_host" value="<?=fa_setup_e($values['mail_host'])?>" maxlength="190" required></label><label class="field">SMTP port<input type="number" name="mail_port" min="1" max="65535" value="<?=fa_setup_e($values['mail_port'])?>" required></label></div><div class="split"><label class="field">Encryption<select name="mail_encryption"><option value="tls" <?=$values['mail_encryption']==='tls'?'selected':''?>>TLS / STARTTLS</option><option value="ssl" <?=$values['mail_encryption']==='ssl'?'selected':''?>>SSL</option></select></label><label class="field">SMTP username<input type="email" name="mail_username" value="<?=fa_setup_e($values['mail_username'])?>" required></label></div><label class="field">New Google App Password<input type="password" name="mail_password" autocomplete="new-password" placeholder="Enter a new Google App Password" required></label><div class="split"><label class="field">From email<input type="email" name="mail_from_email" value="<?=fa_setup_e($values['mail_from_email'])?>" required></label><label class="field">Admin notification email<input type="email" name="mail_admin_email" value="<?=fa_setup_e($values['mail_admin_email'])?>" required></label></div><label class="field">Sender name<input name="mail_from_name" value="<?=fa_setup_e($values['mail_from_name'])?>" maxlength="100"></label><button class="btn gold" type="submit" name="save_connection" value="1">Test and save configuration</button></form><p class="hint">Database and SMTP credentials are saved only after both the database connection and a test email succeed. Use HTTPS. After the Owner account is created and tested, delete <code>setup.php</code> to close this installer.</p></section></main></body></html><?php
    exit;
}

// The credentials work now; use the normal application bootstrap and finish owner setup.
require_once __DIR__.'/server/includes/bootstrap.php';
$usersTableExists=(int)$pdo->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='users'")->fetchColumn()>0;
if ($usersTableExists) {
    try {
        if ((int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='admin'")->fetchColumn() > 0) {
            audit($pdo, null, 'INSTALL_BLOCKED_ALREADY_INITIALIZED', 'Installer opened after an administrator account already exists');
            flash('info', 'An Owner account already exists. Do not run first-time setup again. Sign in and remove setup.php from the server.');
            redirect('/login.php');
        }
    } catch (Throwable $e) {
        // A partial installation may not have all expected tables yet; the guarded setup flow below handles it.
    }
}
$error='';
$databaseConfiguredNotice = !empty($_SESSION['_fa_db_configured']);
unset($_SESSION['_fa_db_configured']);
if ($_SERVER['REQUEST_METHOD']==='POST') {
    verify_csrf();
    $key=post_string('setup_key',250);
    $username=post_string('username',32);
    $display=post_string('display_name',80);
    $email=strtolower(post_string('email',190));
    $pass=post_raw_string('password',200);
    $confirm=post_raw_string('confirm_password',200);
    if (!fa_setup_verify_key($key, $config)) $error='The setup key did not match or the attempt limit has been reached. Wait 15 minutes before retrying.';
    elseif (!preg_match('/^[A-Za-z0-9_.-]{3,32}$/',$username)) $error='Username must be 3–32 characters using letters, numbers, dots, underscores or hyphens.';
    elseif ($display==='' || !filter_var($email,FILTER_VALIDATE_EMAIL)) $error='Enter an Owner display name and valid email address.';
    elseif (!valid_password($pass) || $pass!==$confirm) $error='The Owner password and confirmation must match and contain at least 6 characters.';
    else {
        try {
            $sqls=[
              "CREATE TABLE IF NOT EXISTS users (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, username VARCHAR(32) NOT NULL UNIQUE, display_name VARCHAR(80) NOT NULL, email VARCHAR(190) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, role ENUM('admin','player') NOT NULL DEFAULT 'player', is_owner TINYINT(1) NOT NULL DEFAULT 0, session_version INT UNSIGNED NOT NULL DEFAULT 1, status ENUM('pending','active','rejected','suspended') NOT NULL DEFAULT 'pending', must_change_password TINYINT(1) NOT NULL DEFAULT 0, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, last_login_at DATETIME NULL, INDEX idx_users_status(status), INDEX idx_users_role(role)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS proposals (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL, title VARCHAR(120) NOT NULL, category VARCHAR(80) NOT NULL DEFAULT 'Other', details TEXT NOT NULL, status ENUM('PENDING','TESTING','APPROVED','REJECTED') NOT NULL DEFAULT 'PENDING', admin_notes TEXT NULL, reviewed_by BIGINT UNSIGNED NULL, reviewed_at DATETIME NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, INDEX idx_proposals_status(status), INDEX idx_proposals_user(user_id), CONSTRAINT fk_proposals_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS players (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NULL, display_name VARCHAR(80) NOT NULL, role_title VARCHAR(80) NOT NULL DEFAULT 'Player', rank_title VARCHAR(80) NOT NULL DEFAULT 'Unranked', fictional_balance INT NOT NULL DEFAULT 0, fortune_score INT NOT NULL DEFAULT 0, wins INT UNSIGNED NOT NULL DEFAULT 0, losses INT UNSIGNED NOT NULL DEFAULT 0, status VARCHAR(40) NOT NULL DEFAULT 'Active', visible TINYINT(1) NOT NULL DEFAULT 1, sort_order INT NOT NULL DEFAULT 100, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, UNIQUE KEY uq_players_user(user_id), INDEX idx_players_visible(visible), CONSTRAINT fk_players_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS systems (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, code VARCHAR(24) NOT NULL UNIQUE, name VARCHAR(120) NOT NULL, category VARCHAR(80) NOT NULL DEFAULT 'General', description TEXT NOT NULL, status ENUM('PROPOSED','ACTIVE','PAUSED','ARCHIVED') NOT NULL DEFAULT 'PROPOSED', sort_order INT NOT NULL DEFAULT 100, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, INDEX idx_systems_status(status)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS events (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, code VARCHAR(24) NOT NULL UNIQUE, title VARCHAR(120) NOT NULL, description TEXT NOT NULL, status ENUM('PROPOSED','PLANNED','LIVE','COMPLETED','CANCELLED') NOT NULL DEFAULT 'PROPOSED', starts_at DATETIME NULL, sort_order INT NOT NULL DEFAULT 100, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, INDEX idx_events_status(status)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS contact_messages (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(190) NOT NULL, subject VARCHAR(160) NOT NULL, message TEXT NOT NULL, status ENUM('NEW','READ','REPLIED','CLOSED') NOT NULL DEFAULT 'NEW', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_contact_status(status)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS password_resets (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL, token_hash CHAR(64) NOT NULL UNIQUE, expires_at DATETIME NOT NULL, used_at DATETIME NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_reset_expiry(expires_at), CONSTRAINT fk_reset_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS settings (setting_key VARCHAR(80) PRIMARY KEY, setting_value TEXT NOT NULL, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS audit_log (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, actor_user_id BIGINT UNSIGNED NULL, action VARCHAR(100) NOT NULL, details VARCHAR(1000) NOT NULL DEFAULT '', ip_address VARCHAR(45) NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_audit_created(created_at), INDEX idx_audit_actor(actor_user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS rate_limits (rate_key CHAR(64) PRIMARY KEY, hit_count INT UNSIGNED NOT NULL DEFAULT 0, window_started_at DATETIME NOT NULL, INDEX idx_rate_window(window_started_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
              "CREATE TABLE IF NOT EXISTS admin_approvals (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, requested_by BIGINT UNSIGNED NOT NULL, approver_user_id BIGINT UNSIGNED NOT NULL, action_type VARCHAR(60) NOT NULL, payload_json JSON NOT NULL, status ENUM('PENDING','APPROVED','REJECTED') NOT NULL DEFAULT 'PENDING', decision_note VARCHAR(1000) NOT NULL DEFAULT '', reviewed_by BIGINT UNSIGNED NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at DATETIME NULL, INDEX idx_approvals_recipient(approver_user_id,status,created_at), INDEX idx_approvals_requester(requested_by,created_at), CONSTRAINT fk_approvals_requester FOREIGN KEY(requested_by) REFERENCES users(id) ON DELETE CASCADE, CONSTRAINT fk_approvals_approver FOREIGN KEY(approver_user_id) REFERENCES users(id) ON DELETE CASCADE, CONSTRAINT fk_approvals_reviewer FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE SET NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"];
            foreach($sqls as $sql) $pdo->exec($sql);
            // A single initial Owner account is enough to initialize the site. Additional admin accounts
            // are created later only from the Owner-only Master Admin panel.
            if ((int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='admin'")->fetchColumn()>0) throw new RuntimeException('An admin already exists. Initial setup is locked.');
            $pdo->beginTransaction();
            $q=$pdo->prepare("INSERT INTO users(username,display_name,email,password_hash,role,is_owner,status,must_change_password) VALUES(?,?,?,?,'admin',1,'active',0)");
            $q->execute([$username,$display,$email,password_hash_secure($pass)]);
            $ownerId=(int)$pdo->lastInsertId();
            $defaults=[['site_tagline','A private community command center.'],['site_notice','Fortune Apex is a fictional, friend-run game using homemade currency. No real-money gambling or payments.']];
            $q=$pdo->prepare('INSERT IGNORE INTO settings(setting_key,setting_value) VALUES(?,?)'); foreach($defaults as $s)$q->execute($s);
            $seedPlayers=[]; // Do not seed any real or identifying personal roster data.
            $q=$pdo->prepare('INSERT IGNORE INTO players(display_name,role_title,rank_title,sort_order) VALUES(?,?,?,?)'); foreach($seedPlayers as $i=>$p)$q->execute([$p[0],$p[1],$p[2],$i*10]);
            $seedSystems=[['FA-SYS-001','Banking & Loans','Finance','Loan applications, fictional balances and transaction records are managed here.'],['FA-SYS-002','Insurance Department','Protection','Insurance tiers, coverage and claims are subject to admin-approved rules.'],['FA-SYS-003','Security & Penalties','Security','Disputes, fines, counterfeit reports and investigations need recorded decisions.'],['FA-SYS-004','Fortune Rankings','Player Systems','Player scores, rankings and achievements are admin-managed community stats.'],['FA-SYS-005','Proposal & Governance','Governance','Players submit ideas; only the admin can decide whether to accept, test or reject them.']];
            $q=$pdo->prepare("INSERT IGNORE INTO systems(code,name,category,description,status,sort_order) VALUES(?,?,?,?,'PROPOSED',?)"); foreach($seedSystems as $i=>$s)$q->execute([...$s,$i*10]);
            $seedEvents=[['FA-E-014','Lucky Hour','A proposed limited-time bonus event. Rules and payouts must be decided by the admin before activation.'],['FA-E-022','Market Crash','A proposed game-economy event; effects must be set by the admin before activation.'],['FA-E-031','Fortune Rush','A proposed community challenge event, awaiting admin decision.'],['FA-E-040','Bad Fortune','A proposed risk event, awaiting admin decision.']];
            $q=$pdo->prepare("INSERT IGNORE INTO events(code,title,description,status,sort_order) VALUES(?,?,?,'PROPOSED',?)"); foreach($seedEvents as $i=>$s)$q->execute([...$s,$i*10]);
            audit($pdo,$ownerId,'INSTALL','Initial Owner account and default Fortune Apex records created');
            $pdo->commit();
            flash('success','Fortune Apex is initialized with your Owner account. You can add another administrator later from Master Admin.');
            redirect('login.php');
        } catch(Throwable $ex) {
            if($pdo->inTransaction())$pdo->rollBack();
            error_log('[Fortune Apex setup] Installation failed (' . get_class($ex) . ', code ' . (string)$ex->getCode() . ').');
            $error=$ex instanceof RuntimeException ? $ex->getMessage() : 'Setup failed. Check database permissions and the private server configuration.';
        }
    }
}
require_once __DIR__.'/server/includes/view.php'; page_header($config,null,'First-time setup'); ?>
<section class="auth-wrap"><div class="auth-card"><div class="eyebrow">One-time installer · Owner only</div><h1>Initialize Fortune Apex</h1><p>Create the database tables and your Owner account first. A second administrator does not need to be configured during installation; the Owner can add one later from the Master Admin panel.</p><div class="notice">Use the private setup key configured on the server. This first step creates only one administrator: the Owner. Public registrations remain player accounts and cannot grant themselves admin permissions.</div><?php if($databaseConfiguredNotice): ?><div class="flash success">Database connection tested and configuration saved. Now create your Owner account below.</div><?php endif; ?><?php if($error): ?><div class="flash error"><?=e($error)?></div><?php endif; ?><form method="post"><?=csrf_field()?><label class="field">Private setup key<input type="password" name="setup_key" autocomplete="off" required></label><h2>Owner account</h2><div class="split"><label class="field">Username<input name="username" value="owner" maxlength="32" pattern="[A-Za-z0-9_.-]{3,32}" autocomplete="username" required></label><label class="field">Display name<input name="display_name" maxlength="80" value="Owner" required></label></div><label class="field">Your email address<input type="email" name="email" maxlength="190" value="" autocomplete="email" required></label><div class="split"><label class="field">Password<input type="password" name="password" minlength="6" autocomplete="new-password" required></label><label class="field">Confirm password<input type="password" name="confirm_password" minlength="6" autocomplete="new-password" required></label></div><button class="btn gold" type="submit">Create Owner account and database</button></form><p class="hint">After setup, log in with this Owner account, then use <b>Master Admin</b> to create a separate administrator account when ready.</p></div></section><?php page_footer(); ?>