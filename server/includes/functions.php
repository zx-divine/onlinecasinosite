<?php
declare(strict_types=1);

function e(mixed $value): string
{
    if (!is_scalar($value) && $value !== null) return '';
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $url): never
{
    // Only permit site-local destinations; never turn this helper into an open redirect.
    if ($url === '' || str_contains($url, "\r") || str_contains($url, "\n") || str_starts_with($url, '//')) {
        fa_security_error_page(400);
    }
    $parts = parse_url($url);
    if ($parts === false || isset($parts['scheme']) || isset($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
        fa_security_error_page(400);
    }
    header('Location: ' . $url, true, 303);
    exit;
}

function flash(string $type, string $message): void
{
    $allowedTypes = ['success', 'error', 'warning', 'info'];
    if (!in_array($type, $allowedTypes, true)) $type = 'info';
    $_SESSION['_flash'][] = ['type' => $type, 'message' => substr($message, 0, 1500)];
}

function take_flashes(): array
{
    $items = $_SESSION['_flash'] ?? [];
    unset($_SESSION['_flash']);
    return is_array($items) ? $items : [];
}

function csrf_token(): string
{
    $now = time();
    $policy = $GLOBALS['security']['csrf'] ?? [];
    $ttl = max(300, (int)($policy['token_ttl_seconds'] ?? 7200));
    $max = max(10, (int)($policy['max_tokens_per_session'] ?? 100));
    if (!isset($_SESSION['_csrf_tokens']) || !is_array($_SESSION['_csrf_tokens'])) $_SESSION['_csrf_tokens'] = [];
    foreach ($_SESSION['_csrf_tokens'] as $hash => $createdAt) {
        if (!is_int($createdAt) || $createdAt < $now - $ttl) unset($_SESSION['_csrf_tokens'][$hash]);
    }
    if (count($_SESSION['_csrf_tokens']) >= $max) {
        asort($_SESSION['_csrf_tokens'], SORT_NUMERIC);
        while (count($_SESSION['_csrf_tokens']) >= $max) {
            $oldest = array_key_first($_SESSION['_csrf_tokens']);
            if ($oldest === null) break;
            unset($_SESSION['_csrf_tokens'][$oldest]);
        }
    }
    $token = bin2hex(random_bytes(32));
    $_SESSION['_csrf_tokens'][hash('sha256', $token)] = $now;
    return $token;
}

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">';
}

function clear_csrf_tokens(): void
{
    $_SESSION['_csrf_tokens'] = [];
}

function verify_csrf(): void
{
    $rawToken = $_POST['_csrf'] ?? '';
    $token = is_string($rawToken) ? $rawToken : '';
    $hash = $token !== '' ? hash('sha256', $token) : '';
    $tokens = $_SESSION['_csrf_tokens'] ?? [];
    $createdAt = is_array($tokens) ? ($tokens[$hash] ?? null) : null;
    $ttl = max(300, (int)(($GLOBALS['security']['csrf']['token_ttl_seconds'] ?? 7200)));
    if ($hash === '' || !is_int($createdAt) || $createdAt < time() - $ttl) {
        error_log('[Fortune Apex security] Rejected a state-changing request with a missing, expired or reused CSRF token.');
        fa_security_error_page(403);
    }
    // One use only. A double submit needs a fresh form token.
    unset($_SESSION['_csrf_tokens'][$hash]);
}

function current_user(PDO $pdo): ?array
{
    if (empty($_SESSION['uid'])) return null;
    $q = $pdo->prepare('SELECT id,username,display_name,email,role,is_owner,status,must_change_password,session_version FROM users WHERE id=? LIMIT 1');
    $q->execute([(int)$_SESSION['uid']]);
    $user = $q->fetch();
    if (!$user || $user['status'] !== 'active' || !isset($_SESSION['_fa_session_version']) || (int)$_SESSION['_fa_session_version'] !== (int)$user['session_version']) {
        unset($_SESSION['uid'], $_SESSION['_fa_session_version'], $_SESSION['prompt_approvals']);
        return null;
    }
    return $user;
}

function require_login(PDO $pdo): array
{
    $user = current_user($pdo);
    if (!$user) {
        flash('info', 'Log in to continue.');
        redirect('/login.php');
    }
    if (!empty($user['must_change_password']) && basename((string)($_SERVER['PHP_SELF'] ?? '')) !== 'change-password.php') {
        flash('warning', 'Change your temporary password before continuing.');
        redirect('/change-password.php');
    }
    return $user;
}

function require_admin(PDO $pdo): array
{
    $user = require_login($pdo);
    if (($user['role'] ?? '') !== 'admin') {
        audit($pdo, (int)$user['id'], 'ACCESS_DENIED', 'A non-admin account attempted to access an administrator route.');
        fa_security_error_page(403);
    }
    return $user;
}

function limited(PDO $pdo, string $key, int $max = 8, int $window = 900): bool
{
    $max = max(1, min($max, 1000));
    $window = max(1, min($window, 86400));
    $rateKey = hash('sha256', $key);
    // Bounded periodic cleanup prevents unique-IP attempts from growing this table forever.
    try {
        if (random_int(1, 100) === 1) {
            $pdo->exec("DELETE FROM rate_limits WHERE window_started_at < DATE_SUB(NOW(), INTERVAL 2 DAY)");
        }
    } catch (Throwable $cleanupException) {
        // Cleanup is best-effort; the actual limit remains fail-closed below.
    }
    try {
        // Serialize requests for a key so concurrent requests cannot all pass the same count.
        $pdo->beginTransaction();
        $insert = $pdo->prepare('INSERT INTO rate_limits(rate_key,hit_count,window_started_at) VALUES(?,0,NOW()) ON DUPLICATE KEY UPDATE rate_key=VALUES(rate_key)');
        $insert->execute([$rateKey]);
        $query = $pdo->prepare('SELECT hit_count, UNIX_TIMESTAMP(window_started_at) AS window_epoch FROM rate_limits WHERE rate_key=? LIMIT 1 FOR UPDATE');
        $query->execute([$rateKey]);
        $row = $query->fetch();
        if (!$row) throw new RuntimeException('Rate-limit state could not be read.');
        if ((int)$row['window_epoch'] < time() - $window) {
            $pdo->prepare('UPDATE rate_limits SET hit_count=1,window_started_at=NOW() WHERE rate_key=?')->execute([$rateKey]);
            $pdo->commit();
            return false;
        }
        if ((int)$row['hit_count'] >= $max) {
            $pdo->commit();
            return true;
        }
        $pdo->prepare('UPDATE rate_limits SET hit_count=hit_count+1 WHERE rate_key=?')->execute([$rateKey]);
        $pdo->commit();
        return false;
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log('[Fortune Apex security] Rate-limit storage is unavailable (' . get_class($exception) . ', code ' . (string)$exception->getCode() . ').');
        return true; // Fail closed rather than silently disable brute-force protection.
    }
}

function audit(PDO $pdo, ?int $actor, string $action, string $details = ''): void
{
    $safeAction = preg_replace('/[^A-Z0-9_.-]/i', '_', substr($action, 0, 100)) ?: 'EVENT';
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) $ip = '';
    try {
        $query = $pdo->prepare('INSERT INTO audit_log(actor_user_id,action,details,ip_address,created_at) VALUES(?,?,?,?,NOW())');
        $query->execute([$actor, $safeAction, substr($details, 0, 1000), substr($ip, 0, 45)]);
    } catch (Throwable $exception) {
        error_log('[Fortune Apex audit] Audit storage failed (' . get_class($exception) . ', code ' . (string)$exception->getCode() . ').');
    }
}

function app_url(array $config, string $path = ''): string
{
    $base = rtrim((string)($config['base_url'] ?? ''), '/');
    $parts = parse_url($base);
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https' || empty($parts['host'])) {
        throw new RuntimeException('The application base URL is invalid.');
    }
    if (str_contains($path, "\r") || str_contains($path, "\n") || str_starts_with($path, '//')) {
        throw new RuntimeException('Invalid local URL path.');
    }
    return $base . '/' . ltrim($path, '/');
}

function setting(PDO $pdo, string $key, string $fallback = ''): string
{
    $query = $pdo->prepare('SELECT setting_value FROM settings WHERE setting_key=?');
    $query->execute([$key]);
    $value = $query->fetchColumn();
    return $value === false ? $fallback : (string)$value;
}

function post_string(string $key, int $max = 4000): string
{
    $raw = $_POST[$key] ?? '';
    if (!is_string($raw)) return '';
    $value = trim(str_replace("\0", '', $raw));
    return function_exists('mb_substr') ? mb_substr($value, 0, $max, 'UTF-8') : substr($value, 0, $max);
}

/** Read a secret/form field without trimming or casting malicious arrays to strings. */
function post_raw_string(string $key, int $max = 1024): string
{
    $raw = $_POST[$key] ?? '';
    if (!is_string($raw) || strlen($raw) > $max || str_contains($raw, "\0")) return '';
    return $raw;
}

function valid_password(string $password): bool
{
    $policy = $GLOBALS['security']['password'] ?? [];
    $minimum = max(6, (int)($policy['minimum_length_bytes'] ?? 6));
    $maximum = min(1024, max($minimum, (int)($policy['maximum_length_bytes'] ?? 200)));
    $length = strlen($password);
    return $length >= $minimum && $length <= $maximum && !str_contains($password, "\0");
}

function password_hash_secure(string $password): string
{
    $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    $hash = password_hash($password, $algorithm);
    if (!is_string($hash) || $hash === '') throw new RuntimeException('Password hashing failed.');
    return $hash;
}

function password_rehash_needed(string $hash): bool
{
    $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    return password_needs_rehash($hash, $algorithm);
}

function mail_admin(PDO $pdo, array $config, string $subject, string $body): bool
{
    $to = (string)($config['mail']['admin_email'] ?? '');
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return false;
    try {
        send_app_mail($config, $to, $subject, $body);
        return true;
    } catch (Throwable $exception) {
        error_log('[Fortune Apex mail] Delivery failed (' . get_class($exception) . ', code ' . (string)$exception->getCode() . ').');
        return false;
    }
}