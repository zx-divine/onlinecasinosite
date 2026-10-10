<?php
declare(strict_types=1);
function e(mixed $v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function redirect(string $url): never { header('Location: '.$url, true, 303); exit; }
function flash(string $type, string $message): void { $_SESSION['_flash'][] = ['type'=>$type,'message'=>$message]; }
function take_flashes(): array { $x=$_SESSION['_flash'] ?? []; unset($_SESSION['_flash']); return is_array($x)?$x:[]; }
function csrf_token(): string { if (empty($_SESSION['_csrf'])) $_SESSION['_csrf']=bin2hex(random_bytes(32)); return $_SESSION['_csrf']; }
function csrf_field(): string { return '<input type="hidden" name="_csrf" value="'.e(csrf_token()).'">'; }
function verify_csrf(): void { $v=(string)($_POST['_csrf'] ?? ''); if ($v==='' || !hash_equals((string)($_SESSION['_csrf'] ?? ''),$v)) { http_response_code(419); exit('Security check expired. Go back, refresh the page, and try again.'); } }
function current_user(PDO $pdo): ?array {
    if (empty($_SESSION['uid'])) return null;
    $q=$pdo->prepare('SELECT id,username,display_name,email,role,is_owner,status,must_change_password FROM users WHERE id=? LIMIT 1');
    $q->execute([(int)$_SESSION['uid']]); $u=$q->fetch();
    if (!$u || !in_array($u['status'], ['active'], true)) { unset($_SESSION['uid']); return null; }
    return $u;
}
function require_login(PDO $pdo): array { $u=current_user($pdo); if (!$u) { flash('info','Log in to continue.'); redirect('login.php'); } if (!empty($u['must_change_password']) && basename($_SERVER['PHP_SELF'] ?? '')!=='change-password.php') { flash('warning','Change your temporary password before continuing.'); redirect('change-password.php'); } return $u; }
function require_admin(PDO $pdo): array { $u=require_login($pdo); if ($u['role']!=='admin') { http_response_code(403); exit('Admin access only.'); } return $u; }
function limited(PDO $pdo, string $key, int $max=8, int $window=900): bool {
    // Database-backed limits survive new sessions and use a hash, not a raw IP address, as the key.
    $rk = hash('sha256', $key);
    $q = $pdo->prepare('SELECT hit_count, UNIX_TIMESTAMP(window_started_at) AS window_epoch FROM rate_limits WHERE rate_key=? LIMIT 1');
    $q->execute([$rk]); $row = $q->fetch();
    if (!$row) {
        try { $pdo->prepare('INSERT INTO rate_limits(rate_key,hit_count,window_started_at) VALUES(?,1,NOW())')->execute([$rk]); return false; }
        catch (PDOException $e) { $q->execute([$rk]); $row=$q->fetch(); if(!$row) throw $e; }
    }
    if ((int)$row['window_epoch'] < time()-$window) {
        $pdo->prepare('UPDATE rate_limits SET hit_count=1,window_started_at=NOW() WHERE rate_key=?')->execute([$rk]); return false;
    }
    if ((int)$row['hit_count'] >= $max) return true;
    $pdo->prepare('UPDATE rate_limits SET hit_count=hit_count+1 WHERE rate_key=?')->execute([$rk]);
    return false;
}
function audit(PDO $pdo, ?int $actor, string $action, string $details=''): void {
    try { $q=$pdo->prepare('INSERT INTO audit_log(actor_user_id,action,details,ip_address,created_at) VALUES(?,?,?,?,NOW())'); $q->execute([$actor,$action,substr($details,0,1000),substr((string)($_SERVER['REMOTE_ADDR'] ?? ''),0,45)]); } catch(Throwable $e) { error_log('[Fortune Apex audit] '.$e->getMessage()); }
}
function app_url(array $config, string $path=''): string { $base=rtrim((string)($config['base_url'] ?? ''),'/'); if ($base==='' || str_contains(strtolower($base),'your-domain')) { $https=(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off'); $base=($https?'https':'http').'://'.($_SERVER['HTTP_HOST'] ?? 'localhost'); } return $base.'/'.ltrim($path,'/'); }
function setting(PDO $pdo, string $key, string $fallback=''): string { $q=$pdo->prepare('SELECT setting_value FROM settings WHERE setting_key=?'); $q->execute([$key]); $v=$q->fetchColumn(); return $v===false?$fallback:(string)$v; }
function post_string(string $key, int $max=4000): string { $v=trim((string)($_POST[$key] ?? '')); return function_exists('mb_substr') ? mb_substr($v,0,$max,'UTF-8') : substr($v,0,$max); }
function valid_password(string $password): bool { return strlen($password)>=6 && strlen($password)<=200; }
function mail_admin(PDO $pdo, array $config, string $subject, string $body): bool {
    $to=(string)($config['mail']['admin_email'] ?? '');
    if (!filter_var($to,FILTER_VALIDATE_EMAIL)) return false;
    try { send_app_mail($config,$to,$subject,$body); return true; } catch(Throwable $ex) { error_log('[Fortune Apex mail] '.$ex->getMessage()); return false; }
}