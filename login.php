<?php
declare(strict_types=1);
require_once __DIR__ . '/server/includes/bootstrap.php';
require_once __DIR__ . '/server/includes/view.php';

$user = current_user($pdo);
if ($user) redirect(($user['role'] ?? '') === 'admin' ? '/admin.php' : '/dashboard.php');
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $login = post_string('username', 190);
    $password = post_raw_string('password', 200);
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $blockedIp = limited($pdo, 'login-ip:' . $ip, (int)$security['rate_limits']['login_ip_max'], (int)$security['rate_limits']['login_ip_window_seconds']);
    $blockedIdentity = $login !== '' && limited($pdo, 'login-id:' . strtolower($login), (int)$security['rate_limits']['login_identity_max'], (int)$security['rate_limits']['login_identity_window_seconds']);

    if ($blockedIp || $blockedIdentity) {
        $error = 'Too many sign-in attempts. Please wait 15 minutes before trying again.';
    } else {
        $query = $pdo->prepare('SELECT id,username,password_hash,role,status,must_change_password,session_version FROM users WHERE username=? OR email=? LIMIT 1');
        $query->execute([$login, $login]);
        $candidate = $query->fetch();
        $passwordMatches = $candidate && password_verify($password, (string)$candidate['password_hash']);
        if ($candidate && $passwordMatches && $candidate['status'] === 'active') {
            session_regenerate_id(true);
            clear_csrf_tokens();
            $_SESSION['uid'] = (int)$candidate['id'];
            $_SESSION['_fa_session_version'] = (int)$candidate['session_version'];
            $_SESSION['_fa_created'] = time();
            $_SESSION['_fa_last_seen'] = time();
            if ($candidate['role'] === 'admin') $_SESSION['prompt_approvals'] = true;
            $pdo->prepare('UPDATE users SET last_login_at=NOW() WHERE id=?')->execute([(int)$candidate['id']]);
            if (password_rehash_needed((string)$candidate['password_hash'])) {
                $pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash_secure($password), (int)$candidate['id']]);
            }
            audit($pdo, (int)$candidate['id'], 'LOGIN', 'Successful sign-in');
            redirect(!empty($candidate['must_change_password']) ? '/change-password.php' : (($candidate['role'] === 'admin') ? '/admin.php' : '/dashboard.php'));
        }
        usleep(250000);
        $error = 'Sign-in failed. Check your username/email and password, or recover your password.';
        audit($pdo, $candidate ? (int)$candidate['id'] : null, 'LOGIN_FAILED', 'Failed sign-in attempt');
    }
}

page_header($config, null, 'Member login');
?>
<section class="auth-wrap"><div class="auth-card"><div class="eyebrow">Welcome back</div><h1>Member login</h1><p>Each member has their own account. The Owner creates admin accounts separately through Master Admin.</p><?php if ($error): ?><div class="flash error"><?= e($error) ?></div><?php endif; ?><form method="post" autocomplete="on"><?= csrf_field() ?><label class="field">Username or email<input name="username" maxlength="190" autocomplete="username" required value="<?= e($_POST['username'] ?? '') ?>"></label><label class="field">Password<input type="password" name="password" autocomplete="current-password" required></label><button class="btn gold" type="submit">Log in securely</button></form><p class="hint"><a href="/forgot.php">Forgot password?</a> · <a href="/register.php">Request to join</a></p></div></section>
<?php page_footer(); ?>