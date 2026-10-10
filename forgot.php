<?php
declare(strict_types=1);
require_once __DIR__ . '/server/includes/bootstrap.php';
require_once __DIR__ . '/server/includes/view.php';
$error = '';
$sent = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $username = post_string('username', 32);
    $email = strtolower(post_string('email', 190));
    $blockedIp = limited($pdo, 'forgot-ip:' . $ip, (int)$security['rate_limits']['forgot_password_max'], (int)$security['rate_limits']['forgot_password_window_seconds']);
    $blockedIdentity = limited($pdo, 'forgot-identity:' . strtolower($username . '|' . $email), 3, 3600);
    if ($blockedIp || $blockedIdentity) {
        $error = 'Too many requests. Wait a while and try again.';
    } else {
        $query = $pdo->prepare("SELECT id,display_name,email FROM users WHERE username=? AND email=? AND status='active' LIMIT 1");
        $query->execute([$username, $email]);
        $user = $query->fetch();
        if ($user) {
            $rawToken = bin2hex(random_bytes(32));
            $tokenHash = hash('sha256', $rawToken);
            $pdo->prepare('UPDATE password_resets SET used_at=NOW() WHERE user_id=? AND used_at IS NULL')->execute([(int)$user['id']]);
            $pdo->prepare('INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES(?,?,DATE_ADD(NOW(), INTERVAL 30 MINUTE))')->execute([(int)$user['id'], $tokenHash]);
            $url = app_url($config, 'reset.php?token=' . rawurlencode($rawToken));
            try {
                send_app_mail($config, $user['email'], 'Reset your Fortune Apex password', "Hello {$user['display_name']},\n\nUse this one-time link within 30 minutes to set a new password:\n$url\n\nIf you did not request this, ignore this email.");
                audit($pdo, (int)$user['id'], 'PASSWORD_RESET_REQUEST', 'Password reset requested');
            } catch (Throwable $exception) {
                error_log('[Fortune Apex password reset] Email delivery failed (' . get_class($exception) . ', code ' . (string)$exception->getCode() . ').');
                // Invalidate an undelivered reset link so it cannot be used unexpectedly.
                $pdo->prepare('UPDATE password_resets SET used_at=NOW() WHERE token_hash=? AND used_at IS NULL')->execute([$tokenHash]);
            }
        }
        // Always show the same success message to avoid account enumeration.
        $sent = true;
    }
}
page_header($config, null, 'Password recovery');
?>
<section class="auth-wrap"><div class="auth-card"><div class="eyebrow">Account recovery</div><h1>Forgot password?</h1><p>Enter your username and registered email address. If they match an active account and email is configured, a one-time reset link will be sent.</p><?php if ($error): ?><div class="flash error"><?= e($error) ?></div><?php endif; ?><?php if ($sent): ?><div class="flash success">If those details match an active account, an email with a reset link is on its way. Check your spam folder too.</div><?php else: ?><form method="post"><?= csrf_field() ?><label class="field">Username<input name="username" maxlength="32" autocomplete="username" required></label><label class="field">Registered email<input type="email" name="email" maxlength="190" autocomplete="email" required></label><button class="btn gold" type="submit">Send recovery email</button></form><?php endif; ?><p class="hint"><a href="/login.php">Return to login</a></p></div></section>
<?php page_footer(); ?>