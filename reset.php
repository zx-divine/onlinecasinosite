<?php
declare(strict_types=1);
require_once __DIR__ . '/server/includes/bootstrap.php';
require_once __DIR__ . '/server/includes/view.php';
$tokenRaw = $_GET['token'] ?? $_POST['token'] ?? '';
$token = is_string($tokenRaw) ? trim($tokenRaw) : '';
$error = '';
$valid = false;
$row = null;
if (strlen($token) === 64 && ctype_xdigit($token)) {
    $query = $pdo->prepare("SELECT pr.id,pr.user_id FROM password_resets pr JOIN users u ON u.id=pr.user_id WHERE pr.token_hash=? AND pr.used_at IS NULL AND pr.expires_at>NOW() AND u.status='active' LIMIT 1");
    $query->execute([hash('sha256', $token)]);
    $row = $query->fetch();
    $valid = (bool)$row;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $newPassword = post_raw_string('password', 200);
    $confirmPassword = post_raw_string('confirm_password', 200);
    if (!valid_password($newPassword) || $newPassword !== $confirmPassword) {
        $error = 'Passwords must match and contain at least 6 characters.';
    } elseif (!$valid) {
        $error = 'This reset link is invalid or expired. Request another one.';
    } else {
        // Re-check and lock the reset record during the change so two concurrent requests cannot reuse it.
        $pdo->beginTransaction();
        try {
            $query = $pdo->prepare("SELECT pr.id,pr.user_id FROM password_resets pr JOIN users u ON u.id=pr.user_id WHERE pr.token_hash=? AND pr.used_at IS NULL AND pr.expires_at>NOW() AND u.status='active' LIMIT 1 FOR UPDATE");
            $query->execute([hash('sha256', $token)]);
            $lockedRow = $query->fetch();
            if (!$lockedRow) throw new RuntimeException('Reset token already used or expired.');
            $pdo->prepare('UPDATE users SET password_hash=?,must_change_password=0,session_version=session_version+1 WHERE id=?')->execute([password_hash_secure($newPassword), (int)$lockedRow['user_id']]);
            $consume = $pdo->prepare('UPDATE password_resets SET used_at=NOW() WHERE id=? AND used_at IS NULL');
            $consume->execute([(int)$lockedRow['id']]);
            if ($consume->rowCount() !== 1) throw new RuntimeException('Reset token was consumed concurrently.');
            $pdo->prepare('UPDATE password_resets SET used_at=NOW() WHERE user_id=? AND used_at IS NULL')->execute([(int)$lockedRow['user_id']]);
            $pdo->commit();
            audit($pdo, (int)$lockedRow['user_id'], 'PASSWORD_RESET', 'Password reset completed');
            flash('success', 'Password updated. You can now log in.');
            redirect('/login.php');
        } catch (Throwable $exception) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            error_log('[Fortune Apex reset] Password reset transaction failed (' . get_class($exception) . ', code ' . (string)$exception->getCode() . ').');
            $error = 'This reset link is no longer valid, or the password could not be updated. Request a new link.';
            $valid = false;
        }
    }
}
page_header($config, null, 'Set a new password');
?>
<section class="auth-wrap"><div class="auth-card"><div class="eyebrow">One-time secure link</div><h1>Set a new password</h1><?php if ($error): ?><div class="flash error"><?= e($error) ?></div><?php endif; ?><?php if (!$valid): ?><p>This link is not available or has expired. <a href="/forgot.php">Request a new password reset</a>.</p><?php else: ?><p>Choose a new password. The link will be invalid after you use it.</p><form method="post"><?= csrf_field() ?><input type="hidden" name="token" value="<?= e($token) ?>"><label class="field">New password<input type="password" name="password" minlength="6" maxlength="200" autocomplete="new-password" required></label><label class="field">Confirm new password<input type="password" name="confirm_password" minlength="6" maxlength="200" autocomplete="new-password" required></label><button class="btn gold" type="submit">Save new password</button></form><?php endif; ?></div></section>
<?php page_footer(); ?>