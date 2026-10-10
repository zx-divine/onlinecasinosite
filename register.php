<?php
declare(strict_types=1);
require_once __DIR__ . '/server/includes/bootstrap.php';
require_once __DIR__ . '/server/includes/view.php';

$user = current_user($pdo);
if ($user) redirect(($user['role'] ?? '') === 'admin' ? '/admin.php' : '/dashboard.php');
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    if (limited($pdo, 'register:' . $ip, (int)$security['rate_limits']['registration_max'], (int)$security['rate_limits']['registration_window_seconds'])) {
        $error = 'Too many registration attempts. Please wait before trying again.';
    } else {
        $username = post_string('username', 32);
        $display = post_string('display_name', 80);
        $email = strtolower(post_string('email', 190));
        $password = post_raw_string('password', 200);
        $confirm = post_raw_string('confirm_password', 200);
        if (!preg_match('/^[A-Za-z0-9_.-]{3,32}$/', $username)) {
            $error = 'Username must be 3–32 characters: letters, numbers, dot, underscore or hyphen.';
        } elseif ($display === '' || preg_match('/[\x00-\x1F\x7F]/', $display) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Enter a display name and valid email address.';
        } elseif (!valid_password($password) || $password !== $confirm) {
            $error = 'Passwords must match and contain at least 6 characters.';
        } else {
            try {
                $query = $pdo->prepare("INSERT INTO users(username,display_name,email,password_hash,role,status) VALUES(?,?,?,?,'player','pending')");
                $query->execute([$username, $display, $email, password_hash_secure($password)]);
                $id = (int)$pdo->lastInsertId();
                audit($pdo, $id, 'REGISTRATION_REQUEST', 'New player registration requested');
                $sent = mail_admin($pdo, $config, 'New Fortune Apex registration request', "A new registration request is waiting for review.\n\nName: $display\nUsername: $username\nEmail: $email\n\nApprove or reject it in the admin console.");
                flash($sent ? 'success' : 'warning', $sent ? 'Your registration request is saved. The admin team has been notified by email; access begins after approval.' : 'Your registration request is saved. Email notification could not be sent, but the request remains in the admin console.');
                redirect('/login.php');
            } catch (PDOException $exception) {
                if ((string)$exception->getCode() === '23000') {
                    $error = 'That username or email is already registered. Try logging in or use password recovery.';
                } else {
                    error_log('[Fortune Apex register] Database operation failed (' . get_class($exception) . ', code ' . (string)$exception->getCode() . ').');
                    $error = 'Could not save the request right now. Please try again later.';
                }
            }
        }
    }
}
page_header($config, null, 'Request to join');
?>
<section class="auth-wrap"><div class="auth-card"><div class="eyebrow">Membership application</div><h1>Request access</h1><p>Create your personal login. New accounts stay pending until the admin approves them.</p><?php if ($error): ?><div class="flash error"><?= e($error) ?></div><?php endif; ?><form method="post" autocomplete="on"><?= csrf_field() ?><label class="field">Display name<input name="display_name" maxlength="80" required value="<?= e($_POST['display_name'] ?? '') ?>"></label><label class="field">Username<input name="username" maxlength="32" pattern="[A-Za-z0-9_.-]{3,32}" autocomplete="username" required value="<?= e($_POST['username'] ?? '') ?>"><small>Unique and used for sign-in and password recovery.</small></label><label class="field">Email address<input type="email" name="email" maxlength="190" autocomplete="email" required value="<?= e($_POST['email'] ?? '') ?>"><small>Used for registration updates and password recovery.</small></label><div class="split"><label class="field">Password<input type="password" name="password" minlength="6" maxlength="200" autocomplete="new-password" required></label><label class="field">Confirm password<input type="password" name="confirm_password" minlength="6" maxlength="200" autocomplete="new-password" required></label></div><button class="btn gold" type="submit">Submit registration request</button></form><p class="hint">Already approved? <a href="/login.php">Log in</a>. Forgot your password? <a href="/forgot.php">Recover it</a>.</p></div></section>
<?php page_footer(); ?>