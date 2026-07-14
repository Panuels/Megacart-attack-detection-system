<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';

requireLogin();
$activePage = 'settings.php';

$passwordMessage = '';
$passwordError   = '';
$settingsMessage = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (($_POST['form'] ?? '') === 'password') {
        $current = $_POST['current_password'] ?? '';
        $new     = $_POST['new_password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';
        if ($new !== $confirm) {
            $passwordError = 'New password and confirmation do not match.';
        } else {
            $outcome = changePassword($_SESSION['admin_id'], $current, $new);
            $outcome === true ? $passwordMessage = 'Password updated.' : $passwordError = $outcome;
        }
    }

    if (($_POST['form'] ?? '') === 'preferences') {
        updateSettings([
            'theme'                    => ($_POST['theme'] ?? 'dark') === 'light' ? 'light' : 'dark',
            'owner_email'              => trim($_POST['owner_email'] ?? ''),
            'email_alerts_enabled'     => isset($_POST['email_alerts_enabled']) ? '1' : '0',
            'resend_api_key'           => trim($_POST['resend_api_key'] ?? ''),
        ]);
        $settingsMessage = 'Settings saved.';
    }
}

$settings = getSettings();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MADS — Settings</title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= bodyThemeClass() ?>">

<div class="topbar">
    <div class="topbar-logo">MADS <span>/ Settings</span></div>
    <div class="topbar-right">
        <span><?= htmlspecialchars($_SESSION['admin_username']) ?></span>
    </div>
</div>

<div class="layout">
    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content">

        <!-- Change Password -->
        <div class="settings-section">
            <div class="section-head">Change Password</div>
            <?php if ($passwordMessage): ?>
                <div class="badge green" style="display:block;width:fit-content;padding:8px 14px;margin-bottom:16px;"><?= htmlspecialchars($passwordMessage) ?></div>
            <?php endif; ?>
            <?php if ($passwordError): ?>
                <div class="error-msg"><?= htmlspecialchars($passwordError) ?></div>
            <?php endif; ?>
            <form method="POST" style="display:flex;flex-direction:column;gap:14px;">
                <input type="hidden" name="form" value="password">
                <div class="form-group">
                    <label class="form-label">Current Password</label>
                    <input type="password" name="current_password" class="form-input" required>
                </div>
                <div class="form-group">
                    <label class="form-label">New Password</label>
                    <input type="password" name="new_password" class="form-input" required minlength="8">
                </div>
                <div class="form-group">
                    <label class="form-label">Confirm New Password</label>
                    <input type="password" name="confirm_password" class="form-input" required minlength="8">
                </div>
                <button type="submit" class="btn-primary" style="width:fit-content;padding:11px 28px;">UPDATE PASSWORD</button>
            </form>
        </div>

        <!-- Preferences -->
        <div class="settings-section">
            <div class="section-head">Appearance &amp; Email Alerts</div>
            <?php if ($settingsMessage): ?>
                <div class="badge green" style="display:block;width:fit-content;padding:8px 14px;margin-bottom:16px;"><?= htmlspecialchars($settingsMessage) ?></div>
            <?php endif; ?>
            <form method="POST" style="display:flex;flex-direction:column;gap:18px;">
                <input type="hidden" name="form" value="preferences">

                <!-- Theme -->
                <div>
                    <label class="form-label" style="margin-bottom:10px;">Theme</label>
                    <div style="display:flex;gap:10px;">
                        <label class="filter-btn <?= $settings['theme']==='dark'?'active':'' ?>" style="cursor:pointer;">
                            <input type="radio" name="theme" value="dark" <?= $settings['theme']==='dark'?'checked':'' ?> style="margin-right:6px;"> DARK
                        </label>
                        <label class="filter-btn <?= $settings['theme']==='light'?'active':'' ?>" style="cursor:pointer;">
                            <input type="radio" name="theme" value="light" <?= $settings['theme']==='light'?'checked':'' ?> style="margin-right:6px;"> LIGHT
                        </label>
                    </div>
                </div>

                <!-- Resend API key -->
                <div class="form-group">
                    <label class="form-label">Resend API Key</label>
                    <input type="text" name="resend_api_key" class="form-input"
                           placeholder="re_xxxxxxxxxxxxxxxxxxxx"
                           value="<?= htmlspecialchars($settings['resend_api_key'] ?? '') ?>">
                    <div style="font-size:10px;color:var(--text-dim);font-family:monospace;margin-top:6px;">
                        Get your key at <a href="https://resend.com" target="_blank" style="color:var(--accent);">resend.com</a> — free tier sends 3,000 emails/month
                    </div>
                </div>

                <!-- Owner email -->
                <div class="form-group">
                    <label class="form-label">Owner Alert Email</label>
                    <input type="email" name="owner_email" class="form-input"
                           placeholder="you@gmail.com"
                           value="<?= htmlspecialchars($settings['owner_email'] ?? '') ?>">
                    <div style="font-size:10px;color:var(--text-dim);font-family:monospace;margin-top:6px;">
                        All threat alerts (LOW, MEDIUM, HIGH, CRITICAL) will be sent here
                    </div>
                </div>

                <!-- Enable alerts toggle -->
                <label class="toggle-wrap">
                    <input type="checkbox" name="email_alerts_enabled"
                           <?= $settings['email_alerts_enabled'] ? 'checked' : '' ?>
                           style="display:none;"
                           onclick="this.nextElementSibling.classList.toggle('on')">
                    <div class="toggle <?= $settings['email_alerts_enabled'] ? 'on' : '' ?>"></div>
                    <span style="font-size:12px;color:var(--text-dim);margin-left:6px;">
                        Send email alerts when threats are detected (all severity levels)
                    </span>
                </label>

                <button type="submit" class="btn-primary" style="width:fit-content;padding:11px 28px;">SAVE SETTINGS</button>
            </form>
        </div>

        <!-- Test email -->
        <div class="settings-section">
            <div class="section-head">Test Email Alert</div>
            <p style="font-size:12px;color:var(--text-dim);margin-bottom:14px;">
                Send a test alert to verify your Resend API key and email address are configured correctly.
            </p>
            <button class="filter-btn" onclick="sendTestEmail()" id="testBtn">SEND TEST EMAIL</button>
            <div id="testResult" style="margin-top:10px;font-family:monospace;font-size:12px;display:none;"></div>
        </div>

    </div>
</div>

<script>
async function sendTestEmail() {
    const btn = document.getElementById('testBtn');
    const res = document.getElementById('testResult');
    btn.textContent = 'Sending...';
    btn.disabled = true;
    res.style.display = 'none';

    const fd = new FormData();
    fd.append('action', 'test_email');
    const resp = await fetch('test-email.php', { method:'POST', body:fd });
    const data = await resp.json();

    res.style.display = 'block';
    if (data.ok) {
        res.style.color = 'var(--accent3)';
        res.textContent = '✓ Test email sent successfully — check your inbox.';
    } else {
        res.style.color = 'var(--accent2)';
        res.textContent = '✕ Failed: ' + (data.error || 'Unknown error. Check API key and email.');
    }
    btn.textContent = 'SEND TEST EMAIL';
    btn.disabled = false;
}
</script>
</body>
</html>
