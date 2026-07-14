<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';

requireLogin();

// Simulates a script trying to send card data to a domain NOT in the connect-src allow-list
$destinationDomain = 'evil-real-test.com';

$allowed = isDestinationAllowed($destinationDomain);

echo "<h2>Real Exfiltration Destination Test</h2>";
echo "<p><b>Destination checked:</b> " . htmlspecialchars($destinationDomain) . "</p>";
echo "<p><b>Allowed by CSP connect-src?</b> " . ($allowed ? 'YES' : 'NO') . "</p>";

if (!$allowed) {
    $scriptId = ensureScriptRecord('real-exfil-test.js', 'n/a', 'n/a', 'unknown', 'blocked');
    logIncident($scriptId, 'taint_alert', 'real-exfil-test.js', $destinationDomain, 'critical', 'blocked');
    echo "<p style='color:red;'>BLOCKED -- unauthorized destination detected. A real incident was just logged and an alert email should be sent.</p>";
} else {
    echo "<p style='color:green;'>Destination is allow-listed -- no incident logged.</p>";
}