<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';

requireLogin();

$file = __DIR__ . '/assets/js/demo-tracker.js';
$actualHash = 'sha384-' . base64_encode(hash_file('sha384', $file, true));

// Baseline hash captured once when the file was first verified as clean.
$expectedHash = 'sha384-lJz3lYe8LDlrQmYWyZQtsPM7SfW1Vz6DAFb6RFqJNOQ3DVA9w0atBL0wHRe54bbQ';

$status = verifyScriptIntegrity($actualHash, $expectedHash);

$scriptId = ensureScriptRecord('assets/js/demo-tracker.js', $actualHash, $expectedHash, 'local', $status);

if ($status === 'blocked') {
    logIncident($scriptId, 'sri_mismatch', 'assets/js/demo-tracker.js', 'checkout page', 'critical', 'blocked');
}

echo "<h2>Real Script Integrity Test</h2>";
echo "<p><b>File:</b> assets/js/demo-tracker.js</p>";
echo "<p><b>Expected Hash:</b> " . htmlspecialchars($expectedHash) . "</p>";
echo "<p><b>Actual Hash:</b> " . htmlspecialchars($actualHash) . "</p>";
echo "<p><b>Result:</b> " . strtoupper($status) . "</p>";
if ($status === 'blocked') {
    echo "<p style='color:red;'>Mismatch detected -- a real incident was just logged. Check Incidents and Dashboard.</p>";
} else {
    echo "<p style='color:green;'>Hash matches -- script verified as untampered.</p>";
}