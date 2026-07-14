<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';

requireLogin();

$conn = getDbConnection();
$rules = $conn->query("SELECT * FROM csp_rules")->fetch_all(MYSQLI_ASSOC);

$issues = [];
foreach ($rules as $rule) {
    if (!$rule['is_active']) {
        $issues[] = "{$rule['directive']} is disabled";
    }
    if (str_contains($rule['value'], '*')) {
        $issues[] = "{$rule['directive']} contains a wildcard (*), which is overly permissive";
    }
    if ($rule['directive'] === 'object-src' && trim($rule['value']) !== "'none'") {
        $issues[] = "object-src is not set to 'none'";
    }
}

echo "<h2>Real CSP Misconfiguration Check</h2>";

if (empty($issues)) {
    echo "<p style='color:green;'>No misconfigurations found -- CSP rules look properly restrictive.</p>";
} else {
    echo "<p><b>Issues found:</b></p><ul>";
    foreach ($issues as $issue) {
        echo "<li>" . htmlspecialchars($issue) . "</li>";
    }
    echo "</ul>";

    $scriptId = ensureScriptRecord('csp-policy-review', 'n/a', 'n/a', 'local', 'blocked');
    logIncident($scriptId, 'csp_violation', 'CSP policy review', implode('; ', $issues), 'low', 'reviewing');
    echo "<p style='color:orange;'>LOW severity incident logged for review -- no active exploitation, just a configuration finding.</p>";
}