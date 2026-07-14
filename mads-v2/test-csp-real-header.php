<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireLogin();

// Real, browser-enforced CSP sent as an actual HTTP header (not a meta tag)
// so that report-uri is honored by the browser.
header("Content-Security-Policy: script-src 'self' https://js.stripe.com; report-uri /mads-v2/csp-report-handler.php;");
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Real CSP Enforcement Test</title>
</head>
<body>
<h2>Real CSP Enforcement Test</h2>
<p>This page sends a real Content-Security-Policy HTTP header allowing only 'self' and js.stripe.com.</p>
<p>The script below is an unauthorized "loader script" from a disallowed domain. The browser should block it for real and report the violation.</p>

<!-- Malicious loader script from an unauthorized domain -->
<script src="https://evil-loader-test.com/malicious.js"></script>

<p id="result">If you see this with no errors above, check DevTools Console — the browser blocked the script and sent a real violation report to csp-report-handler.php.</p>
</body>
</html>