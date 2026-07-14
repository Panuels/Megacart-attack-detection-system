<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireLogin();
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<!-- Real, browser-enforced CSP for this page only -->
<meta http-equiv="Content-Security-Policy"
      content="script-src 'self' https://js.stripe.com; report-uri /mads-v2/csp-report-handler.php;">
<title>Real CSP Enforcement Test</title>
</head>
<body>
<h2>Real CSP Enforcement Test</h2>
<p>This page has a real, browser-enforced CSP policy (via meta tag) allowing only 'self' and js.stripe.com.</p>
<p>The script below is an unauthorized "loader script" from a disallowed domain. The browser should block it for real and report the violation.</p>

<!-- Malicious loader script from an unauthorized domain -->
<script src="https://evil-loader-test.com/malicious.js"></script>

<p id="result">If you see this with no errors above, check DevTools Console — the browser blocked the script and should have sent a violation report.</p>
</body>
</html>