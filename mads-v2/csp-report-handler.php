<?php
/**
 * MADS - CSP Violation Report Handler
 * Browsers POST JSON reports here when a CSP rule is violated.
 */

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/detector.php';

$rawData = file_get_contents('php://input');
$report = json_decode($rawData, true);

if (isset($report['csp-report'])) {
    $violation = $report['csp-report'];

    $blockedUri = $violation['blocked-uri'] ?? 'unknown';
    $documentUri = $violation['document-uri'] ?? 'unknown';

    logIncident(
        null,
        'csp_violation',
        $blockedUri,
        $documentUri,
        'high',
        'reviewing'
    );
}

http_response_code(204);
exit;
