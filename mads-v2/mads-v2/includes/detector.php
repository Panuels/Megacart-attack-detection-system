<?php
require_once __DIR__ . '/mailer.php';

function verifyScriptIntegrity($actualHash, $expectedHash) {
    if (empty($expectedHash)) return 'no_sri';
    return ($actualHash === $expectedHash) ? 'verified' : 'blocked';
}

function isDestinationAllowed($destinationDomain) {
    $conn   = getDbConnection();
    $result = $conn->query(
        "SELECT value FROM csp_rules WHERE directive = 'connect-src' AND is_active = 1"
    );
    if ($row = $result->fetch_assoc()) {
        return strpos($row['value'], $destinationDomain) !== false;
    }
    return false;
}

/**
 * Log an incident AND fire an email alert for every severity level.
 */
function logIncident($scriptId, $threatType, $sourceDetail, $targetDetail, $severity, $status) {
    $conn = getDbConnection();
    $stmt = $conn->prepare(
        "INSERT INTO incidents (script_id, threat_type, source_detail, target_detail, severity, status)
         VALUES (?, ?, ?, ?, ?, ?)"
    );
    $stmt->bind_param('isssss', $scriptId, $threatType, $sourceDetail, $targetDetail, $severity, $status);
    $stmt->execute();
    $incidentId = $conn->insert_id;

    // Fire email alert for ALL severities — no threshold filter
    sendAlertEmail($threatType, $sourceDetail, $targetDetail, $severity, $status);

    return $incidentId;
}

/**
 * Register or update a script entry so simulated attacks appear on the Scripts page.
 */
function ensureScriptRecord($scriptSrc, $actualHash, $expectedHash, $origin, $status) {
    $conn = getDbConnection();

    // Get or create the default checkout page record
    $page = $conn->query("SELECT id FROM checkout_pages LIMIT 1")->fetch_assoc();
    $pageId = $page ? $page['id'] : null;

    if (!$pageId) {
        $conn->query("INSERT INTO checkout_pages (page_url) VALUES ('/checkout.php')");
        $pageId = $conn->insert_id;
    }

    // Check if script already exists
    $chk = $conn->prepare("SELECT id FROM scripts WHERE script_src = ? AND page_id = ?");
    $chk->bind_param('si', $scriptSrc, $pageId);
    $chk->execute();
    $existing = $chk->get_result()->fetch_assoc();

    if ($existing) {
        $upd = $conn->prepare(
            "UPDATE scripts SET sri_hash=?, expected_hash=?, origin=?, status=?, last_checked=NOW()
             WHERE id=?"
        );
        $upd->bind_param('ssssi', $actualHash, $expectedHash, $origin, $status, $existing['id']);
        $upd->execute();
        return $existing['id'];
    } else {
        $ins = $conn->prepare(
            "INSERT INTO scripts (page_id, script_src, sri_hash, expected_hash, origin, status)
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        $ins->bind_param('isssss', $pageId, $scriptSrc, $actualHash, $expectedHash, $origin, $status);
        $ins->execute();
        return $conn->insert_id;
    }
}

function getDashboardStats() {
    $conn  = getDbConnection();
    $stats = [];

    // Exclude simulated entries from dashboard counts
    $stats['threats_detected'] = $conn->query(
        "SELECT COUNT(*) AS c FROM incidents
         WHERE DATE(detected_at) = CURDATE()
         AND source_detail NOT LIKE '[SIMULATED]%'"
    )->fetch_assoc()['c'];

    $stats['scripts_monitored'] = $conn->query(
        "SELECT COUNT(*) AS c FROM scripts"
    )->fetch_assoc()['c'];

    $stats['sri_verified'] = $conn->query(
        "SELECT COUNT(*) AS c FROM scripts WHERE status = 'verified'"
    )->fetch_assoc()['c'];

    $stats['csp_violations'] = $conn->query(
        "SELECT COUNT(*) AS c FROM incidents
         WHERE threat_type = 'csp_violation'
         AND detected_at >= NOW() - INTERVAL 1 DAY
         AND source_detail NOT LIKE '[SIMULATED]%'"
    )->fetch_assoc()['c'];

    return $stats;
}

function getRecentIncidents($limit = 5) {
    $conn = getDbConnection();
    $stmt = $conn->prepare(
        "SELECT * FROM incidents
         WHERE source_detail NOT LIKE '[SIMULATED]%'
         ORDER BY detected_at DESC LIMIT ?"
    );
    $stmt->bind_param('i', $limit);
    $stmt->execute();
    return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
}
