<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireLogin();

$conn = getDbConnection();
$from = $_GET['from'] ?? date('Y-m-d', strtotime('-30 days'));
$to   = $_GET['to'] ?? date('Y-m-d');

$stmt = $conn->prepare(
    "SELECT detected_at, threat_type, source_detail, target_detail, severity, status
     FROM incidents
     WHERE DATE(detected_at) BETWEEN ? AND ?
     ORDER BY detected_at DESC"
);
$stmt->bind_param('ss', $from, $to);
$stmt->execute();
$rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="mads_incident_report_' . $from . '_to_' . $to . '.csv"');

$out = fopen('php://output', 'w');
fputcsv($out, ['Timestamp', 'Threat Type', 'Source', 'Target', 'Severity', 'Status']);

foreach ($rows as $row) {
    fputcsv($out, [
        $row['detected_at'],
        $row['threat_type'],
        $row['source_detail'],
        $row['target_detail'],
        $row['severity'],
        $row['status'],
    ]);
}

fclose($out);
exit;
