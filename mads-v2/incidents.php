<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';

requireLogin();
$activePage = 'incidents.php';

$conn = getDbConnection();

$filter = $_GET['filter'] ?? 'all';
$search = trim($_GET['q'] ?? '');

$sql = "SELECT * FROM incidents WHERE 1=1";
$params = [];
$types = '';

if ($filter === 'critical') {
    $sql .= " AND severity = 'critical'";
} elseif ($filter === 'high') {
    $sql .= " AND severity = 'high'";
} elseif ($filter === 'resolved') {
    $sql .= " AND status = 'resolved'";
}

if ($search !== '') {
    $sql .= " AND (threat_type LIKE ? OR source_detail LIKE ? OR target_detail LIKE ?)";
    $like = "%$search%";
    $params = [$like, $like, $like];
    $types = 'sss';
}

$sql .= " ORDER BY detected_at DESC";

$stmt = $conn->prepare($sql);
if ($params) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$incidents = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

$activeThreats = $conn->query("SELECT COUNT(*) AS c FROM incidents WHERE status != 'resolved'")->fetch_assoc()['c'];

function sevBadge($s) {
    return match ($s) {
        'critical' => 'red',
        'high' => 'yellow',
        default => 'blue',
    };
}
function statusDotClass($s) {
    return match ($s) {
        'blocked' => 'fail',
        'resolved' => 'ok',
        default => 'warn',
    };
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MADS — Incident Log</title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= bodyThemeClass() ?>">

<div class="topbar">
    <div class="topbar-logo">MADS <span>/ Incident Log</span></div>
    <div class="topbar-right">
        <span class="badge red"><?= (int)$activeThreats ?> ACTIVE THREATS</span>
        <a href="logout.php" style="color:var(--text-dim);">Logout</a>
    </div>
</div>

<div class="layout">
    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content">
        <form method="GET" class="filter-bar">
            <input type="text" name="q" class="filter-input" placeholder="🔍  Search incidents..." value="<?= htmlspecialchars($search) ?>">
            <input type="hidden" name="filter" value="<?= htmlspecialchars($filter) ?>">
            <a href="?filter=all" class="filter-btn <?= $filter === 'all' ? 'active' : '' ?>">ALL</a>
            <a href="?filter=critical" class="filter-btn <?= $filter === 'critical' ? 'active' : '' ?>">CRITICAL</a>
            <a href="?filter=high" class="filter-btn <?= $filter === 'high' ? 'active' : '' ?>">HIGH</a>
            <a href="?filter=resolved" class="filter-btn <?= $filter === 'resolved' ? 'active' : '' ?>">RESOLVED</a>
        </form>

        <table class="table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Threat Type</th>
                    <th>Source</th>
                    <th>Target</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($incidents)): ?>
                    <tr><td colspan="6" style="color:var(--text-dim);">No incidents match this filter.</td></tr>
                <?php endif; ?>

                <?php foreach ($incidents as $i): ?>
                    <tr>
                        <td><?= htmlspecialchars($i['detected_at']) ?></td>
                        <td><?= htmlspecialchars(ucwords(str_replace('_', ' ', $i['threat_type']))) ?></td>
                        <td style="color:var(--text-dim);">
                            <?= htmlspecialchars(str_replace('[SIMULATED] ', '', $i['source_detail'] ?? '—')) ?>
                            <?php if (str_starts_with($i['source_detail'] ?? '', '[SIMULATED]')): ?>
                                <span class="badge yellow" style="margin-left:6px;">SIM</span>
                            <?php endif; ?>
                        </td>
                        <td><?= htmlspecialchars($i['target_detail'] ?? '—') ?></td>
                        <td><span class="badge <?= sevBadge($i['severity']) ?>"><?= strtoupper($i['severity']) ?></span></td>
                        <td>
                            <span class="status-dot <?= statusDotClass($i['status']) ?>"></span>
                            <?= strtoupper($i['status']) ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

</body>
</html>
