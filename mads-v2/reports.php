<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';

requireLogin();
$activePage = 'reports.php';

$conn = getDbConnection();

$from = $_GET['from'] ?? date('Y-m-d', strtotime('-30 days'));
$to   = $_GET['to'] ?? date('Y-m-d');

// By default, simulated attack-test runs (from the Attack Simulation page,
// tagged "[SIMULATED]") are excluded so reports reflect real-world activity.
// Tick the checkbox to include them too.
$includeSimulated = isset($_GET['include_simulated']);
$simClause = $includeSimulated ? "" : " AND source_detail NOT LIKE '[SIMULATED]%'";

// Threats by type
$stmt = $conn->prepare(
    "SELECT threat_type, COUNT(*) AS total
     FROM incidents
     WHERE DATE(detected_at) BETWEEN ? AND ?" . $simClause . "
     GROUP BY threat_type
     ORDER BY total DESC"
);
$stmt->bind_param('ss', $from, $to);
$stmt->execute();
$byType = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

$maxCount = 1;
foreach ($byType as $row) {
    $maxCount = max($maxCount, $row['total']);
}

$typeColors = [
    'script_injection'   => '#ff3d71',
    'sri_mismatch'       => '#ffb300',
    'csp_violation'      => '#00e5ff',
    'taint_alert'        => '#00ff9d',
    'unauthorised_post'  => '#ff3d71',
];

// Daily detections over the selected period (for the trend line graph)
$stmt2 = $conn->prepare(
    "SELECT DATE(detected_at) AS d, COUNT(*) AS total
     FROM incidents
     WHERE DATE(detected_at) BETWEEN ? AND ?" . $simClause . "
     GROUP BY DATE(detected_at)
     ORDER BY d ASC"
);
$stmt2->bind_param('ss', $from, $to);
$stmt2->execute();
$dailyRaw = $stmt2->get_result()->fetch_all(MYSQLI_ASSOC);

// Fill in every date in the range with 0 so the line graph has no gaps
$daily = [];
$cursor = new DateTime($from);
$end = new DateTime($to);
$byDate = [];
foreach ($dailyRaw as $row) {
    $byDate[$row['d']] = (int)$row['total'];
}
while ($cursor <= $end) {
    $key = $cursor->format('Y-m-d');
    $daily[] = ['d' => $key, 'total' => $byDate[$key] ?? 0];
    $cursor->modify('+1 day');
}

$maxDaily = 1;
foreach ($daily as $d) {
    $maxDaily = max($maxDaily, $d['total']);
}

// Build SVG line-graph point coordinates
$chartW = 600;
$chartH = 160;
$padL = 30; $padR = 10; $padT = 12; $padB = 22;
$plotW = $chartW - $padL - $padR;
$plotH = $chartH - $padT - $padB;
$n = count($daily);

$points = [];
foreach ($daily as $i => $d) {
    $x = $n > 1 ? $padL + ($i / ($n - 1)) * $plotW : $padL + $plotW / 2;
    $y = $padT + $plotH - (($d['total'] / $maxDaily) * $plotH);
    $points[] = ['x' => round($x, 1), 'y' => round($y, 1), 'total' => $d['total'], 'date' => $d['d']];
}
$polyline = implode(' ', array_map(fn($p) => "{$p['x']},{$p['y']}", $points));
$areaPath = '';
if ($points) {
    $areaPath = "M{$points[0]['x']},{$padT}" . " L" . $polyline . " L{$points[count($points)-1]['x']}," . ($padT + $plotH) . " L{$points[0]['x']}," . ($padT + $plotH) . " Z";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MADS — Reports</title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= bodyThemeClass() ?>">

<div class="topbar">
    <div class="topbar-logo">MADS <span>/ Reports</span></div>
    <div class="topbar-right">
        <span class="badge blue"><?= htmlspecialchars($from) ?> → <?= htmlspecialchars($to) ?></span>
        <a href="logout.php" style="color:var(--text-dim);">Logout</a>
    </div>
</div>

<div class="layout">
    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content">

        <div class="report-card" style="margin-bottom:16px;">
            <h4>Detections Over Period</h4>
            <?php if (empty($dailyRaw)): ?>
                <p style="color:var(--text-dim);font-size:12px;">No data for this period.</p>
            <?php else: ?>
                <svg viewBox="0 0 <?= $chartW ?> <?= $chartH ?>" width="100%" height="180" preserveAspectRatio="none" style="overflow:visible;">
                    <!-- gridlines -->
                    <?php for ($g = 0; $g <= 4; $g++): $gy = $padT + ($plotH / 4) * $g; ?>
                        <line x1="<?= $padL ?>" y1="<?= $gy ?>" x2="<?= $chartW - $padR ?>" y2="<?= $gy ?>" stroke="var(--border)" stroke-width="1" />
                    <?php endfor; ?>

                    <!-- area fill -->
                    <path d="<?= $areaPath ?>" fill="rgba(255,61,113,0.12)" stroke="none" />

                    <!-- trend line -->
                    <polyline points="<?= $polyline ?>" fill="none" stroke="#ff3d71" stroke-width="2" />

                    <!-- data points -->
                    <?php foreach ($points as $p): ?>
                        <circle cx="<?= $p['x'] ?>" cy="<?= $p['y'] ?>" r="3" fill="#ff3d71">
                            <title><?= htmlspecialchars($p['date']) ?>: <?= $p['total'] ?> detection<?= $p['total'] === 1 ? '' : 's' ?></title>
                        </circle>
                    <?php endforeach; ?>

                    <!-- y-axis labels -->
                    <text x="2" y="<?= $padT + 4 ?>" font-size="9" fill="var(--text-dim)"><?= $maxDaily ?></text>
                    <text x="2" y="<?= $padT + $plotH + 4 ?>" font-size="9" fill="var(--text-dim)">0</text>
                </svg>
                <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-dim);font-family:monospace;margin-top:4px;">
                    <span><?= htmlspecialchars($from) ?></span>
                    <span><?= htmlspecialchars($to) ?></span>
                </div>
            <?php endif; ?>
        </div>

        <div class="report-grid">
            <div class="report-card">
                <h4>Threats by Type</h4>
                <?php if (empty($byType)): ?>
                    <p style="color:var(--text-dim);font-size:12px;">No incidents in this period.</p>
                <?php endif; ?>
                <?php foreach ($byType as $row): ?>
                    <?php
                        $pct = round(($row['total'] / $maxCount) * 100);
                        $color = $typeColors[$row['threat_type']] ?? '#00e5ff';
                    ?>
                    <div class="bar-row">
                        <div class="bar-label"><?= htmlspecialchars(ucwords(str_replace('_', ' ', $row['threat_type']))) ?></div>
                        <div class="bar-track">
                            <div class="bar-fill" style="width:<?= $pct ?>%;background:<?= $color ?>;"></div>
                        </div>
                        <div class="bar-count"><?= (int)$row['total'] ?></div>
                    </div>
                <?php endforeach; ?>
            </div>

            <div class="report-card">
                <h4>Total Detections (Period Summary)</h4>
                <?php $totalAll = array_sum(array_column($byType, 'total')); ?>
                <div style="font-size:38px;font-weight:700;color:var(--accent2);line-height:1;"><?= $totalAll ?></div>
                <div style="font-size:11px;color:var(--text-dim);font-family:monospace;margin-top:6px;">
                    incidents between <?= htmlspecialchars($from) ?> and <?= htmlspecialchars($to) ?>
                    <?= $includeSimulated ? '(including simulated test runs)' : '(real detections only)' ?>
                </div>
            </div>
        </div>

        <form method="GET" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
            <input type="date" name="from" class="filter-input" style="max-width:180px;" value="<?= htmlspecialchars($from) ?>">
            <input type="date" name="to" class="filter-input" style="max-width:180px;" value="<?= htmlspecialchars($to) ?>">
            <label class="toggle-wrap" style="font-size:11px;color:var(--text-dim);font-family:monospace;">
                <input type="checkbox" name="include_simulated" value="1" <?= $includeSimulated ? 'checked' : '' ?>>
                INCLUDE SIMULATED TEST RUNS
            </label>
            <button type="submit" class="filter-btn" style="background:var(--accent);color:#000;border:none;font-weight:700;">
                APPLY RANGE
            </button>
            <a href="export-csv.php?from=<?= urlencode($from) ?>&to=<?= urlencode($to) ?>" class="filter-btn">EXPORT CSV</a>
        </form>
    </div>
</div>

</body>
</html>
