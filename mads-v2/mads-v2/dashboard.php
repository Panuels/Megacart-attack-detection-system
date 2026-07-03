<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';

requireLogin();
$activePage = 'dashboard.php';
$stats          = getDashboardStats();
$recentIncidents = getRecentIncidents(5);

// Fetch recent scripts for the dashboard script list
$conn = getDbConnection();
$recentScripts = $conn->query(
    "SELECT * FROM scripts ORDER BY last_checked DESC LIMIT 6"
)->fetch_all(MYSQLI_ASSOC);

function severityClass($s) { return match($s) { 'critical'=>'', 'high'=>'warn', default=>'info' }; }
function severityBadge($s) { return match($s) { 'critical'=>'red', 'high'=>'yellow', default=>'blue' }; }
function sdot($s)           { return match($s) { 'verified'=>'ok', 'blocked'=>'fail', default=>'warn' }; }
function obadge($o)         { return match($o) { 'cdn'=>'blue','third_party'=>'green','local'=>'blue', default=>'yellow' }; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MADS — Dashboard</title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= bodyThemeClass() ?>">

<!-- Script detail popup -->
<div class="script-popup" id="scriptPopup">
    <button class="popup-close" onclick="closePopup()">✕</button>
    <h3 id="pp-src">Script Details</h3>
    <div class="popup-row"><span class="popup-key">Status</span><span class="popup-val" id="pp-status"></span></div>
    <div class="popup-row"><span class="popup-key">Origin</span><span class="popup-val" id="pp-origin"></span></div>
    <div class="popup-row"><span class="popup-key">SRI Hash</span><span class="popup-val" id="pp-hash"></span></div>
    <div class="popup-row"><span class="popup-key">Expected Hash</span><span class="popup-val" id="pp-expected"></span></div>
    <div class="popup-row"><span class="popup-key">Last Checked</span><span class="popup-val" id="pp-checked"></span></div>
    <div class="popup-row"><span class="popup-key">First Seen</span><span class="popup-val" id="pp-first"></span></div>
</div>

<div class="topbar">
    <div class="topbar-logo">MADS <span>/ Dashboard</span></div>
    <div class="topbar-right">
        <span class="badge green">● SYSTEM ACTIVE</span>
        <span><?= htmlspecialchars($_SESSION['admin_username']) ?></span>
    </div>
</div>

<div class="layout">
    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content">

        <!-- Stat cards -->
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-label">Threats Detected</div>
                <div class="stat-value red"><?= (int)$stats['threats_detected'] ?></div>
                <div class="stat-sub">today</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Scripts Monitored</div>
                <div class="stat-value blue"><?= (int)$stats['scripts_monitored'] ?></div>
                <div class="stat-sub">on checkout page</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">SRI Verified</div>
                <div class="stat-value green"><?= (int)$stats['sri_verified'] ?></div>
                <div class="stat-sub">scripts trusted</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">CSP Violations</div>
                <div class="stat-value yellow"><?= (int)$stats['csp_violations'] ?></div>
                <div class="stat-sub">last 24 hrs</div>
            </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">

            <!-- Recent alerts -->
            <div>
                <div class="section-head">Recent Alerts</div>
                <div class="alert-list">
                    <?php if (empty($recentIncidents)): ?>
                        <p style="color:var(--text-dim);font-size:13px;">No incidents recorded yet.</p>
                    <?php endif; ?>
                    <?php foreach ($recentIncidents as $inc): ?>
                        <div class="alert-item <?= severityClass($inc['severity']) ?>"
                             onclick="window.location='incidents.php'">
                            <div>
                                <div class="alert-title">
                                    ⚠ <?= htmlspecialchars(ucwords(str_replace('_',' ',$inc['threat_type']))) ?>
                                    <?= $inc['target_detail'] ? '— '.htmlspecialchars($inc['target_detail']) : '' ?>
                                </div>
                                <div class="alert-detail">
                                    <?= htmlspecialchars($inc['source_detail'] ?? '—') ?> ·
                                    <?= htmlspecialchars($inc['detected_at']) ?> ·
                                    <?= strtoupper(htmlspecialchars($inc['status'])) ?>
                                </div>
                            </div>
                            <span class="badge <?= severityBadge($inc['severity']) ?>">
                                <?= strtoupper($inc['severity']) ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Recent scripts — clickable -->
            <div>
                <div class="section-head">Monitored Scripts <span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:11px;">— click for details</span></div>
                <table class="table">
                    <thead><tr><th>Script</th><th>Status</th></tr></thead>
                    <tbody>
                        <?php foreach ($recentScripts as $s): ?>
                        <tr class="clickable-row"
                            onclick='showPopup(event, <?= htmlspecialchars(json_encode([
                                "src"      => $s["script_src"],
                                "status"   => $s["status"],
                                "origin"   => $s["origin"],
                                "hash"     => $s["sri_hash"] ?? "— not set —",
                                "expected" => $s["expected_hash"] ?? "— not set —",
                                "checked"  => $s["last_checked"],
                                "first"    => $s["first_seen"],
                            ]), ENT_QUOTES) ?>)'>
                            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                                <?= htmlspecialchars($s['script_src']) ?>
                            </td>
                            <td>
                                <span class="status-dot <?= sdot($s['status']) ?>"></span>
                                <?= strtoupper(str_replace('_',' ',$s['status'])) ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
function showPopup(e, data) {
    const p = document.getElementById('scriptPopup');
    document.getElementById('pp-src').textContent     = data.src;
    document.getElementById('pp-status').textContent  = data.status.toUpperCase();
    document.getElementById('pp-origin').textContent  = data.origin.replace('_',' ').toUpperCase();
    document.getElementById('pp-hash').textContent    = data.hash;
    document.getElementById('pp-expected').textContent= data.expected;
    document.getElementById('pp-checked').textContent = data.checked;
    document.getElementById('pp-first').textContent   = data.first;
    p.style.left = Math.min(e.clientX + 10, window.innerWidth - 400) + 'px';
    p.style.top  = Math.min(e.clientY + 10, window.innerHeight - 300) + 'px';
    p.classList.add('visible');
    e.stopPropagation();
}
function closePopup() {
    document.getElementById('scriptPopup').classList.remove('visible');
}
document.addEventListener('click', function(e) {
    const p = document.getElementById('scriptPopup');
    if (p && !p.contains(e.target)) closePopup();
});
</script>
</body>
</html>
