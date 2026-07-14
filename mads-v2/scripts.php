<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';

requireLogin();
$activePage = 'scripts.php';

$conn    = getDbConnection();
$scripts = $conn->query("SELECT * FROM scripts ORDER BY last_checked DESC")->fetch_all(MYSQLI_ASSOC);

function sdot($s)   { return match($s) { 'verified'=>'ok','blocked'=>'fail',default=>'warn' }; }
function obadge($o) { return match($o) { 'cdn'=>'blue','third_party'=>'green','local'=>'blue',default=>'yellow' }; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MADS — Script Monitor</title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= bodyThemeClass() ?>">

<!-- Popup -->
<div class="script-popup" id="scriptPopup">
    <button class="popup-close" onclick="closePopup()">✕</button>
    <h3 id="pp-src">Script Details</h3>
    <div class="popup-row"><span class="popup-key">Status</span>     <span class="popup-val" id="pp-status"></span></div>
    <div class="popup-row"><span class="popup-key">Origin</span>     <span class="popup-val" id="pp-origin"></span></div>
    <div class="popup-row"><span class="popup-key">SRI Hash</span>   <span class="popup-val" id="pp-hash"></span></div>
    <div class="popup-row"><span class="popup-key">Expected Hash</span><span class="popup-val" id="pp-expected"></span></div>
    <div class="popup-row"><span class="popup-key">Last Checked</span><span class="popup-val" id="pp-checked"></span></div>
    <div class="popup-row"><span class="popup-key">First Seen</span> <span class="popup-val" id="pp-first"></span></div>
    <div class="popup-row" id="pp-threat-row" style="display:none;">
        <span class="popup-key">⚠ Threat</span>
        <span class="popup-val" id="pp-threat" style="color:var(--accent2);"></span>
    </div>
</div>

<div class="topbar">
    <div class="topbar-logo">MADS <span>/ Script Monitor</span></div>
    <div class="topbar-right">
        <span class="badge green">● SCANNING</span>
    </div>
</div>

<div class="layout">
    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content">
        <div class="section-head">
            JavaScript Inventory — checkout.php
            <span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:11px;margin-left:8px;">
                — click any row for full details
            </span>
        </div>

        <table class="table">
            <thead>
                <tr>
                    <th>Script Source</th>
                    <th>SRI Hash</th>
                    <th>Origin</th>
                    <th>Status</th>
                    <th>Last Checked</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($scripts)): ?>
                    <tr><td colspan="5" style="color:var(--text-dim);">No scripts recorded yet. Run the attack simulation to populate.</td></tr>
                <?php endif; ?>
                <?php foreach ($scripts as $s):
                    // fetch related incident for this script if any
                    $incStmt = $conn->prepare("SELECT threat_type FROM incidents WHERE script_id = ? ORDER BY detected_at DESC LIMIT 1");
                    $incStmt->bind_param('i', $s['id']);
                    $incStmt->execute();
                    $inc = $incStmt->get_result()->fetch_assoc();
                    $threat = $inc ? ucwords(str_replace('_',' ',$inc['threat_type'])) : null;
                ?>
                <tr class="clickable-row"
                    onclick='showPopup(event, <?= htmlspecialchars(json_encode([
                        "src"      => $s["script_src"],
                        "status"   => $s["status"],
                        "origin"   => $s["origin"],
                        "hash"     => $s["sri_hash"] ?? "— not set —",
                        "expected" => $s["expected_hash"] ?? "— not set —",
                        "checked"  => $s["last_checked"],
                        "first"    => $s["first_seen"],
                        "threat"   => $threat,
                    ]),ENT_QUOTES) ?>)'>
                    <td><?= htmlspecialchars($s['script_src']) ?></td>
                    <td style="color:var(--text-dim);font-size:10px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        <?= htmlspecialchars($s['sri_hash'] ?? '— not set —') ?>
                    </td>
                    <td><span class="badge <?= obadge($s['origin']) ?>"><?= strtoupper(str_replace('_',' ',$s['origin'])) ?></span></td>
                    <td><span class="status-dot <?= sdot($s['status']) ?>"></span><?= strtoupper(str_replace('_',' ',$s['status'])) ?></td>
                    <td style="color:var(--text-dim);"><?= htmlspecialchars($s['last_checked']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<script>
function showPopup(e, data) {
    const p = document.getElementById('scriptPopup');
    document.getElementById('pp-src').textContent      = data.src;
    document.getElementById('pp-status').textContent   = data.status.replace(/_/g,' ').toUpperCase();
    document.getElementById('pp-origin').textContent   = data.origin.replace(/_/g,' ').toUpperCase();
    document.getElementById('pp-hash').textContent     = data.hash;
    document.getElementById('pp-expected').textContent = data.expected;
    document.getElementById('pp-checked').textContent  = data.checked;
    document.getElementById('pp-first').textContent    = data.first;
    const tr = document.getElementById('pp-threat-row');
    if (data.threat) {
        document.getElementById('pp-threat').textContent = data.threat;
        tr.style.display = 'flex';
    } else { tr.style.display = 'none'; }
    p.style.left = Math.min(e.clientX + 12, window.innerWidth  - 410) + 'px';
    p.style.top  = Math.min(e.clientY + 12, window.innerHeight - 320) + 'px';
    p.classList.add('visible');
    e.stopPropagation();
}
function closePopup() { document.getElementById('scriptPopup').classList.remove('visible'); }
document.addEventListener('click', function(e) {
    const p = document.getElementById('scriptPopup');
    if (p && !p.contains(e.target)) closePopup();
});
</script>
</body>
</html>
