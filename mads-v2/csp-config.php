<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';

requireLogin();
$activePage = 'csp-config.php';

$conn = getDbConnection();
$message = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $directives = $_POST['directive'] ?? [];
    $values = $_POST['value'] ?? [];
    $active = $_POST['active'] ?? []; // checkbox array of active directive names

    foreach ($directives as $i => $directive) {
        $value = $values[$i] ?? '';
        $isActive = in_array($directive, $active, true) ? 1 : 0;

        $stmt = $conn->prepare(
            "UPDATE csp_rules SET value = ?, is_active = ? WHERE directive = ?"
        );
        $stmt->bind_param('sis', $value, $isActive, $directive);
        $stmt->execute();
    }

    $message = 'CSP policy updated successfully.';
}

$rules = $conn->query("SELECT * FROM csp_rules ORDER BY id ASC")->fetch_all(MYSQLI_ASSOC);
$activeCount = count(array_filter($rules, fn($r) => $r['is_active']));
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MADS — CSP Configuration</title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= bodyThemeClass() ?>">

<div class="topbar">
    <div class="topbar-logo">MADS <span>/ CSP Configuration</span></div>
    <div class="topbar-right">
        <span class="badge green">● <?= $activeCount ?> RULES ACTIVE</span>
        <a href="logout.php" style="color:var(--text-dim);">Logout</a>
    </div>
</div>

<div class="layout">
    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content">
        <div class="section-head">Content Security Policy Rules</div>

        <?php if ($message): ?>
            <div class="badge green" style="display:block;width:fit-content;padding:8px 14px;margin-bottom:16px;">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <form method="POST">
            <?php foreach ($rules as $rule): ?>
                <div class="csp-row">
                    <div class="csp-key"><?= htmlspecialchars($rule['directive']) ?></div>
                    <input type="hidden" name="directive[]" value="<?= htmlspecialchars($rule['directive']) ?>">
                    <input type="text" name="value[]" class="csp-val" value="<?= htmlspecialchars($rule['value']) ?>">
                    <label class="toggle-wrap">
                        <input type="checkbox"
                               name="active[]"
                               value="<?= htmlspecialchars($rule['directive']) ?>"
                               <?= $rule['is_active'] ? 'checked' : '' ?>
                               style="display:none;"
                               onclick="this.nextElementSibling.classList.toggle('on')">
                        <div class="toggle <?= $rule['is_active'] ? 'on' : '' ?>"></div>
                    </label>
                </div>
            <?php endforeach; ?>

            <div style="margin-top:24px;display:flex;gap:10px;">
                <button type="submit" class="filter-btn" style="background:var(--accent);color:#000;border:none;font-weight:700;">
                    SAVE POLICY
                </button>
                <button type="button" class="filter-btn">TEST IN REPORT-ONLY MODE</button>
            </div>
        </form>
    </div>
</div>

</body>
</html>
