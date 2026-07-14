<?php
$navItems = [
    'dashboard.php'  => ['icon' => '◈', 'label' => 'Dashboard'],
    'scripts.php'    => ['icon' => '⬡', 'label' => 'Scripts'],
    'incidents.php'  => ['icon' => '◎', 'label' => 'Incidents'],
    'csp-config.php' => ['icon' => '⊞', 'label' => 'CSP Config'],
    'reports.php'    => ['icon' => '▤', 'label' => 'Reports'],
    'simulate.php'   => ['icon' => '⚡', 'label' => 'Attack Simulation'],
    'settings.php'   => ['icon' => '⊙', 'label' => 'Settings'],
];
$settings = getSettings();
?>
<div class="sidebar">
    <?php foreach ($navItems as $href => $item): ?>
        <a href="<?= $href ?>" class="nav-item <?= ($activePage ?? '') === $href ? 'active' : '' ?>
            <?= $href === 'simulate.php' ? 'nav-sim' : '' ?>">
            <span class="nav-icon"><?= $item['icon'] ?></span>
            <?= $item['label'] ?>
        </a>
    <?php endforeach; ?>

    <div class="sidebar-footer">
        <div style="font-size:10px;color:var(--text-dim);font-family:monospace;padding:16px 22px 4px;">OPERATOR</div>
        <div style="font-size:12px;color:var(--text);padding:0 22px 8px;font-weight:600;">
            <?= htmlspecialchars($_SESSION['admin_username'] ?? 'admin') ?>
        </div>
        <a href="logout.php" style="display:block;padding:8px 22px;font-size:11px;color:var(--text-dim);font-family:monospace;">
            ⇥ Logout
        </a>
        <div style="padding:10px 22px;font-size:10px;color:var(--text-dim);font-family:monospace;">
            API Status: <span style="color:var(--accent3);">ok</span>
        </div>
    </div>
</div>
