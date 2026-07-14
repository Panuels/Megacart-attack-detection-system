<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/detector.php';

requireLogin();
$activePage = 'simulate.php';

// ── AJAX endpoint: run the attack simulation ──────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'run_sim') {
    header('Content-Type: application/json');

    $scenario  = $_POST['scenario'] ?? 'sri_mismatch';
    $cardName  = htmlspecialchars(trim($_POST['card_name']  ?? 'John Doe'));
    $cardNum   = preg_replace('/\D/','',$_POST['card_number'] ?? '4111111111111111');
    $cardNum   = substr($cardNum,0,4).'****'.substr($cardNum,-4);

    // ── Define scenarios ──────────────────────────────────────────────────
    $scenarios = [
        'sri_mismatch' => [
            'script_src'    => 'analytics-v2.min.js',
            'actual_hash'   => 'sha384-TAMPERED_HASH_000000000000000',
            'expected_hash' => 'sha384-ORIGINAL_HASH_999999999999999',
            'origin'        => 'cdn',
            'destination'   => '',
            'target_field'  => 'checkout page',
            'steps' => [
                ['ms'=>400,  'cls'=>'log-warn', 'msg'=>'[00:00:001] Attacker payload delivered via compromised CDN endpoint'],
                ['ms'=>900,  'cls'=>'log-warn', 'msg'=>'[00:00:043] Script tag injected into <head> of /checkout'],
                ['ms'=>1500, 'cls'=>'log-err',  'msg'=>'[00:00:089] Malicious script executing in browser context...'],
                ['ms'=>2200, 'cls'=>'log-err',  'msg'=>'[00:00:124] SRI hash mismatch detected — script has been tampered with'],
                ['ms'=>3000, 'cls'=>'log-ok',   'msg'=>'[00:00:201] MADS blocked script execution'],
                ['ms'=>3500, 'cls'=>'log-ok',   'msg'=>'[00:00:244] Incident logged → severity: CRITICAL'],
                ['ms'=>4000, 'cls'=>'log-ok',   'msg'=>'[00:00:280] Email alert dispatched to owner ✓'],
            ],
        ],
        'card_skimmer' => [
            'script_src'    => 'track.js',
            'actual_hash'   => '',
            'expected_hash' => '',
            'origin'        => 'unknown',
            'destination'   => 'data-collector.ru',
            'target_field'  => '#card_number',
            'steps' => [
                ['ms'=>300,  'cls'=>'log-warn', 'msg'=>'[00:00:012] Unknown script loaded from external domain'],
                ['ms'=>800,  'cls'=>'log-warn', 'msg'=>'[00:00:058] Script attached event listener to #card_number field'],
                ['ms'=>1400, 'cls'=>'log-err',  'msg'=>'[00:00:103] Taint tracking: card data "'.$cardNum.'" captured by script'],
                ['ms'=>2000, 'cls'=>'log-err',  'msg'=>'[00:00:147] Data exfiltration attempt → data-collector.ru NOT in CSP allowlist'],
                ['ms'=>2600, 'cls'=>'log-ok',   'msg'=>'[00:00:198] MADS blocked outbound POST request'],
                ['ms'=>3200, 'cls'=>'log-ok',   'msg'=>'[00:00:241] Incident logged → severity: CRITICAL'],
                ['ms'=>3800, 'cls'=>'log-ok',   'msg'=>'[00:00:289] Email alert dispatched to owner ✓'],
            ],
        ],
        'csp_violation' => [
            'script_src'    => 'inline-tracker.js',
            'actual_hash'   => '',
            'expected_hash' => '',
            'origin'        => 'unknown',
            'destination'   => 'evil-track.io',
            'target_field'  => 'checkout page',
            'steps' => [
                ['ms'=>350,  'cls'=>'log-warn', 'msg'=>'[00:00:008] Inline script detected on checkout page'],
                ['ms'=>850,  'cls'=>'log-warn', 'msg'=>'[00:00:052] Script attempted to load external resource'],
                ['ms'=>1400, 'cls'=>'log-err',  'msg'=>'[00:00:094] CSP violation: evil-track.io blocked by policy'],
                ['ms'=>2000, 'cls'=>'log-ok',   'msg'=>'[00:00:133] Browser enforced CSP — request cancelled'],
                ['ms'=>2600, 'cls'=>'log-ok',   'msg'=>'[00:00:178] Violation report sent to MADS endpoint'],
                ['ms'=>3200, 'cls'=>'log-ok',   'msg'=>'[00:00:212] Incident logged → severity: HIGH'],
                ['ms'=>3800, 'cls'=>'log-ok',   'msg'=>'[00:00:255] Email alert dispatched to owner ✓'],
            ],
        ],
        'legit' => [
            'script_src'    => 'jquery-3.6.0.min.js',
            'actual_hash'   => 'sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg',
            'expected_hash' => 'sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg',
            'origin'        => 'cdn',
            'destination'   => '',
            'target_field'  => '',
            'steps' => [
                ['ms'=>400,  'cls'=>'log-info', 'msg'=>'[00:00:010] Script loaded from CDN'],
                ['ms'=>900,  'cls'=>'log-ok',   'msg'=>'[00:00:048] SRI hash verified — content matches expected hash'],
                ['ms'=>1500, 'cls'=>'log-ok',   'msg'=>'[00:00:082] No external data connections detected'],
                ['ms'=>2000, 'cls'=>'log-ok',   'msg'=>'[00:00:110] Script cleared — no threat detected ✓'],
            ],
        ],
    ];

    $sc = $scenarios[$scenario] ?? $scenarios['sri_mismatch'];

    // ── Run the actual detection logic ───────────────────────────────────
    $findings = [];
    $scriptId = null;

    // SRI check
    $sriStatus = verifyScriptIntegrity($sc['actual_hash'], $sc['expected_hash']);
    $dbStatus  = $sriStatus; // 'verified','no_sri','blocked'

    if ($scenario === 'legit') {
        $scriptId = ensureScriptRecord($sc['script_src'], $sc['actual_hash'], $sc['expected_hash'], $sc['origin'], 'verified');
        $findings[] = ['verdict'=>'PASS','detail'=>'SRI hash verified — script is clean.'];
    } else {
        $scriptId = ensureScriptRecord($sc['script_src'], $sc['actual_hash'] ?: null, $sc['expected_hash'] ?: null, $sc['origin'], $dbStatus === 'verified' ? 'verified' : 'blocked');

        if ($sriStatus === 'blocked') {
            logIncident($scriptId, 'sri_mismatch',
                '[SIMULATED] '.$sc['script_src'], $sc['target_field'], 'critical', 'blocked');
            $findings[] = ['verdict'=>'FAIL','detail'=>'SRI hash mismatch — script tampered. Blocked.'];
        } elseif ($sriStatus === 'no_sri') {
            $findings[] = ['verdict'=>'WARN','detail'=>'No SRI hash — integrity unverifiable.'];
        }

        if ($sc['destination'] !== '') {
            $allowed = isDestinationAllowed($sc['destination']);
            if (!$allowed) {
                logIncident($scriptId, 'taint_alert',
                    '[SIMULATED] '.($sc['target_field'] ?: 'sensitive field'),
                    $sc['destination'], 'critical', 'blocked');
                $findings[] = ['verdict'=>'FAIL','detail'=>'Data exfiltration to '.$sc['destination'].' — NOT in CSP. Blocked.'];
            }
        }

        if ($scenario === 'csp_violation') {
            logIncident($scriptId, 'csp_violation',
                '[SIMULATED] '.$sc['script_src'], $sc['destination'], 'high', 'reviewing');
            $findings[] = ['verdict'=>'FAIL','detail'=>'CSP violation detected and reported.'];
        }
    }

    echo json_encode(['ok'=>true,'steps'=>$sc['steps'],'findings'=>$findings,'scenario'=>$scenario]);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MADS — Attack Simulation</title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= bodyThemeClass() ?>">

<div class="topbar">
    <div class="topbar-logo">MADS <span>/ Attack Simulation</span></div>
    <div class="topbar-right">
        <span class="badge yellow">⚡ LAB MODE</span>
    </div>
</div>

<div class="layout">
    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content">
        <div style="margin-bottom:18px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
            <div>
                <h2 style="font-size:22px;font-weight:700;color:var(--text-bright);display:flex;align-items:center;gap:10px;">
                    ⚡ Attack Simulation
                </h2>
                <p style="font-size:12px;color:var(--text-dim);margin-top:4px;">
                    Controlled Magecart injection demo — safe, sandboxed environment only
                </p>
            </div>
            <div style="margin-left:auto;display:flex;gap:8px;align-items:center;">
                <label style="font-family:monospace;font-size:11px;color:var(--text-dim);">ATTACK SCENARIO:</label>
                <select id="scenarioSelect" class="filter-input" style="width:auto;min-width:220px;">
                    <option value="sri_mismatch">SRI Hash Mismatch (Tampered CDN Script)</option>
                    <option value="card_skimmer">Card Skimmer (Data Exfiltration)</option>
                    <option value="csp_violation">CSP Violation (Inline Tracker)</option>
                    <option value="legit">Legitimate Script (No Threat)</option>
                </select>
            </div>
        </div>

        <div class="sim-layout">

            <!-- LEFT: Fake checkout page -->
            <div class="checkout-chrome">
                <div class="checkout-chrome-bar">
                    <div class="chrome-dots">
                        <div class="chrome-dot" style="background:#ff5f56;"></div>
                        <div class="chrome-dot" style="background:#ffbd2e;"></div>
                        <div class="chrome-dot" style="background:#27c93f;"></div>
                    </div>
                    <div class="chrome-url">🔒 shop.example.com/checkout</div>
                </div>

                <div class="checkout-body">
                    <div class="checkout-title">🛍️ ShopEasy Checkout</div>

                    <div class="checkout-field-label">👤 CARDHOLDER NAME</div>
                    <input type="text" class="checkout-field" id="card_name"
                           placeholder="Full name on card" value="Njeri Wakwetu">

                    <div class="checkout-field-label">💳 CARD NUMBER</div>
                    <input type="text" class="checkout-field" id="card_number"
                           placeholder="1234 5678 9012 3456" value="4111 1111 1111 1111"
                           maxlength="19" oninput="formatCard(this)">

                    <div class="checkout-row">
                        <div>
                            <div class="checkout-field-label">📅 EXPIRY</div>
                            <input type="text" class="checkout-field" id="card_expiry"
                                   placeholder="MM/YYYY" value="2/2027" maxlength="7">
                        </div>
                        <div>
                            <div class="checkout-field-label">🔒 CVV</div>
                            <input type="text" class="checkout-field" id="card_cvv"
                                   placeholder="3-digit code" value="980" maxlength="4">
                        </div>
                    </div>

                    <div class="checkout-field-label">📍 BILLING ADDRESS</div>
                    <input type="text" class="checkout-field" id="billing_address"
                           placeholder="Street, City, Country" value="Nairobi, Kenya">

                    <button class="checkout-btn" id="purchaseBtn" onclick="runSimulation()">
                        <span id="btnText">Complete Purchase — $129.99</span>
                    </button>

                    <div id="purchaseResult" style="display:none;margin-top:14px;text-align:center;font-size:12px;font-family:monospace;"></div>
                </div>
            </div>

            <!-- RIGHT: Attack log panel -->
            <div>
                <div class="attack-panel">
                    <div class="attack-panel-head">
                        <h3>🔴 Magecart Attack Simulator</h3>
                        <p>Simulates a script injection on the checkout page. MADS will detect it, log an incident, and flag the script — exactly as it would in a real attack.</p>
                    </div>

                    <div class="attack-log-header">
                        <span>_ Attack Log</span>
                        <span class="live-dot" id="liveDot" style="display:none;">LIVE</span>
                        <span id="idleText" style="font-family:monospace;font-size:11px;color:var(--text-dim);">● IDLE</span>
                    </div>

                    <div class="attack-log-body" id="attackLog">
                        <span style="color:var(--text-dim);">Awaiting simulation... Fill in card details and click Complete Purchase.</span>
                    </div>
                </div>

                <!-- Result card -->
                <div class="sim-result-card" id="simResult">
                    <div id="resultHeader" style="font-weight:700;font-size:13px;margin-bottom:10px;"></div>
                    <div id="resultFindings"></div>
                    <div style="margin-top:12px;font-size:11px;color:var(--text-dim);font-family:monospace;">
                        ↳ Check <a href="incidents.php" style="color:var(--accent);">Incident Log</a> and
                          <a href="scripts.php" style="color:var(--accent);">Scripts</a> for the recorded entry.
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function formatCard(el) {
    let v = el.value.replace(/\D/g,'').substring(0,16);
    el.value = v.replace(/(.{4})/g,'$1 ').trim();
}

async function runSimulation() {
    const btn      = document.getElementById('purchaseBtn');
    const log      = document.getElementById('attackLog');
    const liveDot  = document.getElementById('liveDot');
    const idleText = document.getElementById('idleText');
    const result   = document.getElementById('simResult');
    const scenario = document.getElementById('scenarioSelect').value;

    // Validate fields
    const name    = document.getElementById('card_name').value.trim();
    const cardNum = document.getElementById('card_number').value.trim();
    const expiry  = document.getElementById('card_expiry').value.trim();
    const cvv     = document.getElementById('card_cvv').value.trim();

    if (!name || !cardNum || !expiry || !cvv) {
        alert('Please fill in all card details before completing purchase.');
        return;
    }

    btn.disabled = true;
    document.getElementById('btnText').textContent = 'Processing...';
    log.innerHTML = '';
    result.classList.remove('visible');
    liveDot.style.display = 'flex';
    idleText.style.display = 'none';
    document.getElementById('purchaseResult').style.display = 'none';

    // Call the PHP backend
    const fd = new FormData();
    fd.append('action', 'run_sim');
    fd.append('scenario', scenario);
    fd.append('card_name', name);
    fd.append('card_number', cardNum);

    const resp = await fetch('simulate.php', { method: 'POST', body: fd });
    const data = await resp.json();

    // Stream the log lines with realistic timing
    for (const step of data.steps) {
        await delay(step.ms / (data.steps.length > 4 ? 1 : 1));
        appendLog(log, step.msg, step.cls);
    }

    // Show result
    await delay(500);
    liveDot.style.display = 'none';
    idleText.style.display = '';
    idleText.textContent   = '● COMPLETE';

    const isLegit   = scenario === 'legit';
    const hdr       = document.getElementById('resultHeader');
    hdr.textContent = isLegit ? '✅ No threat detected — script is clean' : '🚨 Threat detected and blocked by MADS';
    hdr.style.color = isLegit ? 'var(--accent3)' : 'var(--accent2)';

    const findingsEl = document.getElementById('resultFindings');
    findingsEl.innerHTML = '';
    for (const f of data.findings) {
        const color = f.verdict === 'PASS' ? 'var(--accent3)' : f.verdict === 'FAIL' ? 'var(--accent2)' : 'var(--warn)';
        findingsEl.innerHTML +=
            `<div style="font-size:11px;font-family:monospace;color:${color};margin-bottom:5px;">
                ${f.verdict === 'PASS' ? '✓' : f.verdict === 'FAIL' ? '✕' : '⚠'} ${f.detail}
             </div>`;
    }
    result.classList.add('visible');

    // Show payment result in checkout
    const pr = document.getElementById('purchaseResult');
    pr.style.display = 'block';
    if (isLegit) {
        pr.innerHTML = '<span style="color:var(--accent3);">✓ Payment successful — $129.99 charged</span>';
        document.getElementById('btnText').textContent = '✓ Purchase Complete';
    } else {
        pr.innerHTML = '<span style="color:var(--accent2);">✕ Payment blocked — malicious script detected</span>';
        document.getElementById('btnText').textContent = 'Blocked by MADS';
    }
    btn.disabled = false;
}

function appendLog(container, msg, cls) {
    const line = document.createElement('div');
    line.className = 'log-line ' + (cls || '');
    line.textContent = msg;
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
</script>
</body>
</html>
