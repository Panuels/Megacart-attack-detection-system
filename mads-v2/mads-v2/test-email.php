<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/mailer.php';

requireLogin();
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'test_email') {
    $settings = getSettings();
    $apiKey   = trim($settings['resend_api_key'] ?? '');
    $toEmail  = trim($settings['owner_email'] ?? '');

    if ($apiKey === '') {
        echo json_encode(['ok'=>false,'error'=>'Resend API key not configured. Go to Settings and add your key.']);
        exit;
    }
    if ($toEmail === '') {
        echo json_encode(['ok'=>false,'error'=>'Owner email not set. Go to Settings and add your email.']);
        exit;
    }

    $sent = sendAlertEmail('test_alert','MADS Test Email','Settings → Test Email','low','test');
    echo json_encode(['ok' => $sent, 'error' => $sent ? null : 'API call failed. Check your Resend API key is valid.']);
    exit;
}

echo json_encode(['ok'=>false,'error'=>'Invalid request.']);
