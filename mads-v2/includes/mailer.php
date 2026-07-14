<?php
/**
 * MADS Mailer — powered by Resend (https://resend.com)
 * Sends email alerts for ALL severity levels via Resend's HTTP API.
 * No SMTP, no PHPMailer needed — pure cURL.
 */

function sendAlertEmail($threatType, $sourceDetail, $targetDetail, $severity, $status) {
    $settings = getSettings();

    $apiKey    = trim($settings['resend_api_key'] ?? '');
    $toEmail   = trim($settings['owner_email'] ?? '');
    $enabled   = (bool)($settings['email_alerts_enabled'] ?? false);

    // Always send for ALL severities — just needs email + key configured
    if (!$enabled || $apiKey === '' || $toEmail === '') {
        return false;
    }

    $severityColors = [
        'critical' => '#ff3d71',
        'high'     => '#ffb300',
        'medium'   => '#00e5ff',
        'low'      => '#00ff9d',
    ];
    $color      = $severityColors[$severity] ?? '#aaaaaa';
    $severityUC = strtoupper($severity);
    $threatName = ucwords(str_replace('_', ' ', $threatType));
    $timestamp  = date('Y-m-d H:i:s');

    $html = <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0c10;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0c10;padding:40px 0;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#0f1218;border:1px solid #1e2535;border-radius:8px;overflow:hidden;">
        <!-- Header -->
        <tr>
          <td style="background:{$color};padding:20px 28px;">
            <span style="font-size:22px;font-weight:700;color:#000;letter-spacing:2px;">🛡️ MADS ALERT</span>
          </td>
        </tr>
        <!-- Severity badge -->
        <tr>
          <td style="padding:24px 28px 0;">
            <span style="display:inline-block;background:{$color};color:#000;font-size:11px;font-weight:700;padding:4px 12px;border-radius:3px;letter-spacing:1px;">{$severityUC}</span>
          </td>
        </tr>
        <!-- Threat name -->
        <tr>
          <td style="padding:12px 28px 0;">
            <h2 style="margin:0;font-size:20px;color:#eaf2ff;">{$threatName} Detected</h2>
          </td>
        </tr>
        <!-- Details table -->
        <tr>
          <td style="padding:20px 28px;">
            <table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
              <tr style="border-bottom:1px solid #1e2535;">
                <td style="color:#5a6a80;font-size:11px;font-family:monospace;width:120px;">TIMESTAMP</td>
                <td style="color:#c8d6e5;font-size:12px;font-family:monospace;">{$timestamp}</td>
              </tr>
              <tr style="border-bottom:1px solid #1e2535;">
                <td style="color:#5a6a80;font-size:11px;font-family:monospace;">SOURCE</td>
                <td style="color:#c8d6e5;font-size:12px;font-family:monospace;">{$sourceDetail}</td>
              </tr>
              <tr style="border-bottom:1px solid #1e2535;">
                <td style="color:#5a6a80;font-size:11px;font-family:monospace;">TARGET</td>
                <td style="color:#c8d6e5;font-size:12px;font-family:monospace;">{$targetDetail}</td>
              </tr>
              <tr>
                <td style="color:#5a6a80;font-size:11px;font-family:monospace;">STATUS</td>
                <td style="color:#c8d6e5;font-size:12px;font-family:monospace;">{$status}</td>
              </tr>
            </table>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding:16px 28px 24px;border-top:1px solid #1e2535;">
            <p style="margin:0;font-size:11px;color:#5a6a80;font-family:monospace;">
              MADS — Magecart Attack Detection System · Zetech University<br>
              This is an automated security alert. Do not reply to this email.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
HTML;

    $payload = json_encode([
        'from'    => 'MADS Alerts <onboarding@resend.dev>',
        'to'      => [$toEmail],
        'subject' => "[MADS] {$severityUC} — {$threatName} detected",
        'html'    => $html,
    ]);

    $ch = curl_init('https://api.resend.com/emails');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $apiKey,
            'Content-Type: application/json',
        ],
        CURLOPT_TIMEOUT        => 10,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return $httpCode === 200 || $httpCode === 201;
}
