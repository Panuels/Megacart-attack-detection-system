<?php
function getSettings() {
    $conn = getDbConnection();
    $result = $conn->query("SELECT setting_key, setting_value FROM settings");
    $settings = [];
    while ($row = $result->fetch_assoc()) {
        $settings[$row['setting_key']] = $row['setting_value'];
    }
    return array_merge([
        'theme'                    => 'dark',
        'owner_email'              => '',
        'email_alerts_enabled'     => '0',
        'alert_severity_threshold' => 'low',   // default: alert on ALL
        'resend_api_key'           => '',
    ], $settings);
}

function updateSettings(array $data) {
    $conn = getDbConnection();
    $stmt = $conn->prepare(
        "INSERT INTO settings (setting_key, setting_value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)"
    );
    foreach ($data as $key => $value) {
        $stmt->bind_param('ss', $key, $value);
        $stmt->execute();
    }
}

function bodyThemeClass() {
    $s = getSettings();
    return $s['theme'] === 'light' ? 'theme-light' : '';
}
