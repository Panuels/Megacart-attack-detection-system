USE mads_db;
CREATE TABLE IF NOT EXISTS settings (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    setting_key   VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL DEFAULT '',
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT IGNORE INTO settings (setting_key, setting_value) VALUES
('theme','dark'),('owner_email',''),('email_alerts_enabled','0'),
('resend_api_key',''),('alert_severity_threshold','low');
