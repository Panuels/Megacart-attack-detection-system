<?php
if (session_status() === PHP_SESSION_NONE) session_start();

function isLoggedIn() {
    return isset($_SESSION['admin_id']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}

function attemptLogin($username, $password) {
    $conn = getDbConnection();
    $stmt = $conn->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password_hash'])) {
            $_SESSION['admin_id']       = $user['id'];
            $_SESSION['admin_username'] = $user['username'];
            return true;
        }
    }
    return false;
}

function changePassword($userId, $currentPassword, $newPassword) {
    if (strlen($newPassword) < 8) return 'New password must be at least 8 characters.';
    $conn = getDbConnection();
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = ?");
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!$row || !password_verify($currentPassword, $row['password_hash'])) {
        return 'Current password is incorrect.';
    }
    $hash = password_hash($newPassword, PASSWORD_DEFAULT);
    $upd  = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
    $upd->bind_param('si', $hash, $userId);
    $upd->execute();
    return true;
}

function logout() {
    session_unset();
    session_destroy();
}
