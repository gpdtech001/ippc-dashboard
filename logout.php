<?php
require_once 'config.php';

session_start();

// Clear remember token from database if exists
if (isset($_SESSION['user_id'])) {
    $users = getUsers();
    foreach ($users as &$user) {
        if ($user['id'] == $_SESSION['user_id']) {
            $user['remember_token'] = null;
            break;
        }
    }
    saveUsers($users);
}

// Clear remember cookie
if (isset($_COOKIE['remember_token'])) {
    setcookie('remember_token', '', time() - 3600, '/');
}

// Destroy session
session_destroy();

// Redirect to login page
header('Location: login.php');
exit;
?>


