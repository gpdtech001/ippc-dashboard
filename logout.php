<?php
require_once 'config.php';

session_start();

// Clear remember token from database/cookie if exists
if (isset($_SESSION['user_id'])) {
    clearRememberToken($_SESSION['user_id']);
} else {
    clearRememberToken(null);
}

// Destroy session
session_destroy();

// Redirect to login page
header('Location: login.php');
exit;
?>

