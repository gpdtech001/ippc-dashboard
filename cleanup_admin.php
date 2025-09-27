<?php
require_once 'config.php';

if (PHP_SAPI !== 'cli') {
    session_start();
    requireAdmin();
}

$users = getUsers();
echo 'Before cleanup:' . PHP_EOL;
$adminCount = 0;
foreach ($users as $user) {
    if ($user['username'] === 'admin') {
        $adminCount++;
        echo '  - ID: ' . $user['id'] . ', Name: ' . $user['name'] . PHP_EOL;
    }
}
echo 'Total admin users: ' . $adminCount . PHP_EOL . PHP_EOL;

if ($adminCount > 1) {
    // Keep only the first admin user
    $cleanedUsers = [];
    $adminFound = false;

    foreach ($users as $user) {
        if ($user['username'] === 'admin') {
            if (!$adminFound) {
                $cleanedUsers[] = $user;
                $adminFound = true;
                echo 'Keeping admin user: ' . $user['name'] . ' (ID: ' . $user['id'] . ')' . PHP_EOL;
            } else {
                echo 'Removing duplicate admin user: ' . $user['name'] . ' (ID: ' . $user['id'] . ')' . PHP_EOL;
            }
        } else {
            $cleanedUsers[] = $user;
        }
    }

    saveUsers($cleanedUsers);
    echo PHP_EOL . '✅ Successfully cleaned up duplicate admin users!' . PHP_EOL;
    echo 'Remaining users: ' . count($cleanedUsers) . PHP_EOL;
} else {
    echo 'No cleanup needed - only one admin user found.' . PHP_EOL;
}
?>

