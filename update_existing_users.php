<?php
require_once 'config.php';

$users = getUsers();
$updated = 0;

foreach ($users as &$user) {
    // If user doesn't have a status field, set them as approved
    if (!isset($user['status'])) {
        $user['status'] = STATUS_APPROVED;
        $user['approved_at'] = $user['created_at']; // Use creation date as approval date
        $user['approved_by'] = 'system'; // Mark as system-approved
        $updated++;
        echo "Updated user: {$user['name']} ({$user['username']})\n";
    }
}

if ($updated > 0) {
    saveUsers($users);
    echo "\n✅ Successfully updated {$updated} existing users with approved status.\n";
} else {
    echo "ℹ️  All users already have status fields.\n";
}

echo "\nFinal user status:\n";
foreach ($users as $user) {
    $status = $user['status'] ?? 'No status';
    echo "- {$user['name']} ({$user['username']}): {$status}\n";
}
?>


