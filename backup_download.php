<?php
require_once 'config.php';

session_start();
requireAdmin();

$backupName = $_GET['backup'] ?? '';
if (!$backupName) {
    http_response_code(400);
    die('Backup name required');
}

// Sanitize backup name to prevent directory traversal
$backupName = preg_replace('/[^a-zA-Z0-9_-]/', '', $backupName);
$backupPath = __DIR__ . '/backups/' . $backupName;

if (!is_dir($backupPath)) {
    http_response_code(404);
    die('Backup not found');
}

// Create ZIP archive
$zipFile = sys_get_temp_dir() . '/' . $backupName . '.zip';
$zip = new ZipArchive();

if ($zip->open($zipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
    // Add all files from backup directory
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($backupPath),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $file) {
        if (!$file->isDir()) {
            $filePath = $file->getRealPath();
            $relativePath = substr($filePath, strlen($backupPath) + 1);
            $zip->addFile($filePath, $relativePath);
        }
    }

    $zip->close();

    // Send ZIP file to browser
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $backupName . '.zip"');
    header('Content-Length: ' . filesize($zipFile));
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');

    readfile($zipFile);

    // Clean up temporary file
    unlink($zipFile);

    // Log download
    app_log('backup_downloaded', 'Backup downloaded', [
        'backup_name' => $backupName,
        'user' => $_SESSION['user_id'] ?? 'unknown'
    ]);

    exit;
} else {
    http_response_code(500);
    die('Failed to create ZIP archive');
}
?>
