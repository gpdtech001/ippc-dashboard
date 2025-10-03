<?php
// Runtime error logging configuration
define('ERROR_LOG_FILE', __DIR__ . '/error.log');
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', ERROR_LOG_FILE);

// Ensure a file exists and is writable; try to create and relax perms if needed
function ensureWritableFile($filepath) {
    $dir = dirname($filepath);

    // Check/create directory
    if (!file_exists($dir)) {
        if (!@mkdir($dir, 0755, true)) {
            // Can't create directory — return false instead of throwing to avoid fatal errors during logging
            @error_log("ensureWritableFile: Unable to create directory: $dir\n");
            return false;
        }
    }

    // Create file if it doesn't exist
    if (!file_exists($filepath)) {
        if (!@file_put_contents($filepath, '[]')) {
            @error_log("ensureWritableFile: Unable to create file: $filepath\n");
            return false;
        }
        @chmod($filepath, 0644);
    }

    // Verify permissions
    if (!is_writable($filepath)) {
        // Try to fix permissions
        @chmod($filepath, 0644);
        if (!is_writable($filepath)) {
            @error_log("ensureWritableFile: File not writable: $filepath\n");
            return false;
        }
    }

    return true;
}

// Structured application logger
function app_log($level, $message, $context = []) {
    $entry = [
        'ts' => date('c'),
        'level' => $level,
        'msg' => $message,
        'user' => $_SESSION['user_id'] ?? null,
        'context' => $context,
    ];
    $line = json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL;

    // Try to ensure the error log file is writable; if not, fall back to PHP system logger
    try {
        $ok = ensureWritableFile(ERROR_LOG_FILE);
        if ($ok) {
            @error_log($line, 3, ERROR_LOG_FILE);
            return;
        }
    } catch (Exception $e) {
        // ignore — fall back to system logger
    }

    // Fallback: write to system error log to avoid throwing inside error handlers
    @error_log($line);
}

// Global error/exception handlers to capture PHP notices/fatals
set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    app_log('php_error', $errstr, ['errno' => $errno, 'file' => $errfile, 'line' => $errline]);
    // Return false to allow normal PHP error handling as well
    return false;
});

set_exception_handler(function ($ex) {
    app_log('exception', $ex->getMessage(), [
        'file' => $ex->getFile(),
        'line' => $ex->getLine(),
        'trace' => $ex->getTraceAsString(),
    ]);
});

// Database configuration (JSON files)
define('USERS_FILE', __DIR__ . '/users.json');
define('ZONES_FILE', __DIR__ . '/zones.json');
define('REPORT_CATEGORIES_FILE', __DIR__ . '/report_categories.json');
define('FIELD_TYPES_FILE', __DIR__ . '/field_types.json');

// Session configuration
ini_set('session.gc_maxlifetime', 86400); // 24 hours
session_set_cookie_params([
    'lifetime' => 86400,
    'path' => '/',
    'secure' => isset($_SERVER['HTTPS']), // Only send over HTTPS if available
    'httponly' => true, // Prevent JavaScript access
    'samesite' => 'Strict' // CSRF protection
]);

// User roles
define('ROLE_ADMIN', 'admin');
define('ROLE_RZM', 'rzm');
define('ROLE_USER', 'user');

// User approval status
define('STATUS_PENDING', 'pending');
define('STATUS_APPROVED', 'approved');
define('STATUS_REJECTED', 'rejected');
define('STATUS_DISABLED', 'disabled');

// Utility functions
function getUsers() {
    $users = json_decode(file_get_contents(USERS_FILE), true);
    return $users ?: [];
}

function saveUsers($users) {
    if (!ensureWritableFile(USERS_FILE)) {
        app_log('write_error', 'Users file not writable', ['file' => USERS_FILE]);
        return false;
    }
    $json = json_encode($users, JSON_PRETTY_PRINT);
    if ($json === false) {
        app_log('json_error', 'Failed to encode users to JSON', ['error' => json_last_error_msg()]);
        return false;
    }
    $fp = fopen(USERS_FILE, 'w');
    if (!$fp) {
        app_log('write_error', 'Failed to open users file for writing', ['file' => USERS_FILE]);
        return false;
    }
    if (flock($fp, LOCK_EX)) {
        $result = fwrite($fp, $json);
        flock($fp, LOCK_UN);
        fclose($fp);
        if ($result === false) {
            app_log('write_error', 'Failed to write users file', ['file' => USERS_FILE]);
            return false;
        }
    } else {
        fclose($fp);
        app_log('write_error', 'Failed to lock users file', ['file' => USERS_FILE]);
        return false;
    }
    return true;
}

function getZones() {
    $zones = json_decode(file_get_contents(ZONES_FILE), true);
    return $zones ?: [];
}

function getUserById($id) {
    $users = getUsers();
    foreach ($users as $user) {
        if ($user['id'] == $id) {
            return $user;
        }
    }
    return null;
}

function getUserByUsername($username) {
    $users = getUsers();
    foreach ($users as $user) {
        if ($user['username'] == $username) {
            return $user;
        }
    }
    return null;
}

function getUserByEmail($email) {
    $users = getUsers();
    foreach ($users as $user) {
        if ($user['email'] == $email) {
            return $user;
        }
    }
    return null;
}

function generateUserId() {
    return uniqid('user_', true);
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

function sanitizeInput($data) {
    if (!is_string($data)) {
        return '';
    }
    // Trim whitespace
    $data = trim($data);
    // Limit length to prevent DoS
    $data = substr($data, 0, 1000);
    // Remove null bytes
    $data = str_replace(chr(0), '', $data);
    // Strip HTML tags and encode special characters
    $data = htmlspecialchars(strip_tags($data), ENT_QUOTES, 'UTF-8');
    return $data;
}

function validateEmail($email) {
    if (!is_string($email)) {
        return false;
    }
    $email = trim($email);
    if (empty($email)) {
        return false;
    }
    // Use PHP's built-in email validation
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function validateUsername($username) {
    if (!is_string($username)) {
        return false;
    }
    $username = trim($username);
    // Username should be 3-50 characters, alphanumeric + underscore/hyphen
    return preg_match('/^[a-zA-Z0-9_-]{3,50}$/', $username) === 1;
}

function validatePassword($password) {
    if (!is_string($password)) {
        return false;
    }
    // Password should be at least 8 characters and include uppercase, lowercase, and numeric
    return strlen($password) >= 8 && preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/', $password);
}

function validatePhone($phone) {
    if (!is_string($phone)) {
        return false;
    }
    $phone = trim($phone);
    if (empty($phone)) {
        return true; // Phone is optional
    }
    // Allow various phone formats
    return preg_match('/^[\+]?[0-9\s\-\(\)]{7,20}$/', $phone) === 1;
}

function isUserApproved($user) {
    return isset($user['status']) && $user['status'] === STATUS_APPROVED;
}

function isUserEnabled($user) {
    return isset($user['status']) &&
           ($user['status'] === STATUS_APPROVED || $user['status'] === STATUS_PENDING);
}

function approveUser($userId) {
    $users = getUsers();
    foreach ($users as &$user) {
        if ($user['id'] === $userId) {
            $user['status'] = STATUS_APPROVED;
            $user['approved_at'] = date('Y-m-d H:i:s');
            $user['approved_by'] = $_SESSION['user_id'] ?? 'system';
            break;
        }
    }
    saveUsers($users);
    return true;
}

function rejectUser($userId) {
    $users = getUsers();
    foreach ($users as &$user) {
        if ($user['id'] === $userId) {
            $user['status'] = STATUS_REJECTED;
            $user['rejected_at'] = date('Y-m-d H:i:s');
            $user['rejected_by'] = $_SESSION['user_id'] ?? 'system';
            break;
        }
    }
    saveUsers($users);
    return true;
}

function disableUser($userId) {
    $users = getUsers();
    foreach ($users as &$user) {
        if ($user['id'] === $userId) {
            $user['status'] = STATUS_DISABLED;
            $user['disabled_at'] = date('Y-m-d H:i:s');
            $user['disabled_by'] = $_SESSION['user_id'] ?? 'system';
            break;
        }
    }
    saveUsers($users);
    return true;
}

function enableUser($userId) {
    $users = getUsers();
    foreach ($users as &$user) {
        if ($user['id'] === $userId) {
            $user['status'] = STATUS_APPROVED;
            $user['enabled_at'] = date('Y-m-d H:i:s');
            $user['enabled_by'] = $_SESSION['user_id'] ?? 'system';
            break;
        }
    }
    saveUsers($users);
    return true;
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function establishUserSession(array $user): void {
    $_SESSION['user_id'] = $user['id'] ?? null;
    $_SESSION['username'] = $user['username'] ?? null;
    $_SESSION['email'] = $user['email'] ?? null;
    $_SESSION['role'] = $user['role'] ?? null;
    $_SESSION['name'] = $user['name'] ?? null;
}

function rememberCookieOptions(int $expires): array {
    $isSecure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    return [
        'expires' => $expires,
        'path' => '/',
        'secure' => $isSecure,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
}

function setRememberCookie(?string $token, ?int $expires = null): void {
    if ($token === null || $expires === null) {
        setcookie('remember_token', '', rememberCookieOptions(time() - 3600));
        return;
    }
    setcookie('remember_token', $token, rememberCookieOptions($expires));
}

function persistRememberToken(string $userId): ?string {
    $users = getUsers();
    foreach ($users as &$user) {
        if (($user['id'] ?? '') === $userId) {
            $token = bin2hex(random_bytes(32));
            $hash = hash('sha256', $token);
            $user['remember_token'] = $hash;
            $user['remember_token_expires_at'] = date('c', time() + (86400 * 30));
            if (saveUsers($users)) {
                setRememberCookie($token, time() + (86400 * 30));
                return $token;
            }
            return null;
        }
    }
    return null;
}

function clearRememberToken(?string $userId = null): void {
    if ($userId !== null) {
        $users = getUsers();
        $updated = false;
        foreach ($users as &$user) {
            if (($user['id'] ?? '') === $userId) {
                if (isset($user['remember_token']) || isset($user['remember_token_expires_at'])) {
                    unset($user['remember_token'], $user['remember_token_expires_at']);
                    $updated = true;
                }
                break;
            }
        }
        if ($updated) {
            saveUsers($users);
        }
    }
    setRememberCookie(null, null);
}

function attemptRememberedLogin(): void {
    if (isLoggedIn()) {
        return;
    }
    $cookieToken = $_COOKIE['remember_token'] ?? '';
    if ($cookieToken === '') {
        return;
    }
    $hash = hash('sha256', $cookieToken);
    $users = getUsers();
    foreach ($users as $user) {
        if (!empty($user['remember_token']) && hash_equals($user['remember_token'], $hash)) {
            $expiresAt = isset($user['remember_token_expires_at']) ? strtotime($user['remember_token_expires_at']) : null;
            if ($expiresAt !== null && $expiresAt < time()) {
                break;
            }
            if (!isUserApproved($user) || !isUserEnabled($user)) {
                break;
            }
            establishUserSession($user);
            // Refresh cookie to extend validity without regenerating token.
            if ($expiresAt !== null) {
                setRememberCookie($cookieToken, $expiresAt);
            }
            return;
        }
    }
    clearRememberToken();
}

function requireLogin() {
    attemptRememberedLogin();
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}

function requireAdmin() {
    requireLogin();
    if ($_SESSION['role'] !== ROLE_ADMIN) {
        header('Location: dashboard.php');
        exit;
    }
}

function requireRZM() {
    requireLogin();
    if ($_SESSION['role'] !== ROLE_RZM) {
        header('Location: dashboard.php');
        exit;
    }
}

// CSRF Protection
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

function requireCSRFToken() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (!validateCSRFToken($token)) {
            app_log('csrf_failure', 'Invalid CSRF token', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);
            http_response_code(403);
            die('Security error: Invalid request token');
        }
    }
}

// Backup and Recovery Functions
function ensureBackupDirectoryPermissions($backupDir) {
    // Try to fix permissions if directory exists but isn't writable
    if (is_dir($backupDir) && !is_writable($backupDir)) {
        // Try chmod 755 as a safer alternative
        if (!chmod($backupDir, 0755)) {
            app_log('backup_warning', 'Could not fix backup directory permissions', ['path' => $backupDir]);
            return false;
        }
    }
    return true;
}

function createBackup($description = '') {
    $backupDir = __DIR__ . '/backups';

    // Ensure main backups directory exists
    if (!is_dir($backupDir)) {
        if (!mkdir($backupDir, 0755, true)) {
            app_log('backup_error', 'Failed to create backups directory', ['path' => $backupDir]);
            return ['success' => false, 'message' => 'Failed to create backups directory'];
        }
    }

    // Ensure directory is writable
    if (!ensureBackupDirectoryPermissions($backupDir)) {
        return ['success' => false, 'message' => 'Backup directory permissions issue. Please contact administrator.'];
    }

    $timestamp = date('Y-m-d_H-i-s');
    $backupName = 'backup_' . $timestamp;
    if ($description) {
        $backupName .= '_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $description);
    }

    $backupPath = $backupDir . '/' . $backupName;

    // Ensure backup subdirectory exists
    if (!mkdir($backupPath, 0755, true)) {
        // Try with different permissions if 0755 fails
        if (!mkdir($backupPath, 0777, true)) {
            app_log('backup_error', 'Failed to create backup subdirectory', [
                'path' => $backupPath,
                'tried_permissions' => ['0755', '0777']
            ]);
            return ['success' => false, 'message' => 'Failed to create backup directory. Please check directory permissions.'];
        }
    }

    $filesToBackup = [
        USERS_FILE => 'users.json',
        ZONES_FILE => 'zones.json',
        REPORT_CATEGORIES_FILE => 'report_categories.json',
        FIELD_TYPES_FILE => 'field_types.json',
        REPORTS_FILE => 'reports.json'
    ];

    $backedUpFiles = [];
    foreach ($filesToBackup as $source => $filename) {
        if (file_exists($source)) {
            $destination = $backupPath . '/' . $filename;
            if (copy($source, $destination)) {
                $backedUpFiles[] = $filename;
            } else {
                app_log('backup_error', 'Failed to backup file', [
                    'source' => $source,
                    'destination' => $destination,
                    'file' => $filename
                ]);
            }
        } else {
            app_log('backup_warning', 'Source file does not exist', ['file' => $filename, 'path' => $source]);
        }
    }

    // Create backup metadata
    $metadata = [
        'timestamp' => date('c'),
        'description' => $description,
        'files' => $backedUpFiles,
        'created_by' => $_SESSION['user_id'] ?? 'system',
        'version' => '1.0'
    ];

    $metadataPath = $backupPath . '/metadata.json';
    if (file_put_contents($metadataPath, json_encode($metadata, JSON_PRETTY_PRINT)) === false) {
        app_log('backup_error', 'Failed to create backup metadata', ['path' => $metadataPath]);
        return ['success' => false, 'message' => 'Failed to create backup metadata'];
    }

    app_log('backup_created', 'Backup created successfully', [
        'backup_path' => $backupPath,
        'files_count' => count($backedUpFiles)
    ]);

    return [
        'success' => true,
        'path' => $backupPath,
        'files' => $backedUpFiles,
        'name' => $backupName
    ];
}

function listBackups() {
    $backupDir = __DIR__ . '/backups';
    if (!is_dir($backupDir)) {
        return [];
    }

    $backups = [];
    $dirs = scandir($backupDir);
    foreach ($dirs as $dir) {
        if ($dir === '.' || $dir === '..') continue;

        $path = $backupDir . '/' . $dir;
        if (is_dir($path)) {
            $metadataFile = $path . '/metadata.json';
            if (file_exists($metadataFile)) {
                $metadata = json_decode(file_get_contents($metadataFile), true);
                $backups[] = array_merge($metadata, ['path' => $path, 'name' => $dir]);
            } else {
                // Legacy backup without metadata
                $backups[] = [
                    'path' => $path,
                    'name' => $dir,
                    'timestamp' => date('c', filemtime($path)),
                    'files' => array_diff(scandir($path), ['.', '..']),
                    'description' => 'Legacy backup'
                ];
            }
        }
    }

    // Sort by timestamp descending
    usort($backups, function($a, $b) {
        return strtotime($b['timestamp']) - strtotime($a['timestamp']);
    });

    return $backups;
}

function restoreBackup($backupName) {
    $backupDir = __DIR__ . '/backups';
    $backupPath = $backupDir . '/' . basename($backupName);

    if (!is_dir($backupPath)) {
        return ['success' => false, 'message' => 'Backup not found'];
    }

    // Create pre-restore backup
    createBackup('pre-restore-' . $backupName);

    $filesToRestore = [
        'users.json' => USERS_FILE,
        'zones.json' => ZONES_FILE,
        'report_categories.json' => REPORT_CATEGORIES_FILE,
        'field_types.json' => FIELD_TYPES_FILE,
        'reports.json' => REPORTS_FILE
    ];

    $restoredFiles = [];
    foreach ($filesToRestore as $backupFile => $targetFile) {
        $sourcePath = $backupPath . '/' . $backupFile;
        if (file_exists($sourcePath)) {
            if (copy($sourcePath, $targetFile)) {
                $restoredFiles[] = $backupFile;
            } else {
                app_log('restore_error', 'Failed to restore file', ['file' => $backupFile]);
                return ['success' => false, 'message' => 'Failed to restore ' . $backupFile];
            }
        }
    }

    app_log('backup_restored', 'Backup restored successfully', [
        'backup_name' => $backupName,
        'files_count' => count($restoredFiles)
    ]);

    return [
        'success' => true,
        'message' => 'Backup restored successfully',
        'files' => $restoredFiles
    ];
}

// Report Categories functions
function getReportCategories() {
    if (!file_exists(REPORT_CATEGORIES_FILE)) {
        return [];
    }
    $categories = json_decode(file_get_contents(REPORT_CATEGORIES_FILE), true);
    return $categories ?: [];
}

function saveReportCategories($categories) {
    if (!ensureWritableFile(REPORT_CATEGORIES_FILE)) {
        app_log('write_error', 'Report categories file not writable', ['file' => REPORT_CATEGORIES_FILE]);
        return ['success' => false, 'message' => 'Unable to write to report categories file. Please check file permissions.'];
    }
    $json = json_encode($categories, JSON_PRETTY_PRINT);
    if ($json === false) {
        app_log('json_error', 'Failed to encode report categories to JSON', ['error' => json_last_error_msg()]);
        return ['success' => false, 'message' => 'Invalid data format. Please check your input.'];
    }
    $result = @file_put_contents(REPORT_CATEGORIES_FILE, $json);
    if ($result === false) {
        app_log('write_error', 'Failed to write report categories', ['file' => REPORT_CATEGORIES_FILE]);
        return ['success' => false, 'message' => 'Failed to save report categories. Please try again.'];
    }
    return ['success' => true, 'message' => 'Report categories saved successfully.'];
}

// Field Types helpers
function getFieldTypes() {
    if (!file_exists(FIELD_TYPES_FILE)) {
        $defaults = defaultFieldTypes();
        ensureWritableFile(FIELD_TYPES_FILE);
        @file_put_contents(FIELD_TYPES_FILE, json_encode($defaults, JSON_PRETTY_PRINT));
        return $defaults;
    }
    $types = json_decode(@file_get_contents(FIELD_TYPES_FILE), true);
    if (!$types) {
        $types = defaultFieldTypes();
    }
    return $types;
}

function saveFieldTypes($types) {
    if (!ensureWritableFile(FIELD_TYPES_FILE)) {
        app_log('write_error', 'Field types file not writable', ['file' => FIELD_TYPES_FILE]);
        return ['success' => false, 'message' => 'Unable to write to field types file. Please check file permissions.'];
    }
    $json = json_encode($types, JSON_PRETTY_PRINT);
    if ($json === false) {
        app_log('json_error', 'Failed to encode field types to JSON', ['error' => json_last_error_msg()]);
        return ['success' => false, 'message' => 'Invalid data format. Please check your input.'];
    }
    $result = @file_put_contents(FIELD_TYPES_FILE, $json);
    if ($result === false) {
        app_log('write_error', 'Failed to write field types', ['file' => FIELD_TYPES_FILE]);
        return ['success' => false, 'message' => 'Failed to save field types. Please try again.'];
    }
    return ['success' => true, 'message' => 'Field types saved successfully.'];
}

function defaultFieldTypes() {
    return [
        [ 'id' => 'type_text', 'key' => 'text', 'label' => 'Text', 'base_type' => 'text', 'source' => 'manual', 'description' => 'Single-line text input' ],
        [ 'id' => 'type_textarea', 'key' => 'textarea', 'label' => 'Textarea', 'base_type' => 'textarea', 'source' => 'manual', 'description' => 'Multi-line text input' ],
        [ 'id' => 'type_number', 'key' => 'number', 'label' => 'Number', 'base_type' => 'number', 'source' => 'manual', 'description' => 'Numeric input' ],
        [ 'id' => 'type_date', 'key' => 'date', 'label' => 'Date', 'base_type' => 'date', 'source' => 'manual', 'description' => 'Date picker' ],
        [ 'id' => 'type_select', 'key' => 'select', 'label' => 'Select (Manual)', 'base_type' => 'select', 'source' => 'manual', 'description' => 'Dropdown with manually entered options' ],
        [ 'id' => 'type_groups', 'key' => 'groups', 'label' => 'Groups (zones.json)', 'base_type' => 'select', 'source' => 'zones_groups', 'description' => 'Dropdown of groups from zones.json' ],
    ];
}

function generateCategoryId() {
    return uniqid('cat_', true);
}

function generateFieldId() {
    return uniqid('fld_', true);
}

function getCategoryById($id) {
    $categories = getReportCategories();
    foreach ($categories as $category) {
        if ($category['id'] === $id) {
            // Fix existing currency fields and add automatic currency field if needed
            $category = fixCurrencyFields($category);
            $category = addAutomaticCurrencyField($category);
            return $category;
        }
    }
    return null;
}

// Fix existing currency fields to ensure they have proper source attribute
function fixCurrencyFields($category) {
    if (!isset($category['fields']) || !is_array($category['fields'])) {
        return $category;
    }
    
    foreach ($category['fields'] as &$field) {
        if (($field['type'] ?? '') === 'currency' && !isset($field['source'])) {
            $field['source'] = 'currency';
        }
    }
    
    return $category;
}

// Add automatic currency field if category contains currency_amount fields
function addAutomaticCurrencyField($category) {
    if (!isset($category['fields']) || !is_array($category['fields'])) {
        return $category;
    }
    
    // Check if category has currency_amount fields
    $hasCurrencyAmount = false;
    $hasCurrencyField = false;
    
    foreach ($category['fields'] as $field) {
        if (($field['type'] ?? '') === 'currency_amount') {
            $hasCurrencyAmount = true;
        }
        if (($field['type'] ?? '') === 'currency') {
            $hasCurrencyField = true;
        }
    }
    
    // If has currency_amount fields but no currency field, add one automatically
    if ($hasCurrencyAmount && !$hasCurrencyField) {
        $currencyField = [
            'id' => 'auto_currency_' . $category['id'],
            'label' => 'Currency',
            'type' => 'currency',
            'source' => 'currency',
            'required' => true,
            'placeholder' => 'Select currency for amounts',
            'auto_added' => true
        ];
        
        // Add currency field at the end
        $category['fields'][] = $currencyField;
    }
    
    return $category;
}

// Resolve dynamic options for field based on source and user context
function resolveFieldOptions($field, $user) {
    $type = $field['type'] ?? 'text';
    // Handle select-like field types (select, groups, currency)
    if ($type !== 'select' && $type !== 'groups' && $type !== 'currency') {
        return [];
    }
    $source = $field['source'] ?? 'manual';
    if ($source === 'manual') {
        $opts = $field['options'] ?? [];
        $out = [];
        foreach ($opts as $o) {
            $out[] = ['id' => $o, 'label' => $o];
        }
        return $out;
    }
    if ($source === 'zones_groups') {
        $zones = getZones();
        $role = $user['role'] ?? ($_SESSION['role'] ?? null);
        if ($role === ROLE_RZM) {
            $region = $user['region'] ?? '';
            $zone = $user['zone'] ?? '';
            if (!$region || !$zone) {
                app_log('context_error', 'RZM missing region/zone for zones_groups');
                return [];
            }
            if (!isset($zones[$region]) || !isset($zones[$region][$zone])) {
                app_log('not_found', 'RZM region/zone not found in zones.json', ['region' => $region, 'zone' => $zone]);
                return [];
            }
            $groups = $zones[$region][$zone]['groups'] ?? [];
            $out = [];
            foreach ($groups as $g) {
                $out[] = ['id' => $g['id'], 'label' => $g['name']];
            }
            return $out;
        } else {
            // Admin sees all groups with Region > Zone > Group label
            $out = [];
            foreach ($zones as $regionName => $regionZones) {
                foreach ($regionZones as $zoneName => $zoneData) {
                    $groups = $zoneData['groups'] ?? [];
                    foreach ($groups as $g) {
                        $out[] = [
                            'id' => $g['id'],
                            'label' => $regionName . ' > ' . $zoneName . ' > ' . $g['name']
                        ];
                    }
                }
            }
            return $out;
        }
    }
    if ($source === 'currency') {
        $currencyFile = __DIR__ . '/currency.json';
        if (!file_exists($currencyFile)) {
            app_log('config_error', 'Currency file not found', ['file' => $currencyFile]);
            return [];
        }
        $currencyData = json_decode(file_get_contents($currencyFile), true);
        if (!$currencyData) {
            app_log('config_error', 'Invalid currency JSON data');
            return [];
        }
        $out = [];
        foreach ($currencyData as $currency) {
            $out[] = [
                'id' => $currency['code'],
                'label' => $currency['code'] . ' - ' . $currency['name'] . ' (' . $currency['symbol'] . ')'
            ];
        }
        return $out;
    }
    app_log('config_warning', 'Unknown field source', ['source' => $source]);
    return [];
}

// Utility: resolve a group id to its name by scanning zones.json
function resolveGroupLabelById($groupId) {
    if (!$groupId) return '';
    $zones = getZones();
    foreach ($zones as $regionZones) {
        foreach ($regionZones as $zoneData) {
            $groups = $zoneData['groups'] ?? [];
            foreach ($groups as $g) {
                if (($g['id'] ?? null) === $groupId) {
                    return $g['name'] ?? $groupId;
                }
            }
        }
    }
    return $groupId; // fallback to id if not found
}

// Find group ID by name within user's zone
function findGroupIdByName($groupName, $user) {
    if (!$groupName || !$user) {
        return null;
    }
    
    $userRole = $user['role'] ?? '';
    $userRegion = $user['region'] ?? '';
    $userZone = $user['zone'] ?? '';
    
    if ($userRole !== 'rzm' || !$userRegion || !$userZone) {
        return null;
    }
    
    $zones = getZones();
    $groups = $zones[$userRegion][$userZone]['groups'] ?? [];
    
    foreach ($groups as $group) {
        if (strcasecmp($group['name'], $groupName) === 0) {
            return $group['id'];
        }
    }
    
    return null; // Group not found
}

// Ensure a group exists in the user's zone, create if it doesn't exist
function ensureGroupExists($groupName, $user) {
    if (!$groupName || !$user) {
        return [];
    }
    
    $userRole = $user['role'] ?? '';
    $userRegion = $user['region'] ?? '';
    $userZone = $user['zone'] ?? '';
    
    // Only RZM users can add groups to their specific zone
    if ($userRole !== 'rzm' || !$userRegion || !$userZone) {
        return [];
    }
    
    error_log("ensureGroupExists: Checking group '" . $groupName . "' for user " . $user['name']);
    
    $zones = getZones();
    
    // Check if group already exists in user's zone
    $existingGroups = $zones[$userRegion][$userZone]['groups'] ?? [];
    foreach ($existingGroups as $existingGroup) {
        if (strcasecmp($existingGroup['name'], $groupName) === 0) {
            error_log("ensureGroupExists: Group '" . $groupName . "' already exists");
            return []; // Group already exists
        }
    }
    
    // Group doesn't exist, create it
    $newGroupId = 'grp_' . uniqid() . '_' . time();
    $newGroup = [
        'id' => $newGroupId,
        'name' => $groupName,
        'created_at' => date('Y-m-d H:i:s'),
        'created_by' => $user['id'] ?? 'bulk_upload',
        'source' => 'bulk_upload'
    ];
    
    // Add group to user's zone
    if (!isset($zones[$userRegion])) {
        $zones[$userRegion] = [];
    }
    if (!isset($zones[$userRegion][$userZone])) {
        $zones[$userRegion][$userZone] = ['groups' => []];
    }
    if (!isset($zones[$userRegion][$userZone]['groups'])) {
        $zones[$userRegion][$userZone]['groups'] = [];
    }
    
    $zones[$userRegion][$userZone]['groups'][] = $newGroup;
    
    // Save updated zones
    if (saveZones($zones)) {
        error_log("ensureGroupExists: Successfully created group '" . $groupName . "' with ID '" . $newGroupId . "'");
        return [$newGroup];
    } else {
        error_log("ensureGroupExists: Failed to save group '" . $groupName . "'");
        return [];
    }
}

// Resolve the proper HTML input type for a field, including custom field types
function resolveFieldInputType($fieldType) {
    // Handle standard HTML types directly
    $standardTypes = ['text', 'textarea', 'number', 'date', 'select', 'email', 'password', 'tel', 'url'];
    if (in_array($fieldType, $standardTypes)) {
        return $fieldType;
    }

    // Handle special field types
    if ($fieldType === 'quantity' || $fieldType === 'currency_amount') {
        return 'number';
    }
    
    // Currency fields should use select dropdown
    if ($fieldType === 'currency') {
        return 'select';
    }

    // For custom field types, look up the base_type from field_types.json
    $fieldTypes = getFieldTypes();
    foreach ($fieldTypes as $fieldTypeDef) {
        if (($fieldTypeDef['key'] ?? '') === $fieldType || ($fieldTypeDef['id'] ?? '') === $fieldType) {
            $baseType = $fieldTypeDef['base_type'] ?? 'text';
            // Ensure base_type is a valid HTML input type
            return in_array($baseType, $standardTypes) ? $baseType : 'text';
        }
    }

    // Default fallback
    return 'text';
}

// Currency conversion helpers
define('CURRENCY_SETTINGS_FILE', __DIR__ . '/currency_settings.json');

// Get currency conversion settings
function getCurrencySettings() {
    if (!file_exists(CURRENCY_SETTINGS_FILE)) {
        // Create default settings if file doesn't exist
        $defaultSettings = [
            'base_currency' => [
                'code' => 'E',
                'name' => 'Espees',
                'symbol' => 'E',
                'country' => 'IPPC'
            ],
            'exchange_rates' => ['E' => 1.0],
            'last_updated' => date('c'),
            'updated_by' => null
        ];
        saveCurrencySettings($defaultSettings);
        return $defaultSettings;
    }
    $settings = json_decode(file_get_contents(CURRENCY_SETTINGS_FILE), true);
    return $settings ?: [];
}

// Save currency conversion settings
function saveCurrencySettings($settings) {
    if (!ensureWritableFile(CURRENCY_SETTINGS_FILE)) {
        app_log('write_error', 'Currency settings file not writable', ['file' => CURRENCY_SETTINGS_FILE]);
        return ['success' => false, 'message' => 'Unable to write to currency settings file. Please check file permissions.'];
    }
    
    $settings['last_updated'] = date('c');
    $json = json_encode($settings, JSON_PRETTY_PRINT);
    if ($json === false) {
        app_log('json_error', 'Failed to encode currency settings to JSON', ['error' => json_last_error_msg()]);
        return ['success' => false, 'message' => 'Invalid data format. Please check your input.'];
    }
    
    $result = @file_put_contents(CURRENCY_SETTINGS_FILE, $json);
    if ($result === false) {
        app_log('write_error', 'Failed to write currency settings', ['file' => CURRENCY_SETTINGS_FILE]);
        return ['success' => false, 'message' => 'Failed to save currency settings. Please try again.'];
    }
    
    return ['success' => true, 'message' => 'Currency settings saved successfully.'];
}

// Convert amount from one currency to base currency (Espees)
function convertToBaseCurrency($amount, $fromCurrency) {
    if ($amount === 0 || $amount === '0' || $amount === '') {
        return 0;
    }
    
    $settings = getCurrencySettings();
    $rates = $settings['exchange_rates'] ?? [];
    
    // If converting from base currency, return as is
    if ($fromCurrency === $settings['base_currency']['code']) {
        return (float)$amount;
    }
    
    // Get exchange rate (rate represents: X Currency = 1 Espee)
    // So to convert TO espees, we divide the amount by the rate
    $rate = $rates[$fromCurrency] ?? 1;
    return $rate > 0 ? (float)$amount / (float)$rate : 0;
}

// Convert amount from base currency to target currency
function convertFromBaseCurrency($amount, $toCurrency) {
    if ($amount === 0 || $amount === '0' || $amount === '') {
        return 0;
    }
    
    $settings = getCurrencySettings();
    $rates = $settings['exchange_rates'] ?? [];
    
    // If converting to base currency, return as is
    if ($toCurrency === $settings['base_currency']['code']) {
        return (float)$amount;
    }
    
    // Get exchange rate (rate represents: X Currency = 1 Espee)
    // So to convert FROM espees, we multiply the amount by the rate
    $rate = $rates[$toCurrency] ?? 1;
    return (float)$amount * (float)$rate;
}

// Format currency amount with proper symbol and formatting
function formatCurrencyAmount($amount, $currencyCode, $showCode = true) {
    if ($currencyCode === 'E') {
        $symbol = 'E';
        $formatted = number_format((float)$amount, 2);
        return $showCode ? "E {$formatted}" : $formatted;
    }
    
    // Get currency info from currency.json
    $currencies = json_decode(file_get_contents(__DIR__ . '/currency.json'), true);
    foreach ($currencies as $currency) {
        if ($currency['code'] === $currencyCode) {
            $formatted = number_format((float)$amount, 2);
            return $showCode ? "{$currency['symbol']} {$formatted} ({$currencyCode})" : "{$currency['symbol']} {$formatted}";
        }
    }
    
    // Fallback
    return number_format((float)$amount, 2) . ' ' . $currencyCode;
}

// Reports storage helpers
define('REPORTS_FILE', __DIR__ . '/reports.json');

function getReports() {
    if (!file_exists(REPORTS_FILE)) {
        return [];
    }
    $reports = json_decode(@file_get_contents(REPORTS_FILE), true);
    return $reports ?: [];
}

function saveReports($reports) {
    $filepath = __DIR__ . '/reports.json';
    try {
        if (!ensureWritableFile($filepath)) {
            throw new Exception('Reports file is not writable');
        }

        // Encode payload once so we can reuse it across fallbacks
        $json = json_encode($reports, JSON_PRETTY_PRINT);
        if ($json === false) {
            throw new Exception('JSON encode failed: ' . json_last_error_msg());
        }

        // Atomic write using temp file with fallback to app directory when system temp is unavailable
        $temp = @tempnam(sys_get_temp_dir(), 'report');
        if ($temp === false) {
            $temp = __DIR__ . '/reports.json.tmp.' . uniqid();
        }

        $writeThrough = function () use ($filepath, $json) {
            $fp = @fopen($filepath, 'c');
            if (!$fp) {
                return false;
            }
            $written = false;
            if (flock($fp, LOCK_EX)) {
                if (ftruncate($fp, 0) !== false) {
                    $bytes = fwrite($fp, $json);
                    if ($bytes === strlen($json)) {
                        fflush($fp);
                        $written = true;
                    }
                }
                flock($fp, LOCK_UN);
            }
            fclose($fp);
            return $written;
        };

        if (file_put_contents($temp, $json) === false) {
            if (file_exists($temp)) {
                @unlink($temp);
            }
            if ($writeThrough()) {
                return true;
            }
            throw new Exception('Failed to write reports data: temporary file write failed');
        }

        // Try atomic rename first. If it fails (e.g. directory not writable for target user), fall back to locked write.
        if (!@rename($temp, $filepath)) {
            $renameError = error_get_last();
            $writeOk = $writeThrough();
            @unlink($temp);

            if ($writeOk) {
                return true;
            }

            $reason = $renameError['message'] ?? 'unknown error during rename';
            throw new Exception('Failed to persist reports: ' . $reason);
        }

        return true;
    } catch (Exception $e) {
        error_log('Error saving reports: ' . $e->getMessage());
        throw $e;
    }
}

function generateReportId() {
    return uniqid('rep_', true);
}

function addReportCategory($name, $description) {
    $categories = getReportCategories();
    
    $newCategory = [
        'id' => generateCategoryId(),
        'name' => $name,
        'description' => $description,
        'status' => 'active',
        'created_at' => date('Y-m-d H:i:s'),
        'created_by' => $_SESSION['user_id'] ?? 'system',
        'updated_at' => date('Y-m-d H:i:s')
    ];
    
    $categories[] = $newCategory;
    saveReportCategories($categories);
    return $newCategory['id'];
}

function updateReportCategory($id, $name, $description) {
    $categories = getReportCategories();
    
    foreach ($categories as &$category) {
        if ($category['id'] === $id) {
            $category['name'] = $name;
            $category['description'] = $description;
            $category['updated_at'] = date('Y-m-d H:i:s');
            $category['updated_by'] = $_SESSION['user_id'] ?? 'system';
            break;
        }
    }
    
    saveReportCategories($categories);
    return true;
}

function deleteReportCategory($id) {
    $categories = getReportCategories();
    $categories = array_filter($categories, function($category) use ($id) {
        return $category['id'] !== $id;
    });
    saveReportCategories(array_values($categories));
    return true;
}

function toggleCategoryStatus($id) {
    $categories = getReportCategories();
    
    foreach ($categories as &$category) {
        if ($category['id'] === $id) {
            $category['status'] = $category['status'] === 'active' ? 'inactive' : 'active';
            $category['updated_at'] = date('Y-m-d H:i:s');
            $category['updated_by'] = $_SESSION['user_id'] ?? 'system';
            break;
        }
    }
    
    saveReportCategories($categories);
    return true;
}

// Group management functions
define('GROUPS_FILE', __DIR__ . '/groups.json');

function getAllGroups() {
    // Get groups from zones.json (existing groups) and groups.json (newly created groups)
    $allGroups = [];
    
    // First, get existing groups from zones.json
    $zones = getAllZones();
    foreach ($zones as $zoneId => $zone) {
        if (!empty($zone['groups'])) {
            foreach ($zone['groups'] as $group) {
                $allGroups[] = [
                    'id' => $group['id'],
                    'name' => $group['name'],
                    'description' => '', // Existing groups don't have descriptions
                    'zone_id' => $zoneId,
                    'created_at' => '2024-01-01 00:00:00', // Default date for existing groups
                    'created_by' => 'system',
                    'updated_at' => '2024-01-01 00:00:00',
                    'updated_by' => 'system',
                    'source' => 'zones.json' // Mark as existing group
                ];
            }
        }
    }
    
    // Then, get newly created groups from groups.json
    if (file_exists(GROUPS_FILE)) {
        $newGroups = json_decode(@file_get_contents(GROUPS_FILE), true);
        if ($newGroups) {
            foreach ($newGroups as $group) {
                $group['source'] = 'groups.json'; // Mark as new group
                $allGroups[] = $group;
            }
        }
    }
    
    return $allGroups;
}

function getGroupsByZone($zoneId) {
    $allGroups = getAllGroups();
    return array_filter($allGroups, function($group) use ($zoneId) {
        return $group['zone_id'] == $zoneId;
    });
}

function getGroupById($groupId) {
    $groups = getAllGroups();
    foreach ($groups as $group) {
        if ($group['id'] === $groupId) {
            return $group;
        }
    }
    return null;
}

function saveGroups($groups) {
    if (!ensureWritableFile(GROUPS_FILE)) {
        app_log('write_error', 'Groups file not writable', ['file' => GROUPS_FILE]);
        return false;
    }
    
    $json = json_encode($groups, JSON_PRETTY_PRINT);
    if ($json === false) {
        app_log('json_error', 'Failed to encode groups to JSON', ['error' => json_last_error_msg()]);
        return false;
    }
    
    $result = @file_put_contents(GROUPS_FILE, $json);
    if ($result === false) {
        app_log('write_error', 'Failed to write groups', ['file' => GROUPS_FILE]);
        return false;
    }
    
    return true;
}

function createGroup($name, $description, $zoneId, $userId) {
    // Check if group name already exists in the same zone (including existing groups)
    $allGroups = getAllGroups();
    foreach ($allGroups as $group) {
        if ($group['name'] === $name && $group['zone_id'] == $zoneId) {
            return ['success' => false, 'message' => 'A group with this name already exists in this zone'];
        }
    }
    
    $newGroup = [
        'id' => 'grp_' . uniqid(),
        'name' => $name,
        'description' => $description,
        'zone_id' => $zoneId,
        'created_at' => date('Y-m-d H:i:s'),
        'created_by' => $userId,
        'updated_at' => date('Y-m-d H:i:s'),
        'updated_by' => $userId
    ];
    
    // Get only the editable groups (from groups.json)
    $editableGroups = [];
    if (file_exists(GROUPS_FILE)) {
        $editableGroups = json_decode(@file_get_contents(GROUPS_FILE), true) ?: [];
    }
    
    $editableGroups[] = $newGroup;
    
    if (saveGroups($editableGroups)) {
        app_log('group_created', 'New group created', [
            'group_id' => $newGroup['id'],
            'name' => $name,
            'zone_id' => $zoneId,
            'created_by' => $userId
        ]);
        return ['success' => true, 'message' => 'Group created successfully', 'id' => $newGroup['id']];
    } else {
        return ['success' => false, 'message' => 'Failed to save group'];
    }
}

function updateGroup($groupId, $name, $description, $zoneId, $userId) {
    // First check if this group exists and if it's editable
    $currentGroup = getGroupById($groupId);
    if (!$currentGroup) {
        return ['success' => false, 'message' => 'Group not found'];
    }
    
    // Allow editing groups from zones.json (system groups)
    // We'll handle both system groups and custom groups
    
    // Check if group name already exists in the same zone (excluding current group)
    $allGroups = getAllGroups();
    foreach ($allGroups as $group) {
        if ($group['name'] === $name && $group['zone_id'] == $zoneId && $group['id'] !== $groupId) {
            return ['success' => false, 'message' => 'A group with this name already exists in this zone'];
        }
    }
    
    if ($currentGroup['source'] === 'zones.json') {
        // Update system group in zones.json
        $zones = [];
        if (file_exists(ZONES_FILE)) {
            $zonesData = json_decode(@file_get_contents(ZONES_FILE), true);
            if ($zonesData) {
                // Find and update the group in the zones structure
                foreach ($zonesData as $regionName => &$regionData) {
                    foreach ($regionData as $zoneName => &$zoneData) {
                        if (!empty($zoneData['groups'])) {
                            foreach ($zoneData['groups'] as &$group) {
                                if ($group['id'] === $groupId) {
                                    $group['name'] = $name;
                                    // If changing zones, we need to move the group
                                    if ($zoneName !== $zoneId) {
                                        // Remove from current zone
                                        $zoneData['groups'] = array_filter($zoneData['groups'], function($g) use ($groupId) {
                                            return $g['id'] !== $groupId;
                                        });
                                        $zoneData['groups'] = array_values($zoneData['groups']);
                                        
                                        // Add to new zone
                                        foreach ($zonesData as $newRegionName => &$newRegionData) {
                                            foreach ($newRegionData as $newZoneName => &$newZoneData) {
                                                if ($newZoneName === $zoneId) {
                                                    if (!isset($newZoneData['groups'])) {
                                                        $newZoneData['groups'] = [];
                                                    }
                                                    $newZoneData['groups'][] = [
                                                        'id' => $groupId,
                                                        'name' => $name
                                                    ];
                                                    break 2;
                                                }
                                            }
                                        }
                                    }
                                    
                                    // Save the updated zones file
                                    if (!ensureWritableFile(ZONES_FILE)) {
                                        return ['success' => false, 'message' => 'Zones file not writable'];
                                    }
                                    
                                    $json = json_encode($zonesData, JSON_PRETTY_PRINT);
                                    if ($json === false) {
                                        return ['success' => false, 'message' => 'Failed to encode zones data'];
                                    }
                                    
                                    $result = @file_put_contents(ZONES_FILE, $json);
                                    if ($result === false) {
                                        return ['success' => false, 'message' => 'Failed to save zones file'];
                                    }
                                    
                                    app_log('group_updated', 'System group updated', [
                                        'group_id' => $groupId,
                                        'name' => $name,
                                        'zone_id' => $zoneId,
                                        'updated_by' => $userId
                                    ]);
                                    return ['success' => true, 'message' => 'Group updated successfully'];
                                }
                            }
                        }
                    }
                }
            }
        }
        return ['success' => false, 'message' => 'System group not found in zones file'];
    } else {
        // Update custom group in groups.json
        $editableGroups = [];
        if (file_exists(GROUPS_FILE)) {
            $editableGroups = json_decode(@file_get_contents(GROUPS_FILE), true) ?: [];
        }
        
        // Update the group in the editable groups array
        $found = false;
        foreach ($editableGroups as &$group) {
            if ($group['id'] === $groupId) {
                $group['name'] = $name;
                $group['description'] = $description;
                $group['zone_id'] = $zoneId;
                $group['updated_at'] = date('Y-m-d H:i:s');
                $group['updated_by'] = $userId;
                $found = true;
                break;
            }
        }
        
        if (!$found) {
            return ['success' => false, 'message' => 'Custom group not found'];
        }
        
        if (saveGroups($editableGroups)) {
            app_log('group_updated', 'Custom group updated', [
                'group_id' => $groupId,
                'name' => $name,
                'zone_id' => $zoneId,
                'updated_by' => $userId
            ]);
            return ['success' => true, 'message' => 'Group updated successfully'];
        } else {
            return ['success' => false, 'message' => 'Failed to save group changes'];
        }
    }
}

function deleteGroup($groupId, $userId) {
    // First check if this group exists and if it's editable
    $currentGroup = getGroupById($groupId);
    if (!$currentGroup) {
        return ['success' => false, 'message' => 'Group not found'];
    }
    
    // Allow deletion of both system groups and custom groups
    
    // Check if group is used in any reports
    $reports = getReports();
    $groupInUse = false;
    foreach ($reports as $report) {
        $data = $report['data'] ?? [];
        if (!is_array($data)) {
            continue;
        }
        foreach ($data as $value) {
            if ($value === $groupId) {
                $groupInUse = true;
                break 2;
            }
        }
    }

    if ($groupInUse) {
        return ['success' => false, 'message' => 'Cannot delete group as it is referenced by existing reports'];
    }
    
    if ($currentGroup['source'] === 'zones.json') {
        // Delete system group from zones.json
        if (file_exists(ZONES_FILE)) {
            $zonesData = json_decode(@file_get_contents(ZONES_FILE), true);
            if ($zonesData) {
                // Find and remove the group from the zones structure
                foreach ($zonesData as $regionName => &$regionData) {
                    foreach ($regionData as $zoneName => &$zoneData) {
                        if (!empty($zoneData['groups'])) {
                            $originalCount = count($zoneData['groups']);
                            $zoneData['groups'] = array_filter($zoneData['groups'], function($group) use ($groupId) {
                                return $group['id'] !== $groupId;
                            });
                            $zoneData['groups'] = array_values($zoneData['groups']);
                            
                            if (count($zoneData['groups']) < $originalCount) {
                                // Group was found and removed, save the file
                                if (!ensureWritableFile(ZONES_FILE)) {
                                    return ['success' => false, 'message' => 'Zones file not writable'];
                                }
                                
                                $json = json_encode($zonesData, JSON_PRETTY_PRINT);
                                if ($json === false) {
                                    return ['success' => false, 'message' => 'Failed to encode zones data'];
                                }
                                
                                $result = @file_put_contents(ZONES_FILE, $json);
                                if ($result === false) {
                                    return ['success' => false, 'message' => 'Failed to save zones file'];
                                }
                                
                                app_log('group_deleted', 'System group deleted', [
                                    'group_id' => $groupId,
                                    'deleted_by' => $userId
                                ]);
                                return ['success' => true, 'message' => 'Group deleted successfully'];
                            }
                        }
                    }
                }
            }
        }
        return ['success' => false, 'message' => 'System group not found in zones file'];
    } else {
        // Delete custom group from groups.json
        $editableGroups = [];
        if (file_exists(GROUPS_FILE)) {
            $editableGroups = json_decode(@file_get_contents(GROUPS_FILE), true) ?: [];
        }
        
        $originalCount = count($editableGroups);
        $editableGroups = array_filter($editableGroups, function($group) use ($groupId) {
            return $group['id'] !== $groupId;
        });
        
        if (count($editableGroups) === $originalCount) {
            return ['success' => false, 'message' => 'Custom group not found'];
        }
        
        if (saveGroups(array_values($editableGroups))) {
            app_log('group_deleted', 'Custom group deleted', [
                'group_id' => $groupId,
                'deleted_by' => $userId
            ]);
            return ['success' => true, 'message' => 'Group deleted successfully'];
        } else {
            return ['success' => false, 'message' => 'Failed to delete group'];
        }
    }
}

// Zone management functions
function getAllZones() {
    if (!file_exists(ZONES_FILE)) {
        return [];
    }
    
    $zonesData = json_decode(@file_get_contents(ZONES_FILE), true);
    if (!$zonesData) {
        return [];
    }
    
    $zones = [];
    // Extract all zones from the nested structure
    foreach ($zonesData as $regionName => $regionData) {
        foreach ($regionData as $zoneName => $zoneData) {
            $zones[$zoneName] = [
                'id' => $zoneName,
                'name' => $zoneData['name'] ?? $zoneName,
                'region' => $regionName,
                'groups' => $zoneData['groups'] ?? []
            ];
        }
    }
    
    return $zones;
}

function getZoneGroups($zoneName) {
    $zones = getAllZones();
    return $zones[$zoneName]['groups'] ?? [];
}

// Save zones data back to zones.json
function saveZones($zones) {
    if (!ensureWritableFile(ZONES_FILE)) {
        app_log('write_error', 'Zones file not writable', ['file' => ZONES_FILE]);
        return false;
    }
    
    $json = json_encode($zones, JSON_PRETTY_PRINT);
    if ($json === false) {
        app_log('json_error', 'Failed to encode zones to JSON', ['error' => json_last_error_msg()]);
        return false;
    }
    
    $result = @file_put_contents(ZONES_FILE, $json);
    if ($result === false) {
        app_log('write_error', 'Failed to write zones file', ['file' => ZONES_FILE]);
        return false;
    }
    
    return true;
}

// Bulk upload processing function
function processBulkUpload($csvFilePath, $categoryId, $userId) {
    error_log("processBulkUpload: Starting with csvFile=" . $csvFilePath . ", categoryId=" . $categoryId . ", userId=" . $userId);
    
    try {
        // Get user information
        $user = getUserById($userId);
        if (!$user) {
            error_log("processBulkUpload: ERROR - Invalid user ID: " . $userId);
            return ['success' => false, 'message' => 'Invalid user'];
        }
        
        error_log("processBulkUpload: User found: " . ($user['name'] ?? 'NO NAME'));
        
        // Get the report category to understand the field structure
        error_log("processBulkUpload: Getting category by ID: " . $categoryId);
        $category = getCategoryById($categoryId);
        if (!$category) {
            error_log("processBulkUpload: ERROR - Invalid category ID: " . $categoryId);
            return ['success' => false, 'message' => 'Invalid report category'];
        }
        
        error_log("processBulkUpload: Category found: " . ($category['name'] ?? 'NO NAME'));
        
        // Apply fixes to the category
        $category = fixCurrencyFields($category);
        $category = addAutomaticCurrencyField($category);
        $fields = $category['fields'] ?? [];
        
        // Read the CSV file
        $csvData = array_map('str_getcsv', file($csvFilePath));
        if (empty($csvData)) {
            return ['success' => false, 'message' => 'CSV file is empty or invalid'];
        }
        
        $headers = array_shift($csvData); // Remove header row
        
        // Create a mapping of CSV headers to field IDs
        $fieldMapping = [];
        $fieldsByLabel = [];
        $fieldsById = [];
        
        // Build lookup arrays for fields
        foreach ($fields as $field) {
            $fieldsById[$field['id']] = $field;
            $fieldsByLabel[strtolower($field['label'] ?? $field['id'])] = $field;
        }
        
        // Map CSV headers to field IDs
        foreach ($headers as $colIndex => $header) {
            $cleanHeader = trim($header);
            $headerLower = strtolower($cleanHeader);
            
            // Try exact match with field ID first
            if (isset($fieldsById[$cleanHeader])) {
                $fieldMapping[$colIndex] = $cleanHeader;
            }
            // Then try exact match with field label (case insensitive)
            elseif (isset($fieldsByLabel[$headerLower])) {
                $fieldMapping[$colIndex] = $fieldsByLabel[$headerLower]['id'];
            }
            // Try partial matches for common variations
            else {
                $found = false;
                foreach ($fields as $field) {
                    $fieldLabel = strtolower($field['label'] ?? $field['id']);
                    $fieldId = strtolower($field['id']);
                    
                    // Check if header matches field label or ID (case insensitive)
                    if ($headerLower === $fieldLabel || $headerLower === $fieldId) {
                        $fieldMapping[$colIndex] = $field['id'];
                        $found = true;
                        break;
                    }
                    
                    // Check for partial matches for common field patterns
                    if (strpos($fieldLabel, $headerLower) !== false || strpos($headerLower, $fieldLabel) !== false) {
                        $fieldMapping[$colIndex] = $field['id'];
                        $found = true;
                        break;
                    }
                }
                
                if (!$found) {
                    // If no field mapping found, use the header as-is (for custom fields)
                    $fieldMapping[$colIndex] = $cleanHeader;
                }
            }
        }
        
        $reports = [];
        $errors = [];
        $rowNumber = 2; // Start at 2 because header is row 1
        
        foreach ($csvData as $row) {
            // Skip empty rows
            if (empty(array_filter($row))) {
                $rowNumber++;
                continue;
            }
            
            // Skip instruction/comment rows (rows that start with #, //, etc.)
            if (isset($row[0]) && (strpos(trim($row[0]), '#') === 0 || strpos(trim($row[0]), '//') === 0)) {
                $rowNumber++;
                continue;
            }
            
            $reportData = [];
            $hasRequiredData = false;
            
            // Map CSV columns to report fields using our mapping
            foreach ($row as $colIndex => $value) {
                $cleanValue = trim($value);
                
                if (isset($fieldMapping[$colIndex])) {
                    $fieldId = $fieldMapping[$colIndex];
                    $reportData[$fieldId] = $cleanValue;
                    
                    if (!empty($cleanValue)) {
                        $hasRequiredData = true;
                    }
                }
            }
            
            // Skip rows that have no meaningful data
            if (!$hasRequiredData) {
                $rowNumber++;
                continue;
            }
            
            // Validate required fields
            $rowErrors = [];
            foreach ($fields as $field) {
                if (($field['required'] ?? false) && empty($reportData[$field['id']] ?? '')) {
                    $rowErrors[] = "Missing required field: {$field['label']}";
                }
            }
            
            if (!empty($rowErrors)) {
                $errors[] = "Row {$rowNumber}: " . implode(', ', $rowErrors);
            } else {
                // Create the report with user and zone information
                $report = [
                    'id' => generateReportId(),
                    'category_id' => $categoryId,
                    'category_name' => $category['name'] ?? 'Unknown Category',
                    'data' => $reportData,
                    'created_at' => date('Y-m-d H:i:s'),
                    'created_by' => $userId,
                    'submitted_by' => $userId, // Store user ID like manual reports
                    'submitted_by_name' => $user['name'] ?? 'Unknown User', // Store name for display
                    'role' => $user['role'] ?? '',
                    'region' => $user['region'] ?? '',
                    'zone' => $user['zone'] ?? '',
                    'source' => 'bulk_upload'
                ];
                
                $reports[] = $report;
            }
            
            $rowNumber++;
        }
        
        // If there are validation errors, provide debug information
        if (!empty($errors)) {
            $debugInfo = "\n\nDEBUG INFO:\n";
            $debugInfo .= "CSV Headers found: " . implode(', ', $headers) . "\n";
            $debugInfo .= "Field mappings created:\n";
            foreach ($fieldMapping as $colIndex => $fieldId) {
                $headerName = $headers[$colIndex] ?? "Column {$colIndex}";
                $debugInfo .= "  '{$headerName}' -> '{$fieldId}'\n";
            }
            $debugInfo .= "\nExpected field IDs:\n";
            foreach ($fields as $field) {
                $required = ($field['required'] ?? false) ? ' (REQUIRED)' : '';
                $debugInfo .= "  '{$field['id']}' (label: '{$field['label']}'){$required}\n";
            }
            
            return [
                'success' => false, 
                'message' => 'Validation errors found:\n' . implode('\n', array_slice($errors, 0, 5)) . (count($errors) > 5 ? '\n... and ' . (count($errors) - 5) . ' more errors' : '') . $debugInfo
            ];
        }
        
        // If no reports were created, return error
        if (empty($reports)) {
            return ['success' => false, 'message' => 'No valid data rows found in the CSV file'];
        }
        
        // Load existing reports and process updates/inserts
        $existingReports = getReports();
        $updatedCount = 0;
        $createdCount = 0;
        
        // Find the group field ID for this category
        $groupFieldId = null;
        foreach ($fields as $field) {
            if ($field['type'] === 'select' && ($field['source'] ?? 'manual') === 'zones_groups') {
                $groupFieldId = $field['id'];
                break;
            }
        }
        
        if (!$groupFieldId) {
            return ['success' => false, 'message' => 'No group field found in this category. Cannot process bulk upload.'];
        }
        
        $updatedGroups = [];
        $createdGroups = [];
        
        // Before processing reports, ensure all groups from CSV exist in the user's zone
        $newGroupsAdded = [];
        foreach ($reports as $newReport) {
            $groupValue = $newReport['data'][$groupFieldId] ?? '';
            if ($groupValue) {
                $newGroupsAdded = array_merge($newGroupsAdded, ensureGroupExists($groupValue, $user));
            }
        }
        
        foreach ($reports as $newReport) {
            $groupValue = $newReport['data'][$groupFieldId] ?? '';
            
            // Convert group name to group ID if needed
            $groupId = findGroupIdByName($groupValue, $user);
            if ($groupId && $groupId !== $groupValue) {
                // Update the report to use group ID instead of group name
                $newReport['data'][$groupFieldId] = $groupId;
                error_log("Mapped group name '" . $groupValue . "' to ID '" . $groupId . "'");
            }
            
            $finalGroupValue = $newReport['data'][$groupFieldId];
            $existingIndex = null;
            
            // Look for existing report with same user, category, and group
            foreach ($existingReports as $index => $existingReport) {
                if ($existingReport['created_by'] === $userId && 
                    $existingReport['category_id'] === $categoryId &&
                    isset($existingReport['data'][$groupFieldId]) &&
                    $existingReport['data'][$groupFieldId] === $finalGroupValue) {
                    $existingIndex = $index;
                    break;
                }
            }
            
            if ($existingIndex !== null) {
                // Update existing report
                $oldCreatedAt = $existingReports[$existingIndex]['created_at'];
                $existingReports[$existingIndex]['data'] = $newReport['data'];
                $existingReports[$existingIndex]['created_at'] = $newReport['created_at']; // Update timestamp
                $existingReports[$existingIndex]['source'] = 'bulk_upload_update';
                // Ensure proper field structure for analytics
                $existingReports[$existingIndex]['category_name'] = $category['name'] ?? 'Unknown Category';
                $existingReports[$existingIndex]['submitted_by_name'] = $user['name'] ?? 'Unknown User';
                $existingReports[$existingIndex]['role'] = $user['role'] ?? '';
                $existingReports[$existingIndex]['region'] = $user['region'] ?? '';
                $existingReports[$existingIndex]['zone'] = $user['zone'] ?? '';
                $updatedCount++;
                
                // Track the updated group with details
                $updatedGroups[] = [
                    'group_name' => resolveGroupLabelById($finalGroupValue) ?: $finalGroupValue,
                    'group_id' => $finalGroupValue,
                    'previous_date' => $oldCreatedAt
                ];
            } else {
                // Add new report
                $existingReports[] = $newReport;
                $createdCount++;
                
                // Track the new group
                $createdGroups[] = [
                    'group_name' => resolveGroupLabelById($finalGroupValue) ?: $finalGroupValue,
                    'group_id' => $finalGroupValue
                ];
            }
        }
        
        if (saveReports($existingReports)) {
            app_log('bulk_upload_success', 'Bulk upload completed', [
                'category_id' => $categoryId,
                'reports_created' => $createdCount,
                'reports_updated' => $updatedCount,
                'uploaded_by' => $userId
            ]);
            
            // Build detailed success message
            $message = "Bulk upload completed successfully!\n\n";
            
            // Add information about auto-created groups
            if (!empty($newGroupsAdded)) {
                $message .= "🆕 AUTO-CREATED " . count($newGroupsAdded) . " NEW GROUPS:\n";
                foreach ($newGroupsAdded as $group) {
                    $message .= "  • {$group['name']} (now available for future uploads)\n";
                }
                $message .= "\n";
            }
            
            if ($createdCount > 0) {
                $message .= "📝 CREATED {$createdCount} NEW REPORTS:\n";
                foreach ($createdGroups as $group) {
                    $message .= "  • {$group['group_name']}\n";
                }
                $message .= "\n";
            }
            
            if ($updatedCount > 0) {
                $message .= "🔄 UPDATED {$updatedCount} EXISTING REPORTS:\n";
                foreach ($updatedGroups as $group) {
                    $message .= "  • {$group['group_name']} (previously from " . date('M d, Y H:i', strtotime($group['previous_date'])) . ")\n";
                }
                $message .= "\n";
            }
            
            if (empty($createdGroups) && empty($updatedGroups)) {
                $message .= "No changes were made.\n";
            }
            
            return [
                'success' => true, 
                'message' => trim($message),
                'details' => [
                    'created_groups' => $createdGroups,
                    'updated_groups' => $updatedGroups,
                    'created_count' => $createdCount,
                    'updated_count' => $updatedCount
                ]
            ];
        } else {
            return ['success' => false, 'message' => 'Failed to save reports. Please try again.'];
        }
        
    } catch (Exception $e) {
        app_log('bulk_upload_error', 'Bulk upload failed', [
            'category_id' => $categoryId,
            'error' => $e->getMessage(),
            'uploaded_by' => $userId
        ]);
        
        return ['success' => false, 'message' => 'Error processing CSV file: ' . $e->getMessage()];
    }
}

?>
