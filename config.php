<?php
// Runtime error logging configuration
define('ERROR_LOG_FILE', __DIR__ . '/error.log');
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', ERROR_LOG_FILE);

// Ensure a file exists and is writable; try to create and relax perms if needed
function ensureWritableFile($path) {
    if (!file_exists($path)) {
        $result = @file_put_contents($path, '');
        if ($result === false) {
            app_log('file_creation_error', 'Failed to create file', ['path' => $path]);
            return false;
        }
    }
    // Attempt to relax permissions for web-server write access
    if (!is_writable($path)) {
        // Try chmod, but don't fail if it doesn't work (some systems don't allow it)
        @chmod($path, 0666);
        // If still not writable, log the issue but continue
        if (!is_writable($path)) {
            app_log('permission_warning', 'File not writable after chmod attempt', ['path' => $path]);
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
    // Prefer PHP's error_log to avoid race conditions; ensure file first
    ensureWritableFile(ERROR_LOG_FILE);
    @error_log($line, 3, ERROR_LOG_FILE);
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

function requireLogin() {
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
            return $category;
        }
    }
    return null;
}

// Resolve dynamic options for field based on source and user context
function resolveFieldOptions($field, $user) {
    $type = $field['type'] ?? 'text';
    if ($type !== 'select') {
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

// Resolve the proper HTML input type for a field, including custom field types
function resolveFieldInputType($fieldType) {
    // Handle standard HTML types directly
    $standardTypes = ['text', 'textarea', 'number', 'date', 'select', 'email', 'password', 'tel', 'url'];
    if (in_array($fieldType, $standardTypes)) {
        return $fieldType;
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
    if (!ensureWritableFile(REPORTS_FILE)) {
        app_log('write_error', 'Reports file not writable', ['file' => REPORTS_FILE]);
        return false;
    }
    $json = json_encode($reports, JSON_PRETTY_PRINT);
    if ($json === false) {
        app_log('json_error', 'Failed to encode reports to JSON', ['error' => json_last_error_msg()]);
        return false;
    }
    $fp = fopen(REPORTS_FILE, 'w');
    if (!$fp) {
        app_log('write_error', 'Failed to open reports file for writing', ['file' => REPORTS_FILE]);
        return false;
    }
    if (flock($fp, LOCK_EX)) {
        $result = fwrite($fp, $json);
        flock($fp, LOCK_UN);
        fclose($fp);
        if ($result === false) {
            app_log('write_error', 'Failed to write reports file', ['file' => REPORTS_FILE]);
            return false;
        }
    } else {
        fclose($fp);
        app_log('write_error', 'Failed to lock reports file', ['file' => REPORTS_FILE]);
        return false;
    }
    return true;
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
?>
