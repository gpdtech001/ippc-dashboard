<?php
require_once 'config.php';

session_start();
requireAdmin();

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

// Page configuration
$pageTitle = 'Field Types Management';
$pageDescription = 'Create and manage custom field types for reports';

// Statistics
$stats = [
    'total_types' => 0,
    'custom_types' => 0,
    'system_types' => 0,
    'used_in_categories' => 0
];

// Load managed types and discovered ones from categories
$types = getFieldTypes();
$managedKeys = array_column($types, 'key');

// Calculate statistics
$stats['total_types'] = count($types);
$stats['system_types'] = count(array_filter($types, function($t) {
    return strpos($t['id'], 'type_') === 0; // System types start with 'type_'
}));
$stats['custom_types'] = $stats['total_types'] - $stats['system_types'];

// Count usage in categories
$categories = getReportCategories();
$usedTypes = [];
foreach ($categories as $cat) {
    $fields = $cat['fields'] ?? [];
    foreach ($fields as $field) {
        $type = $field['type'] ?? '';
        if ($type) {
            $usedTypes[$type] = true;
        }
    }
}
$stats['used_in_categories'] = count($usedTypes);

function discoverTypesFromCategories() {
    $cats = getReportCategories();
    $found = [];
    foreach ($cats as $cat) {
        $fields = isset($cat['fields']) && is_array($cat['fields']) ? $cat['fields'] : [];
        foreach ($fields as $f) {
            $base = $f['type'] ?? 'text';
            $src = $f['source'] ?? 'manual';
            // Map select+zones_groups to groups pseudo-type for clarity
            $key = ($base === 'select' && $src === 'zones_groups') ? 'groups' : $base;
            if (!isset($found[$key])) {
                $found[$key] = [ 'key' => $key, 'base_type' => ($key === 'groups' ? 'select' : $base), 'source' => ($key === 'groups' ? 'zones_groups' : $src) ];
            }
        }
    }
    return $found;
}

$discovered = discoverTypesFromCategories();

// JSON download
if (isset($_GET['download']) && $_GET['download'] === 'json') {
    header('Content-Type: application/json');
    echo json_encode($types, JSON_PRETTY_PRINT);
    exit;
}

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if ($action === 'add_type') {
        $key = sanitizeInput($_POST['key'] ?? '');
        $label = sanitizeInput($_POST['label'] ?? '');
        $base = sanitizeInput($_POST['base_type'] ?? 'text');
        $source = sanitizeInput($_POST['source'] ?? 'manual');
        $description = sanitizeInput($_POST['description'] ?? '');

        if (empty($key) || empty($label)) {
            $error = 'Key and Label are required';
            app_log('validation_error', 'Missing key/label for field type add');
        } elseif (in_array($key, array_column($types, 'key'), true)) {
            $error = 'Type key already exists';
            app_log('validation_error', 'Duplicate type key', ['key' => $key]);
        } else {
            $types[] = [
                'id' => uniqid('ft_', true),
                'key' => $key,
                'label' => $label,
                'base_type' => $base,
                'source' => $base === 'select' ? $source : 'manual',
                'description' => $description,
            ];
            if (saveFieldTypes($types) === false) {
                $error = 'Failed to save type';
            } else {
                $_SESSION['flash_message'] = 'Type added';
                header('Location: field_types.php');
                exit;
            }
        }
    } elseif ($action === 'delete_type') {
        $key = sanitizeInput($_POST['key'] ?? '');
        $before = count($types);
        $types = array_values(array_filter($types, function ($t) use ($key) { return $t['key'] !== $key; }));
        if ($before === count($types)) {
            $_SESSION['flash_error'] = 'Type not found';
        } else {
            if (saveFieldTypes($types) === false) {
                $error = 'Failed to delete type';
            } else {
                $_SESSION['flash_message'] = 'Type deleted';
            }
        }
        header('Location: field_types.php');
        exit;
    } elseif ($action === 'adopt_discovered') {
        $key = sanitizeInput($_POST['key'] ?? '');
        if (!$key || !isset($discovered[$key])) {
            $error = 'Discovered type not found';
        } elseif (in_array($key, array_column($types, 'key'), true)) {
            $error = 'Type already exists';
        } else {
            $meta = $discovered[$key];
            $types[] = [
                'id' => uniqid('ft_', true),
                'key' => $key,
                'label' => ucfirst($key),
                'base_type' => $meta['base_type'],
                'source' => $meta['source'],
                'description' => 'Imported from existing fields',
            ];
            if (saveFieldTypes($types) === false) {
                $error = 'Failed to save type';
            } else {
                $_SESSION['flash_message'] = 'Type added';
                header('Location: field_types.php');
                exit;
            }
        }
    } elseif ($action === 'edit_type') {
        $key = sanitizeInput($_POST['key'] ?? '');
        $label = sanitizeInput($_POST['label'] ?? '');
        $base = sanitizeInput($_POST['base_type'] ?? 'text');
        $source = sanitizeInput($_POST['source'] ?? 'manual');
        $description = sanitizeInput($_POST['description'] ?? '');

        if (empty($key) || empty($label)) {
            $error = 'Key and Label are required';
            app_log('validation_error', 'Missing key/label for field type edit');
        } else {
            $found = false;
            foreach ($types as &$t) {
                if ($t['key'] === $key) {
                    $t['label'] = $label;
                    $t['base_type'] = $base;
                    $t['source'] = $base === 'select' ? $source : 'manual';
                    $t['description'] = $description;
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $error = 'Type not found';
                app_log('not_found', 'Edit non-existent field type', ['key' => $key]);
            } else {
                if (saveFieldTypes($types) === false) {
                    $error = 'Failed to save changes';
                } else {
                    $_SESSION['flash_message'] = 'Type updated';
                    header('Location: field_types.php');
                    exit;
                }
            }
        }
    } elseif ($action === 'import_types') {
        $mode = sanitizeInput($_POST['mode'] ?? 'replace'); // replace|merge
        $content = '';
        if (!empty($_FILES['json_file']['tmp_name'])) {
            $content = @file_get_contents($_FILES['json_file']['tmp_name']);
        } elseif (!empty($_POST['json_text'])) {
            $content = $_POST['json_text'];
        }
        if ($content === '') {
            $error = 'Please provide a JSON file or paste JSON';
        } else {
            $parsed = json_decode($content, true);
            if (!is_array($parsed)) {
                $error = 'Invalid JSON';
                app_log('validation_error', 'Import invalid JSON for field types');
            } else {
                // Normalize imported entries
                $normalized = [];
                foreach ($parsed as $item) {
                    if (!is_array($item)) continue;
                    $key = isset($item['key']) ? sanitizeInput($item['key']) : '';
                    $label = isset($item['label']) ? sanitizeInput($item['label']) : '';
                    $base = isset($item['base_type']) ? sanitizeInput($item['base_type']) : 'text';
                    $source = isset($item['source']) ? sanitizeInput($item['source']) : 'manual';
                    $desc = isset($item['description']) ? sanitizeInput($item['description']) : '';
                    if (!$key || !$label) continue;
                    $normalized[] = [
                        'id' => $item['id'] ?? uniqid('ft_', true),
                        'key' => $key,
                        'label' => $label,
                        'base_type' => $base,
                        'source' => $base === 'select' ? $source : 'manual',
                        'description' => $desc,
                    ];
                }
                if (empty($normalized)) {
                    $error = 'No valid types found in JSON';
                } else {
                    if ($mode === 'replace') {
                        $types = $normalized;
                    } else { // merge
                        $byKey = [];
                        foreach ($types as $t) { $byKey[$t['key']] = $t; }
                        foreach ($normalized as $n) { $byKey[$n['key']] = $n; }
                        $types = array_values($byKey);
                    }
                    if (saveFieldTypes($types) === false) {
                        $error = 'Failed to import types';
                    } else {
                        $_SESSION['flash_message'] = 'Types imported';
                        header('Location: field_types.php');
                        exit;
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Field Types</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
</head>
<body class="hold-transition sidebar-mini layout-fixed">
<div class="wrapper">
    <nav class="main-header navbar navbar-expand navbar-white navbar-light">
        <ul class="navbar-nav">
            <li class="nav-item">
                <a class="nav-link" data-widget="pushmenu" href="#" role="button"><i class="fas fa-bars"></i></a>
            </li>
            <li class="nav-item d-none d-sm-inline-block">
                <a href="dashboard.php" class="nav-link">Home</a>
            </li>
        </ul>
        <ul class="navbar-nav ml-auto">
            <li class="nav-item">
                <a class="nav-link" href="profile.php"><i class="fas fa-user"></i> Profile</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </li>
        </ul>
    </nav>

    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content-wrapper">
        <div class="content-header">
            <div class="container-fluid">
                <div class="row mb-2">
                    <div class="col-sm-6">
                        <h1 class="m-0"><?php echo htmlspecialchars($pageTitle); ?></h1>
                        <p class="text-muted mb-0"><?php echo htmlspecialchars($pageDescription); ?></p>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Field Types</li>
                        </ol>
                    </div>
                </div>

                <!-- Statistics Dashboard -->
                <div class="row mb-4">
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-info">
                            <div class="inner">
                                <h3><?php echo $stats['total_types']; ?></h3>
                                <p>Total Field Types</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-shapes"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-success">
                            <div class="inner">
                                <h3><?php echo $stats['custom_types']; ?></h3>
                                <p>Custom Types</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-plus-circle"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-warning">
                            <div class="inner">
                                <h3><?php echo $stats['system_types']; ?></h3>
                                <p>System Types</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-cog"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-danger">
                            <div class="inner">
                                <h3><?php echo $stats['used_in_categories']; ?></h3>
                                <p>Types in Use</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-chart-bar"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <!-- Quick Actions -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card card-outline card-primary">
                            <div class="card-header">
                                <h3 class="card-title">Quick Actions</h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-3">
                                        <button type="button" class="btn btn-primary btn-block" data-toggle="modal" data-target="#addTypeModal">
                                            <i class="fas fa-plus"></i> Add New Type
                                        </button>
                                    </div>
                                    <div class="col-md-3">
                                        <button type="button" class="btn btn-success btn-block" data-toggle="modal" data-target="#importModal">
                                            <i class="fas fa-upload"></i> Import JSON
                                        </button>
                                    </div>
                                    <div class="col-md-3">
                                        <a href="?download=json" class="btn btn-info btn-block">
                                            <i class="fas fa-download"></i> Export JSON
                                        </a>
                                    </div>
                                    <div class="col-md-3">
                                        <a href="report_categories.php" class="btn btn-warning btn-block">
                                            <i class="fas fa-external-link-alt"></i> Use in Reports
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Main Content -->
                <div class="row">
                    <div class="col-md-5">
                        <div class="card card-primary">
                            <div class="card-header">
                                <h3 class="card-title"><i class="fas fa-plus"></i> Create Field Type</h3>
                            </div>
                            <form method="post">
                                <div class="card-body">
                                    <?php if (!empty($message)): ?>
                                        <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
                                    <?php endif; ?>
                                    <?php if (!empty($error)): ?>
                                        <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                                    <?php endif; ?>
                                    <input type="hidden" name="action" value="add_type">
                                    <div class="form-group">
                                        <label>Key *</label>
                                        <input type="text" name="key" class="form-control" placeholder="e.g. text, number, select, groups" required>
                                    </div>
                                    <div class="form-group">
                                        <label>Label *</label>
                                        <input type="text" name="label" class="form-control" placeholder="Display label" required>
                                    </div>
                                    <div class="form-group">
                                        <label>Base Type *</label>
                                        <select name="base_type" class="form-control" id="base_type_select" onchange="toggleSource()" required>
                                            <option value="text">Text</option>
                                            <option value="textarea">Textarea</option>
                                            <option value="number">Number</option>
                                            <option value="date">Date</option>
                                            <option value="email">Email</option>
                                            <option value="url">URL</option>
                                            <option value="tel">Telephone</option>
                                            <option value="password">Password</option>
                                            <option value="select">Select</option>
                                        </select>
                                    </div>
                                    <div class="form-group" id="source_group" style="display:none;">
                                        <label>Source</label>
                                        <select name="source" id="source_select" class="form-control">
                                            <option value="manual">Manual</option>
                                            <option value="zones_groups">Zones: Groups</option>
                                        </select>
                                    </div>
                                    <div class="form-group">
                                        <label>Description</label>
                                        <textarea name="description" class="form-control" rows="3" placeholder="Optional description"></textarea>
                                    </div>
                                </div>
                                <div class="card-footer">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-plus"></i> Create Field Type
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <div class="col-md-7">
                        <div class="card card-outline card-secondary mb-3">
                            <div class="card-header">
                                <h3 class="card-title"><i class="fas fa-list"></i> Field Types (<?php echo count($types); ?>)</h3>
                                <div class="card-tools">
                                    <a href="base_types_manager.php" class="btn btn-sm btn-primary mr-1">
                                        <i class="fas fa-cogs"></i> Base Types Manager
                                    </a>
                                    <a href="?download=json" class="btn btn-sm btn-info">
                                        <i class="fas fa-download"></i> Export
                                    </a>
                                </div>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped mb-0">
                                        <thead class="bg-light">
                                            <tr>
                                                <th><i class="fas fa-key text-muted"></i> Key</th>
                                                <th><i class="fas fa-tag text-muted"></i> Label</th>
                                                <th><i class="fas fa-code text-muted"></i> Base Type</th>
                                                <th><i class="fas fa-database text-muted"></i> Source</th>
                                                <th><i class="fas fa-info-circle text-muted"></i> Description</th>
                                                <th><i class="fas fa-cogs text-muted"></i> Type</th>
                                                <th style="width:140px"><i class="fas fa-tools text-muted"></i> Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (empty($types)): ?>
                                                <tr><td colspan="7" class="text-center text-muted py-4">
                                                    <i class="fas fa-inbox fa-2x text-muted mb-2"></i><br>
                                                    No field types found
                                                </td></tr>
                                            <?php else: foreach ($types as $t): ?>
                                                <tr>
                                                    <td><code><?php echo htmlspecialchars($t['key']); ?></code></td>
                                                    <td><?php echo htmlspecialchars($t['label']); ?></td>
                                                    <td><span class="badge badge-info"><?php echo htmlspecialchars($t['base_type']); ?></span></td>
                                                    <td><?php echo htmlspecialchars($t['source'] ?? 'manual'); ?></td>
                                                    <td><?php echo htmlspecialchars($t['description'] ?? ''); ?></td>
                                                    <td>
                                                        <?php if (strpos($t['id'], 'type_') === 0): ?>
                                                            <span class="badge badge-warning"><i class="fas fa-cog"></i> System</span>
                                                        <?php else: ?>
                                                            <span class="badge badge-success"><i class="fas fa-user"></i> Custom</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <button type="button" class="btn btn-sm btn-primary mr-1" data-toggle="modal" data-target="#editTypeModal"
                                                            data-key="<?php echo htmlspecialchars($t['key']); ?>"
                                                            data-label="<?php echo htmlspecialchars($t['label']); ?>"
                                                            data-base="<?php echo htmlspecialchars($t['base_type']); ?>"
                                                            data-source="<?php echo htmlspecialchars($t['source'] ?? 'manual'); ?>"
                                                            data-description="<?php echo htmlspecialchars($t['description'] ?? ''); ?>">
                                                            <i class="fas fa-edit"></i>
                                                        </button>
                                                        <form method="post" class="d-inline" onsubmit="return confirm('Delete this type?');">
                                                            <input type="hidden" name="action" value="delete_type">
                                                            <input type="hidden" name="key" value="<?php echo htmlspecialchars($t['key']); ?>">
                                                            <button type="submit" class="btn btn-sm btn-danger"><i class="fas fa-trash"></i></button>
                                                        </form>
                                                    </td>
                                                </tr>
                                            <?php endforeach; endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="card card-outline card-info">
                            <div class="card-header"><h3 class="card-title">Discovered From Categories</h3></div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped mb-0">
                                        <thead>
                                            <tr>
                                                <th>Key</th>
                                                <th>Base</th>
                                                <th>Source</th>
                                                <th style="width:120px">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php
                                                $managed = array_column($types, 'key');
                                                $hasRows = false;
                                                foreach ($discovered as $k => $meta):
                                                    if (in_array($k, $managed, true)) continue;
                                                    $hasRows = true;
                                            ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($k); ?></td>
                                                    <td><?php echo htmlspecialchars($meta['base_type']); ?></td>
                                                    <td><?php echo htmlspecialchars($meta['source']); ?></td>
                                                    <td>
                                                        <form method="post" class="d-inline">
                                                            <input type="hidden" name="action" value="adopt_discovered">
                                                            <input type="hidden" name="key" value="<?php echo htmlspecialchars($k); ?>">
                                                            <button type="submit" class="btn btn-sm btn-primary">Add</button>
                                                        </form>
                                                    </td>
                                                </tr>
                                            <?php endforeach; if (!$hasRows): ?>
                                                <tr><td colspan="4" class="text-center text-muted">No undiscovered types</td></tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="card card-outline card-success mt-3">
                            <div class="card-header"><h3 class="card-title">Import / Export JSON</h3></div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <a class="btn btn-sm btn-secondary" href="field_types.php?download=json"><i class="fas fa-download"></i> Download JSON</a>
                                </div>
                                <form method="post" enctype="multipart/form-data">
                                    <input type="hidden" name="action" value="import_types">
                                    <div class="form-group">
                                        <label>Upload JSON file</label>
                                        <input type="file" name="json_file" accept="application/json" class="form-control-file">
                                    </div>
                                    <div class="form-group">
                                        <label>Or paste JSON</label>
                                        <textarea name="json_text" class="form-control" rows="6" placeholder='[ {"key":"text", "label":"Text", "base_type":"text"} ]'></textarea>
                                    </div>
                                    <div class="form-group">
                                        <label>Mode</label>
                                        <select name="mode" class="form-control">
                                            <option value="replace">Replace all types</option>
                                            <option value="merge">Merge (update by key)</option>
                                        </select>
                                    </div>
                                    <button type="submit" class="btn btn-success">Import</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Documentation Section -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-primary">
                            <div class="card-header">
                                <h3 class="card-title"><i class="fas fa-book"></i> Field Types System Documentation</h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h5><i class="fas fa-code"></i> Base Types Reference</h5>
                                        <table class="table table-sm table-bordered">
                                            <thead>
                                                <tr>
                                                    <th>Type</th>
                                                    <th>HTML Element</th>
                                                    <th>Use Case</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <tr><td><code>text</code></td><td><code>&lt;input type="text"&gt;</code></td><td>Single-line text</td></tr>
                                                <tr><td><code>textarea</code></td><td><code>&lt;textarea&gt;</code></td><td>Multi-line text</td></tr>
                                                <tr><td><code>number</code></td><td><code>&lt;input type="number"&gt;</code></td><td>Numbers with spinner</td></tr>
                                                <tr><td><code>date</code></td><td><code>&lt;input type="date"&gt;</code></td><td>Date picker</td></tr>
                                                <tr><td><code>email</code></td><td><code>&lt;input type="email"&gt;</code></td><td>Email validation</td></tr>
                                                <tr><td><code>url</code></td><td><code>&lt;input type="url"&gt;</code></td><td>URL validation</td></tr>
                                                <tr><td><code>tel</code></td><td><code>&lt;input type="tel"&gt;</code></td><td>Phone numbers</td></tr>
                                                <tr><td><code>password</code></td><td><code>&lt;input type="password"&gt;</code></td><td>Masked input</td></tr>
                                                <tr><td><code>select</code></td><td><code>&lt;select&gt;</code></td><td>Dropdown options</td></tr>
                                            </tbody>
                                        </table>
                                    </div>
                                    <div class="col-md-6">
                                        <h5><i class="fas fa-lightbulb"></i> Best Practices</h5>
                                        <ul class="list-unstyled">
                                            <li><i class="fas fa-check text-success"></i> Use descriptive keys (PascalCase)</li>
                                            <li><i class="fas fa-check text-success"></i> Provide clear labels and descriptions</li>
                                            <li><i class="fas fa-check text-success"></i> Choose appropriate base types for validation</li>
                                            <li><i class="fas fa-check text-success"></i> Test field types in report forms</li>
                                            <li><i class="fas fa-check text-success"></i> Use consistent naming conventions</li>
                                        </ul>

                                        <h6><i class="fas fa-cog"></i> System Features</h6>
                                        <ul class="list-unstyled">
                                            <li><i class="fas fa-check text-info"></i> Automatic HTML input type resolution</li>
                                            <li><i class="fas fa-check text-info"></i> Built-in validation for supported types</li>
                                            <li><i class="fas fa-check text-info"></i> JSON export/import functionality</li>
                                            <li><i class="fas fa-check text-info"></i> Dynamic source support (zones_groups)</li>
                                            <li><i class="fas fa-check text-info"></i> Real-time statistics and usage tracking</li>
                                        </ul>

                                        <h6><i class="fas fa-question-circle"></i> Need Help?</h6>
                                        <p class="text-muted mb-0">Field types automatically resolve to proper HTML input elements with built-in validation and user experience enhancements.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </div>

    <footer class="main-footer">
        <strong>&copy; 2024 IPPC Dashboard.</strong> All rights reserved.
    </footer>
    <!-- Edit Type Modal -->
    <div class="modal fade" id="editTypeModal" tabindex="-1" role="dialog">
      <div class="modal-dialog" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Edit Field Type</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <form method="post">
            <div class="modal-body">
              <input type="hidden" name="action" value="edit_type">
              <div class="form-group">
                <label>Key (read-only)</label>
                <input type="text" class="form-control" id="edit_key" name="key" readonly>
              </div>
              <div class="form-group">
                <label>Label *</label>
                <input type="text" class="form-control" id="edit_label" name="label" required>
              </div>
              <div class="form-group">
                <label>Base Type *</label>
                <select class="form-control" id="edit_base_type" name="base_type" onchange="document.getElementById('edit_source_group').style.display = (this.value==='select')?'':'none'" required>
                  <option value="text">Text</option>
                  <option value="textarea">Textarea</option>
                  <option value="number">Number</option>
                  <option value="date">Date</option>
                  <option value="email">Email</option>
                  <option value="url">URL</option>
                  <option value="tel">Telephone</option>
                  <option value="password">Password</option>
                  <option value="select">Select</option>
                </select>
              </div>
              <div class="form-group" id="edit_source_group" style="display:none;">
                <label>Source</label>
                <select class="form-control" id="edit_source" name="source">
                  <option value="manual">Manual</option>
                  <option value="zones_groups">Zones: Groups</option>
                </select>
              </div>
              <div class="form-group">
                <label>Description</label>
                <textarea class="form-control" id="edit_description" name="description" rows="3"></textarea>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Save Changes</button>
            </div>
          </form>
        </div>
      </div>
    </div>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script>
function toggleSource() {
    var baseSel = document.getElementById('base_type_select');
    var group = document.getElementById('source_group');
    if (!baseSel || !group) return;
    group.style.display = baseSel.value === 'select' ? '' : 'none';
}
document.addEventListener('DOMContentLoaded', toggleSource);

$('#editTypeModal').on('show.bs.modal', function (event) {
    var b = $(event.relatedTarget);
    $('#edit_key').val(b.data('key'));
    $('#edit_label').val(b.data('label'));
    $('#edit_base_type').val(b.data('base'));
    $('#edit_source').val(b.data('source'));
    $('#edit_description').val(b.data('description'));
    // Toggle source visibility based on base type
    var group = document.getElementById('edit_source_group');
    if (group) group.style.display = (b.data('base') === 'select') ? '' : 'none';
});
</script>
</body>
</html>
