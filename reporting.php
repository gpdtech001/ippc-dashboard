<?php
if (version_compare(PHP_VERSION, '7.0.0', '<')) {
    die('PHP 7.0+ required for this application.');
}
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

// Fetch categories
$categories = getReportCategories();

// Handle submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token for all POST requests on this page
    requireCSRFToken();

    $categoryId = htmlspecialchars(trim($_POST['category_id'] ?? ''), ENT_QUOTES, 'UTF-8');
    if (!isset($_POST['field']) || !is_array($_POST['field'])) {
        $error = 'Invalid form data';
        app_log('validation_error', 'Invalid POST field data', ['category_id' => $categoryId]);
    } else {
        foreach ($_POST['field'] as $key => $value) {
            $_POST['field'][$key] = htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
        }
        $category = getCategoryById($categoryId);
        if (strlen($categoryId) > 100) {
            $error = 'Category ID too long';
            app_log('validation_error', 'Category ID too long', ['category_id' => $categoryId]);
        } elseif (!$category) {
            $error = 'Invalid category';
            app_log('validation_error', 'Report submit invalid category', ['category_id' => $categoryId]);
        } else {
        $fields = isset($category['fields']) && is_array($category['fields']) ? $category['fields'] : [];
        $data = [];
        $errors = [];
        foreach ($fields as $f) {
            $fid = $f['id'];
            $val = isset($_POST['field'][$fid]) ? trim($_POST['field'][$fid]) : '';
            if (!empty($f['required']) && $val === '') {
                $errors[] = ($f['label'] ?? $fid) . ' is required';
            }
            // Validate field based on resolved input type
            $fieldType = $f['type'] ?? 'text';
            $inputType = resolveFieldInputType($fieldType);

            // Validate select options when applicable
            if ($inputType === 'select' || $fieldType === 'groups' || $fieldType === 'currency') {
                try {
                    $opts = resolveFieldOptions($f, $user);
                } catch (Exception $e) {
                    $opts = [];
                    $errors[] = 'Error loading options for ' . ($f['label'] ?? $fid) . ': ' . $e->getMessage();
                }
                if (!empty($opts)) {
                    $allowed = array_column($opts, 'id');
                    if ($val !== '' && !in_array($val, $allowed, true)) {
                        $errors[] = ($f['label'] ?? $fid) . ' has an invalid selection';
                    }
                } else {
                    if ($val !== '') {
                        $errors[] = ($f['label'] ?? $fid) . ' has no available options but value provided';
                    }
                }
            }

            // Additional validation based on input type
            if ($inputType === 'number' && $val !== '' && filter_var($val, FILTER_VALIDATE_FLOAT) === false) {
                $errors[] = ($f['label'] ?? $fid) . ' must be a valid number';
            }

            if ($inputType === 'email' && $val !== '' && !filter_var($val, FILTER_VALIDATE_EMAIL)) {
                $errors[] = ($f['label'] ?? $fid) . ' must be a valid email address';
            }

            // Length check
            if (strlen($val) > 1000) {
                $errors[] = ($f['label'] ?? $fid) . ' is too long (max 1000 characters)';
            }

            $data[$fid] = $val;
        }

        if (!empty($errors)) {
            $error = implode('\n', $errors);
            app_log('validation_error', 'Report submission validation errors', ['errors' => $errors, 'category_id' => $categoryId]);
        } else {
            try {
                $reports = getReports();
            } catch (Exception $e) {
                $error = 'Failed to load reports: ' . $e->getMessage();
                app_log('error', 'Failed to load reports', ['error' => $e->getMessage()]);
            }
            if (!$error) {
                try {
                    $id = generateReportId();
                } catch (Exception $e) {
                    $error = 'Failed to generate report ID: ' . $e->getMessage();
                    app_log('error', 'Failed to generate report ID', ['error' => $e->getMessage()]);
                }
                if (!$error) {
                    $timestamp = date('Y-m-d H:i:s');
                    $rep = [
                        'id' => $id,
                        'category_id' => $category['id'],
                        'category_name' => $category['name'] ?? '',
                        'submitted_by' => $user['id'] ?? null,
                        'submitted_by_name' => $user['name'] ?? '',
                        'role' => $user['role'] ?? '',
                        'region' => $user['region'] ?? null,
                        'zone' => $user['zone'] ?? null,
                        'submitted_at' => $timestamp,
                        'created_at' => $timestamp,
                        'created_by' => $user['id'] ?? null,
                        'source' => 'manual',
                        'data' => $data
                    ];
                    $reports[] = $rep;
                    try {
                        if (saveReports($reports) === false) {
                            throw new Exception('Save failed');
                        }
                    } catch (Exception $e) {
                        $error = 'Failed to save report: ' . $e->getMessage();
                        app_log('write_error', 'Failed to save report', ['category_id' => $categoryId, 'error' => $e->getMessage()]);
                    }
                    if (!$error) {
                        $_SESSION['flash_message'] = 'Report submitted successfully';
                        header('Location: reporting.php');
                        exit;
                    }
                }
            }
        }
    }
}
}

// Determine selected category (for rendering form)
$selectedCategoryId = htmlspecialchars(trim($_GET['category_id'] ?? ''), ENT_QUOTES, 'UTF-8') ?: htmlspecialchars(trim($_POST['category_id'] ?? ''), ENT_QUOTES, 'UTF-8');
$selectedCategory = $selectedCategoryId ? getCategoryById($selectedCategoryId) : null;

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Reports</title>
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
                        <h1 class="m-0">Submit Report</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Reports</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-4">
                        <div class="card card-outline card-secondary">
                            <div class="card-header"><h3 class="card-title">Report Categories</h3></div>
                            <div class="card-body">
                                <?php if (empty($categories)): ?>
                                    <div class="text-muted">No categories defined yet.</div>
                                <?php else: ?>
                                    <select class="form-control" id="categorySelect" onchange="if(this.value) window.location.href='reporting.php?category_id='+this.value;">
                                        <option value="">-- Select Category --</option>
                                        <?php foreach ($categories as $cat): ?>
                                            <option value="<?php echo htmlspecialchars($cat['id']); ?>" <?php echo ($selectedCategoryId === $cat['id']) ? 'selected' : ''; ?>><?php echo htmlspecialchars($cat['name']); ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-8">
                        <div class="card card-primary">
                            <div class="card-header"><h3 class="card-title">Report Form</h3></div>
                            <form method="post">
                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                <div class="card-body">
                                    <?php // Flash messages handled via SweetAlert2 ?>
                                    <?php if ($selectedCategory): ?>
                                        <input type="hidden" name="category_id" value="<?php echo htmlspecialchars($selectedCategory['id']); ?>">
                                        <div class="mb-3">
                                            <span class="badge badge-secondary">Category: <?php echo htmlspecialchars($selectedCategory['name']); ?></span>
                                        </div>
                                    <?php else: ?>
                                        <div class="alert alert-info mb-3">Select a category from the left to load its form.</div>
                                    <?php endif; ?>

                                    <?php if ($selectedCategory): ?>
                                        <?php $fields = isset($selectedCategory['fields']) && is_array($selectedCategory['fields']) ? $selectedCategory['fields'] : []; ?>
                                        <?php if (empty($fields)): ?>
                                            <div class="alert alert-info mb-0">No fields configured for this category.</div>
                                        <?php else: ?>
                                            <?php foreach ($fields as $f): ?>
                                                <?php
                                                    $fid = $f['id'];
                                                    $label = $f['label'] ?? $fid;
                                                    $fieldType = $f['type'] ?? 'text';
                                                    $inputType = resolveFieldInputType($fieldType);
                                                ?>
                                                <div class="form-group">
                                                    <label><?php echo htmlspecialchars($label); ?><?php echo !empty($f['required']) ? ' *' : ''; ?></label>
                                                    <?php if ($inputType === 'textarea'): ?>
                                                        <textarea class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]" rows="3" placeholder="<?php echo htmlspecialchars($f['placeholder'] ?? ''); ?>"><?php echo htmlspecialchars($_POST['field'][$fid] ?? ''); ?></textarea>
                                                    <?php elseif ($inputType === 'select' || $fieldType === 'groups' || $fieldType === 'currency'): ?>
                                                        <?php $opts = resolveFieldOptions($f, $user); ?>
                                                        <select class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]">
                                                            <option value="">-- Select --</option>
                                                            <?php foreach ($opts as $opt): ?>
                                                                <?php $ov = $opt['id']; $ol = $opt['label']; $sel = (($_POST['field'][$fid] ?? '') === $ov) ? 'selected' : ''; ?>
                                                                <option value="<?php echo htmlspecialchars($ov); ?>" <?php echo $sel; ?>><?php echo htmlspecialchars($ol); ?></option>
                                                            <?php endforeach; ?>
                                                        </select>
                                                    <?php else: ?>
                                                        <input type="<?php echo htmlspecialchars($inputType); ?>" class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]" value="<?php echo htmlspecialchars($_POST['field'][$fid] ?? ''); ?>" placeholder="<?php echo htmlspecialchars($f['placeholder'] ?? ''); ?>">
                                                    <?php endif; ?>
                                                </div>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </div>
                                <div class="card-footer">
                                    <button type="submit" class="btn btn-primary" <?php echo $selectedCategory ? '' : 'disabled'; ?>>Submit Report</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </div>

    <footer class="main-footer">
        <strong>&copy; 2024 IPPC Dashboard.</strong> All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script src="assets/js/sweetalert-init.js"></script>
<script>
window.__FLASH_MESSAGES__ = {
    success: <?php echo json_encode($message ?? ''); ?>,
    error: <?php echo json_encode($error ?? ''); ?>,
    errorTitle: 'Error'
};
</script>
</body>
</html>
