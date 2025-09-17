<?php
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);
$isAdmin = ($_SESSION['role'] === ROLE_ADMIN);

$reportId = $_GET['id'] ?? '';
$reports = getReports();
$report = null;
$idx = -1;
foreach ($reports as $i => $r) {
    if (($r['id'] ?? '') === $reportId) { $report = $r; $idx = $i; break; }
}
if (!$report) {
    app_log('not_found', 'Edit report not found', ['report_id' => $reportId]);
    header('Location: reports.php');
    exit;
}

// Permission: admin or owner
if (!$isAdmin && (($report['submitted_by'] ?? '') !== ($user['id'] ?? ''))) {
    app_log('auth_error', 'Unauthorized edit attempt', ['report_id' => $reportId, 'user' => $user['id'] ?? null]);
    header('Location: reports.php');
    exit;
}

$category = getCategoryById($report['category_id'] ?? '');
if (!$category) {
    app_log('not_found', 'Edit report category missing', ['report_id' => $reportId, 'category_id' => $report['category_id'] ?? '']);
}

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token on edit submission
    requireCSRFToken();

    if (!$category) {
        $error = 'Category not found';
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
            if (($f['type'] === 'select' || $f['type'] === 'groups')) {
                $opts = resolveFieldOptions($f, $user);
                if (!empty($opts)) {
                    $allowed = array_column($opts, 'id');
                    if ($val !== '' && !in_array($val, $allowed, true)) {
                        $errors[] = ($f['label'] ?? $fid) . ' has an invalid selection';
                    }
                }
            }
            $data[$fid] = $val;
        }
        if (!empty($errors)) {
            $error = implode("\n", $errors);
            app_log('validation_error', 'Report edit validation errors', ['report_id' => $reportId, 'errors' => $errors]);
        } else {
            $reports[$idx]['data'] = $data;
            $reports[$idx]['updated_at'] = date('Y-m-d H:i:s');
            $reports[$idx]['updated_by'] = $user['id'] ?? null;
            if (saveReports($reports) === false) {
                $error = 'Failed to save changes';
                app_log('write_error', 'Failed to save edited report', ['report_id' => $reportId]);
            } else {
                $_SESSION['flash_message'] = 'Report updated successfully';
                header('Location: report_edit.php?id=' . urlencode($reportId));
                exit;
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
    <title>IPPC | Edit Report</title>
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
                <a href="reports.php" class="nav-link"><i class="fas fa-arrow-left"></i> Back to Reports</a>
            </li>
        </ul>
        <ul class="navbar-nav ml-auto">
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
                        <h1 class="m-0">Edit Report</h1>
                        <p class="text-muted mb-0">Category: <?php echo htmlspecialchars($category['name'] ?? 'Unknown'); ?></p>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item"><a href="reports.php">Reports</a></li>
                            <li class="breadcrumb-item active">Edit</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-8">
                        <div class="card card-primary">
                            <div class="card-header"><h3 class="card-title">Update Fields</h3></div>
                            <form method="post">
                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                <div class="card-body">
                                    <?php // Flash messages handled via SweetAlert2 ?>

                                    <?php $fields = isset($category['fields']) && is_array($category['fields']) ? $category['fields'] : []; ?>
                                    <?php if (empty($fields)): ?>
                                        <div class="alert alert-info mb-0">No fields exist for this category.</div>
                                    <?php else: ?>
                                        <?php foreach ($fields as $f): ?>
                                            <?php $fid = $f['id']; $label = $f['label'] ?? $fid; $type = $f['type'] ?? 'text'; $value = $report['data'][$fid] ?? ''; ?>
                                            <div class="form-group">
                                                <label><?php echo htmlspecialchars($label); ?><?php echo !empty($f['required']) ? ' *' : ''; ?></label>
                                                <?php if ($type === 'textarea'): ?>
                                                    <textarea class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]" rows="3" placeholder="<?php echo htmlspecialchars($f['placeholder'] ?? ''); ?>"><?php echo htmlspecialchars($value); ?></textarea>
                                                <?php elseif ($type === 'number'): ?>
                                                    <input type="number" class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]" value="<?php echo htmlspecialchars($value); ?>" placeholder="<?php echo htmlspecialchars($f['placeholder'] ?? ''); ?>">
                                                <?php elseif ($type === 'date'): ?>
                                                    <input type="date" class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]" value="<?php echo htmlspecialchars($value); ?>">
                                                <?php else: ?>
                                                    <?php $isSelect = ($type === 'select' || $type === 'groups'); ?>
                                                    <?php if ($isSelect): ?>
                                                        <?php $opts = resolveFieldOptions($f, $user); ?>
                                                        <select class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]">
                                                            <option value="">-- Select --</option>
                                                            <?php foreach ($opts as $opt): ?>
                                                                <?php $ov = $opt['id']; $ol = $opt['label']; $sel = ($value === $ov) ? 'selected' : ''; ?>
                                                                <option value="<?php echo htmlspecialchars($ov); ?>" <?php echo $sel; ?>><?php echo htmlspecialchars($ol); ?></option>
                                                            <?php endforeach; ?>
                                                        </select>
                                                    <?php else: ?>
                                                        <input type="text" class="form-control" name="field[<?php echo htmlspecialchars($fid); ?>]" value="<?php echo htmlspecialchars($value); ?>" placeholder="<?php echo htmlspecialchars($f['placeholder'] ?? ''); ?>">
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            </div>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </div>
                                <div class="card-footer">
                                    <button type="submit" class="btn btn-primary">Save Changes</button>
                                    <a href="reports.php" class="btn btn-secondary">Cancel</a>
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
