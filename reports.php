<?php
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);
$isAdmin = ($_SESSION['role'] === ROLE_ADMIN);

$reports = getReports();
$categories = getReportCategories();
$categoryById = [];
foreach ($categories as $c) { $categoryById[$c['id']] = $c; }

// Filter for non-admin: show only own submissions
if (!$isAdmin) {
    $reports = array_values(array_filter($reports, function($r) use ($user) {
        return isset($r['submitted_by']) && $r['submitted_by'] === ($user['id'] ?? null);
    }));
}

// Sort reports by submitted_at desc
usort($reports, function($a, $b){
    return strcmp($b['submitted_at'] ?? '', $a['submitted_at'] ?? '');
});

// Group reports by category_id
$grouped = [];
foreach ($reports as $r) {
    $cid = $r['category_id'] ?? 'unknown';
    if (!isset($grouped[$cid])) { $grouped[$cid] = []; }
    $grouped[$cid][] = $r;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | Reports</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.8/css/dataTables.bootstrap4.min.css">
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
            <li class="nav-item"><a class="nav-link" href="reporting.php"><i class="fas fa-plus"></i> Submit Report</a></li>
            <li class="nav-item"><a class="nav-link" href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
        </ul>
    </nav>

    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <div class="content-wrapper">
        <div class="content-header">
            <div class="container-fluid">
                <div class="row mb-2">
                    <div class="col-sm-6">
                        <h1 class="m-0">Submitted Reports</h1>
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
                <?php if (empty($grouped)): ?>
                    <div class="alert alert-info">No reports submitted yet.</div>
                <?php else: ?>
                    <?php foreach ($grouped as $cid => $items): ?>
                        <?php $cat = $categoryById[$cid] ?? ['name' => 'Unknown Category']; ?>
                        <?php $catFields = isset($cat['fields']) && is_array($cat['fields']) ? $cat['fields'] : []; ?>
                        <div class="card card-outline card-secondary">
                            <div class="card-header">
                                <h3 class="card-title">Category: <?php echo htmlspecialchars($cat['name']); ?></h3>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped table-bordered mb-0 datatable">
                                        <thead>
                                            <tr>
                                                <th style="width:180px">Submitted At</th>
                                                <th>Submitted By</th>
                                                <th style="width:100px">Actions</th>
                                                <?php foreach ($catFields as $f): ?>
                                                    <th><?php echo htmlspecialchars($f['label'] ?? $f['id']); ?></th>
                                                <?php endforeach; ?>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($items as $r): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($r['submitted_at'] ?? ''); ?></td>
                                                <td><?php echo htmlspecialchars(($r['submitted_by_name'] ?? '') . ($isAdmin ? ' (' . ($r['role'] ?? '') . ')' : '')); ?></td>
                                                <td>
                                                    <?php $canEdit = $isAdmin || (($r['submitted_by'] ?? '') === ($user['id'] ?? '')); ?>
                                                    <?php if ($canEdit): ?>
                                                        <a class="btn btn-sm btn-primary" href="report_edit.php?id=<?php echo urlencode($r['id']); ?>">
                                                            <i class="fas fa-edit"></i> Edit
                                                        </a>
                                                    <?php else: ?>
                                                        <span class="text-muted">—</span>
                                                    <?php endif; ?>
                                                </td>
                                                <?php foreach ($catFields as $f): ?>
                                                    <?php
                                                        $fid = $f['id'];
                                                        $val = $r['data'][$fid] ?? '';
                                                        // Pretty-print for groups: map ID to group name
                                                        if (($f['type'] ?? '') === 'select' && ($f['source'] ?? 'manual') === 'zones_groups') {
                                                            $val = $val !== '' ? resolveGroupLabelById($val) : '';
                                                        }
                                                    ?>
                                                    <td><?php echo $val === '' ? '<span class="text-muted">—</span>' : htmlspecialchars(is_array($val) ? json_encode($val) : $val); ?></td>
                                                <?php endforeach; ?>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </section>
    </div>

    <footer class="main-footer">
        <strong>&copy; 2024 PPC Management.</strong> All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.8/js/dataTables.bootstrap4.min.js"></script>
<script>
  $(function(){
    $('.datatable').DataTable({
      order: [[0, 'desc']],
      pageLength: 10,
      lengthMenu: [[10, 25, 50, -1], [10, 25, 50, 'All']],
      autoWidth: false
    });
  });
</script>
</body>
</html>
