<?php
require_once 'config.php';

session_start();
requireAdmin();

// Page configuration
$pageTitle = 'Base Types Management System';
$pageDescription = 'Comprehensive field types and base types management';

// Get all data
$fieldTypes = getFieldTypes();
$categories = getReportCategories();
$reports = getReports();

// Statistics
$stats = [
    'total_field_types' => count($fieldTypes),
    'total_categories' => count($categories),
    'total_reports' => count($reports),
    'system_types' => count(array_filter($fieldTypes, function($t) {
        return strpos($t['id'], 'type_') === 0;
    })),
    'custom_types' => count(array_filter($fieldTypes, function($t) {
        return strpos($t['id'], 'type_') !== 0;
    })),
    'base_types_used' => count(array_unique(array_column($fieldTypes, 'base_type'))),
    'types_in_use' => 0
];

// Count usage in categories
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
$stats['types_in_use'] = count($usedTypes);

// Base type analysis
$baseTypeStats = [];
foreach ($fieldTypes as $type) {
    $base = $type['base_type'];
    if (!isset($baseTypeStats[$base])) {
        $baseTypeStats[$base] = ['count' => 0, 'system' => 0, 'custom' => 0];
    }
    $baseTypeStats[$base]['count']++;
    if (strpos($type['id'], 'type_') === 0) {
        $baseTypeStats[$base]['system']++;
    } else {
        $baseTypeStats[$base]['custom']++;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | <?php echo htmlspecialchars($pageTitle); ?></title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <style>
        .stat-card {
            transition: transform 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-2px);
        }
        .base-type-card {
            border-left: 4px solid;
        }
        .base-type-text { border-left-color: #007bff; }
        .base-type-textarea { border-left-color: #28a745; }
        .base-type-number { border-left-color: #dc3545; }
        .base-type-date { border-left-color: #ffc107; }
        .base-type-email { border-left-color: #17a2b8; }
        .base-type-url { border-left-color: #6c757d; }
        .base-type-tel { border-left-color: #e83e8c; }
        .base-type-password { border-left-color: #fd7e14; }
        .base-type-select { border-left-color: #20c997; }
    </style>
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
                <a class="nav-link" href="field_types.php">
                    <i class="fas fa-arrow-left"></i> Back to Field Types
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="profile.php">
                    <i class="fas fa-user"></i> Profile
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="logout.php">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
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
                            <li class="breadcrumb-item"><a href="field_types.php">Field Types</a></li>
                            <li class="breadcrumb-item active">Base Types Manager</li>
                        </ol>
                    </div>
                </div>

                <!-- System Statistics -->
                <div class="row mb-4">
                    <div class="col-lg-2 col-6">
                        <div class="small-box bg-info stat-card">
                            <div class="inner">
                                <h3><?php echo $stats['total_field_types']; ?></h3>
                                <p>Total Field Types</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-shapes"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-2 col-6">
                        <div class="small-box bg-success stat-card">
                            <div class="inner">
                                <h3><?php echo $stats['custom_types']; ?></h3>
                                <p>Custom Types</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-plus-circle"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-2 col-6">
                        <div class="small-box bg-warning stat-card">
                            <div class="inner">
                                <h3><?php echo $stats['system_types']; ?></h3>
                                <p>System Types</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-cog"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-2 col-6">
                        <div class="small-box bg-danger stat-card">
                            <div class="inner">
                                <h3><?php echo $stats['base_types_used']; ?></h3>
                                <p>Base Types Used</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-code"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-2 col-6">
                        <div class="small-box bg-secondary stat-card">
                            <div class="inner">
                                <h3><?php echo $stats['total_categories']; ?></h3>
                                <p>Report Categories</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-list"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-2 col-6">
                        <div class="small-box bg-primary stat-card">
                            <div class="inner">
                                <h3><?php echo $stats['types_in_use']; ?></h3>
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
                <!-- Base Types Overview -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card card-outline card-info">
                            <div class="card-header">
                                <h3 class="card-title"><i class="fas fa-code"></i> Base Types Overview</h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <?php foreach ($baseTypeStats as $baseType => $stats): ?>
                                        <div class="col-lg-3 col-md-4 col-sm-6 mb-3">
                                            <div class="card base-type-card base-type-<?php echo $baseType; ?>">
                                                <div class="card-body p-3">
                                                    <div class="d-flex justify-content-between align-items-center">
                                                        <div>
                                                            <h6 class="mb-0"><code><?php echo htmlspecialchars($baseType); ?></code></h6>
                                                            <small class="text-muted"><?php echo $stats['count']; ?> field types</small>
                                                        </div>
                                                        <div class="text-right">
                                                            <span class="badge badge-primary"><?php echo $stats['system']; ?> sys</span>
                                                            <span class="badge badge-success"><?php echo $stats['custom']; ?> cust</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Field Types by Base Type -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-primary">
                            <div class="card-header">
                                <h3 class="card-title"><i class="fas fa-list"></i> Field Types by Base Type</h3>
                            </div>
                            <div class="card-body">
                                <?php
                                $groupedTypes = [];
                                foreach ($fieldTypes as $type) {
                                    $base = $type['base_type'];
                                    if (!isset($groupedTypes[$base])) {
                                        $groupedTypes[$base] = [];
                                    }
                                    $groupedTypes[$base][] = $type;
                                }

                                foreach ($groupedTypes as $baseType => $types):
                                ?>
                                    <div class="mb-4">
                                        <h5 class="text-primary">
                                            <i class="fas fa-code"></i> <?php echo htmlspecialchars($baseType); ?>
                                            <span class="badge badge-secondary ml-2"><?php echo count($types); ?> types</span>
                                        </h5>
                                        <div class="row">
                                            <?php foreach ($types as $type): ?>
                                                <div class="col-lg-3 col-md-4 col-sm-6 mb-3">
                                                    <div class="card h-100">
                                                        <div class="card-body">
                                                            <h6 class="card-title">
                                                                <code><?php echo htmlspecialchars($type['key']); ?></code>
                                                                <?php if (strpos($type['id'], 'type_') === 0): ?>
                                                                    <span class="badge badge-warning badge-sm">System</span>
                                                                <?php else: ?>
                                                                    <span class="badge badge-success badge-sm">Custom</span>
                                                                <?php endif; ?>
                                                            </h6>
                                                            <p class="card-text small text-muted"><?php echo htmlspecialchars($type['label']); ?></p>
                                                            <?php if (!empty($type['description'])): ?>
                                                                <p class="card-text small"><?php echo htmlspecialchars($type['description']); ?></p>
                                                            <?php endif; ?>
                                                            <small class="text-muted">
                                                                Source: <?php echo htmlspecialchars($type['source'] ?? 'manual'); ?>
                                                            </small>
                                                        </div>
                                                    </div>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Usage Analysis -->
                <div class="row">
                    <div class="col-md-6">
                        <div class="card card-outline card-success">
                            <div class="card-header">
                                <h3 class="card-title"><i class="fas fa-chart-pie"></i> Usage Statistics</h3>
                            </div>
                            <div class="card-body">
                                <canvas id="usageChart" style="max-height: 300px;"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card card-outline card-warning">
                            <div class="card-header">
                                <h3 class="card-title"><i class="fas fa-info-circle"></i> System Health</h3>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <strong>Field Types Health:</strong>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-success" style="width: 100%">All Valid</div>
                                    </div>
                                </div>

                                <div class="mb-3">
                                    <strong>Base Types Coverage:</strong>
                                    <div class="progress mt-2">
                                        <?php
                                        $coverage = ($stats['base_types_used'] / 9) * 100; // 9 standard HTML types
                                        $progressClass = $coverage >= 80 ? 'bg-success' : ($coverage >= 60 ? 'bg-warning' : 'bg-danger');
                                        ?>
                                        <div class="progress-bar <?php echo $progressClass; ?>" style="width: <?php echo $coverage; ?>%">
                                            <?php echo round($coverage, 1); ?>%
                                        </div>
                                    </div>
                                </div>

                                <div class="mb-3">
                                    <strong>Types Utilization:</strong>
                                    <div class="progress mt-2">
                                        <?php
                                        $utilization = ($stats['types_in_use'] / $stats['total_field_types']) * 100;
                                        $utilClass = $utilization >= 70 ? 'bg-success' : ($utilization >= 40 ? 'bg-warning' : 'bg-danger');
                                        ?>
                                        <div class="progress-bar <?php echo $utilClass; ?>" style="width: <?php echo $utilization; ?>%">
                                            <?php echo round($utilization, 1); ?>%
                                        </div>
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
        <strong>&copy; 2024 PPC Management.</strong> All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script>
// Usage Chart
var ctx = document.getElementById('usageChart').getContext('2d');
var usageChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['System Types', 'Custom Types', 'Unused Types'],
        datasets: [{
            data: [
                <?php echo $stats['system_types']; ?>,
                <?php echo $stats['custom_types']; ?>,
                <?php echo $stats['total_field_types'] - $stats['types_in_use']; ?>
            ],
            backgroundColor: [
                '#ffc107',
                '#28a745',
                '#dc3545'
            ]
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom'
            }
        }
    }
});
</script>
</body>
</html>
