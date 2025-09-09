<?php
require_once 'config.php';

session_start();
requireAdmin();

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

// System information
$systemInfo = [
    'php_version' => PHP_VERSION,
    'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
    'server_name' => $_SERVER['SERVER_NAME'] ?? 'Unknown',
    'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
    'max_upload_size' => ini_get('upload_max_filesize'),
    'max_post_size' => ini_get('post_max_size'),
    'memory_limit' => ini_get('memory_limit'),
    'timezone' => date_default_timezone_get()
];

// File system information
$fileInfo = [
    'total_space' => disk_total_space('/'),
    'free_space' => disk_free_space('/'),
    'data_files' => [
        'users.json' => file_exists(USERS_FILE) ? filesize(USERS_FILE) : 0,
        'zones.json' => file_exists(ZONES_FILE) ? filesize(ZONES_FILE) : 0,
        'reports.json' => file_exists(REPORTS_FILE) ? filesize(REPORTS_FILE) : 0,
        'report_categories.json' => file_exists(REPORT_CATEGORIES_FILE) ? filesize(REPORT_CATEGORIES_FILE) : 0,
        'field_types.json' => file_exists(FIELD_TYPES_FILE) ? filesize(FIELD_TYPES_FILE) : 0
    ]
];

// Database statistics
$dbStats = [
    'users_count' => count(getUsers()),
    'categories_count' => count(getReportCategories()),
    'reports_count' => count(getReports()),
    'zones_count' => count(getZones()),
    'field_types_count' => count(getFieldTypes())
];

// Log analysis
$logStats = [];
$errorLog = ERROR_LOG_FILE;
$debugLog = __DIR__ . '/debug.log';

if (file_exists($errorLog)) {
    $errorContent = file_get_contents($errorLog);
    $logStats['error_lines'] = substr_count($errorContent, "\n");
    $logStats['error_size'] = filesize($errorLog);

    // Count error types
    $logStats['error_types'] = [
        'php_error' => substr_count($errorContent, '"level":"php_error"'),
        'write_error' => substr_count($errorContent, '"level":"write_error"'),
        'validation_error' => substr_count($errorContent, '"level":"validation_error"'),
        'security_warning' => substr_count($errorContent, '"level":"security_warning"')
    ];
}

if (file_exists($debugLog)) {
    $debugContent = file_get_contents($debugLog);
    $logStats['debug_lines'] = substr_count($debugContent, "\n");
    $logStats['debug_size'] = filesize($debugLog);
}

// Recent activity from logs
$recentActivity = [];
if (file_exists($errorLog)) {
    $lines = file($errorLog);
    $recentLines = array_slice($lines, -10); // Last 10 entries
    foreach ($recentLines as $line) {
        $entry = json_decode($line, true);
        if ($entry) {
            $recentActivity[] = $entry;
        }
    }
}
$recentActivity = array_reverse($recentActivity);

function formatBytes($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | System Monitor</title>
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
                        <h1 class="m-0">System Monitor</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">System Monitor</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <?php if ($message): ?>
                    <div class="alert alert-success alert-dismissible">
                        <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                        <i class="icon fas fa-check"></i> <?php echo htmlspecialchars($message); ?>
                    </div>
                <?php endif; ?>

                <?php if ($error): ?>
                    <div class="alert alert-danger alert-dismissible">
                        <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                        <i class="icon fas fa-ban"></i> <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <!-- System Overview -->
                <div class="row">
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-info">
                            <div class="inner">
                                <h3><?php echo $dbStats['users_count']; ?></h3>
                                <p>Total Users</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-users"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-success">
                            <div class="inner">
                                <h3><?php echo $dbStats['reports_count']; ?></h3>
                                <p>Total Reports</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-file-alt"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-warning">
                            <div class="inner">
                                <h3><?php echo $dbStats['categories_count']; ?></h3>
                                <p>Categories</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-list"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-danger">
                            <div class="inner">
                                <h3><?php echo $logStats['error_lines'] ?? 0; ?></h3>
                                <p>Log Entries</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-exclamation-triangle"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- System Information -->
                <div class="row">
                    <div class="col-md-6">
                        <div class="card card-outline card-primary">
                            <div class="card-header">
                                <h3 class="card-title">System Information</h3>
                            </div>
                            <div class="card-body">
                                <dl class="row">
                                    <dt class="col-sm-5">PHP Version:</dt>
                                    <dd class="col-sm-7"><?php echo htmlspecialchars($systemInfo['php_version']); ?></dd>

                                    <dt class="col-sm-5">Server:</dt>
                                    <dd class="col-sm-7"><?php echo htmlspecialchars($systemInfo['server_software']); ?></dd>

                                    <dt class="col-sm-5">Memory Limit:</dt>
                                    <dd class="col-sm-7"><?php echo htmlspecialchars($systemInfo['memory_limit']); ?></dd>

                                    <dt class="col-sm-5">Upload Max:</dt>
                                    <dd class="col-sm-7"><?php echo htmlspecialchars($systemInfo['max_upload_size']); ?></dd>

                                    <dt class="col-sm-5">Timezone:</dt>
                                    <dd class="col-sm-7"><?php echo htmlspecialchars($systemInfo['timezone']); ?></dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card card-outline card-success">
                            <div class="card-header">
                                <h3 class="card-title">Disk Usage</h3>
                            </div>
                            <div class="card-body">
                                <div class="progress mb-3">
                                    <?php
                                    $usedPercent = (($fileInfo['total_space'] - $fileInfo['free_space']) / $fileInfo['total_space']) * 100;
                                    $progressClass = $usedPercent > 90 ? 'bg-danger' : ($usedPercent > 70 ? 'bg-warning' : 'bg-success');
                                    ?>
                                    <div class="progress-bar <?php echo $progressClass; ?>" role="progressbar"
                                         style="width: <?php echo $usedPercent; ?>%">
                                        <?php echo round($usedPercent, 1); ?>%
                                    </div>
                                </div>
                                <dl class="row">
                                    <dt class="col-sm-5">Total Space:</dt>
                                    <dd class="col-sm-7"><?php echo formatBytes($fileInfo['total_space']); ?></dd>

                                    <dt class="col-sm-5">Free Space:</dt>
                                    <dd class="col-sm-7"><?php echo formatBytes($fileInfo['free_space']); ?></dd>

                                    <dt class="col-sm-5">Used Space:</dt>
                                    <dd class="col-sm-7"><?php echo formatBytes($fileInfo['total_space'] - $fileInfo['free_space']); ?></dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Data Files -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-info">
                            <div class="card-header">
                                <h3 class="card-title">Data Files</h3>
                            </div>
                            <div class="card-body table-responsive p-0">
                                <table class="table table-hover text-nowrap">
                                    <thead>
                                        <tr>
                                            <th>File</th>
                                            <th>Size</th>
                                            <th>Records</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>users.json</td>
                                            <td><?php echo formatBytes($fileInfo['data_files']['users.json']); ?></td>
                                            <td><?php echo $dbStats['users_count']; ?> users</td>
                                            <td><span class="badge badge-success">OK</span></td>
                                        </tr>
                                        <tr>
                                            <td>zones.json</td>
                                            <td><?php echo formatBytes($fileInfo['data_files']['zones.json']); ?></td>
                                            <td><?php echo $dbStats['zones_count']; ?> zones</td>
                                            <td><span class="badge badge-success">OK</span></td>
                                        </tr>
                                        <tr>
                                            <td>reports.json</td>
                                            <td><?php echo formatBytes($fileInfo['data_files']['reports.json']); ?></td>
                                            <td><?php echo $dbStats['reports_count']; ?> reports</td>
                                            <td><span class="badge badge-success">OK</span></td>
                                        </tr>
                                        <tr>
                                            <td>report_categories.json</td>
                                            <td><?php echo formatBytes($fileInfo['data_files']['report_categories.json']); ?></td>
                                            <td><?php echo $dbStats['categories_count']; ?> categories</td>
                                            <td><span class="badge badge-success">OK</span></td>
                                        </tr>
                                        <tr>
                                            <td>field_types.json</td>
                                            <td><?php echo formatBytes($fileInfo['data_files']['field_types.json']); ?></td>
                                            <td><?php echo $dbStats['field_types_count']; ?> types</td>
                                            <td><span class="badge badge-success">OK</span></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Log Statistics -->
                <div class="row">
                    <div class="col-md-6">
                        <div class="card card-outline card-warning">
                            <div class="card-header">
                                <h3 class="card-title">Error Log Statistics</h3>
                            </div>
                            <div class="card-body">
                                <div class="info-box">
                                    <span class="info-box-icon bg-warning"><i class="fas fa-exclamation-triangle"></i></span>
                                    <div class="info-box-content">
                                        <span class="info-box-text">Total Entries</span>
                                        <span class="info-box-number"><?php echo $logStats['error_lines'] ?? 0; ?></span>
                                        <div class="progress">
                                            <div class="progress-bar bg-warning" style="width: 100%"></div>
                                        </div>
                                        <span class="progress-description">
                                            <?php echo formatBytes($logStats['error_size'] ?? 0); ?> total size
                                        </span>
                                    </div>
                                </div>
                                <?php if (isset($logStats['error_types'])): ?>
                                    <div class="mt-3">
                                        <strong>Error Types:</strong>
                                        <ul class="list-unstyled">
                                            <?php foreach ($logStats['error_types'] as $type => $count): ?>
                                                <?php if ($count > 0): ?>
                                                    <li><span class="badge badge-secondary"><?php echo $count; ?></span> <?php echo htmlspecialchars($type); ?></li>
                                                <?php endif; ?>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card card-outline card-secondary">
                            <div class="card-header">
                                <h3 class="card-title">Debug Log Statistics</h3>
                            </div>
                            <div class="card-body">
                                <div class="info-box">
                                    <span class="info-box-icon bg-secondary"><i class="fas fa-bug"></i></span>
                                    <div class="info-box-content">
                                        <span class="info-box-text">Total Entries</span>
                                        <span class="info-box-number"><?php echo $logStats['debug_lines'] ?? 0; ?></span>
                                        <div class="progress">
                                            <div class="progress-bar bg-secondary" style="width: 100%"></div>
                                        </div>
                                        <span class="progress-description">
                                            <?php echo formatBytes($logStats['debug_size'] ?? 0); ?> total size
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Activity -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-danger">
                            <div class="card-header">
                                <h3 class="card-title">Recent Activity (Last 10 Events)</h3>
                            </div>
                            <div class="card-body table-responsive p-0">
                                <?php if (empty($recentActivity)): ?>
                                    <div class="text-center py-4">
                                        <i class="fas fa-info-circle fa-3x text-muted mb-3"></i>
                                        <p class="text-muted">No recent activity found.</p>
                                    </div>
                                <?php else: ?>
                                    <table class="table table-hover text-nowrap">
                                        <thead>
                                            <tr>
                                                <th>Time</th>
                                                <th>Level</th>
                                                <th>Message</th>
                                                <th>User</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($recentActivity as $activity): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars(date('M j H:i:s', strtotime($activity['ts']))); ?></td>
                                                    <td>
                                                        <?php
                                                        $levelClass = match($activity['level'] ?? '') {
                                                            'php_error' => 'badge-danger',
                                                            'write_error' => 'badge-warning',
                                                            'validation_error' => 'badge-info',
                                                            'security_warning' => 'badge-dark',
                                                            default => 'badge-secondary'
                                                        };
                                                        ?>
                                                        <span class="badge <?php echo $levelClass; ?>">
                                                            <?php echo htmlspecialchars($activity['level'] ?? ''); ?>
                                                        </span>
                                                    </td>
                                                    <td><?php echo htmlspecialchars($activity['msg'] ?? ''); ?></td>
                                                    <td><?php echo htmlspecialchars($activity['user'] ?? 'system'); ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </div>

    <footer class="main-footer">
        <strong>Copyright &copy; 2024 <a href="#">PPC Management</a>.</strong>
        All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
</body>
</html>
