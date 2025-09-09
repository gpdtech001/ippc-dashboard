<?php
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);
$isAdmin = ($_SESSION['role'] === ROLE_ADMIN);
// Latest report: admin -> any; RZM -> own
$latestReport = null;
if (function_exists('getReports')) {
    $allReports = getReports();
    // Sort by submitted_at desc
    usort($allReports, function($a, $b){ return strcmp($b['submitted_at'] ?? '', $a['submitted_at'] ?? ''); });
    if ($isAdmin) {
        $latestReport = $allReports[0] ?? null;
    } else {
        foreach ($allReports as $r) {
            if (($r['submitted_by'] ?? '') === ($user['id'] ?? '')) { $latestReport = $r; break; }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | Dashboard</title>

    <!-- Google Font: Source Sans Pro -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <!-- Theme style -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
</head>
<body class="hold-transition sidebar-mini layout-fixed">
<div class="wrapper">

    <!-- Navbar -->
    <nav class="main-header navbar navbar-expand navbar-white navbar-light">
        <!-- Left navbar links -->
        <ul class="navbar-nav">
            <li class="nav-item">
                <a class="nav-link" data-widget="pushmenu" href="#" role="button"><i class="fas fa-bars"></i></a>
            </li>
            <li class="nav-item d-none d-sm-inline-block">
                <a href="dashboard.php" class="nav-link">Home</a>
            </li>
        </ul>

        <!-- Right navbar links -->
        <ul class="navbar-nav ml-auto">
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
    <!-- /.navbar -->

    <?php include __DIR__ . '/includes/sidebar.php'; ?>

    <!-- Content Wrapper. Contains page content -->
    <div class="content-wrapper">
        <!-- Content Header (Page header) -->
        <div class="content-header">
            <div class="container-fluid">
                <div class="row mb-2">
                    <div class="col-sm-6">
                        <h1 class="m-0">Dashboard</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="#">Home</a></li>
                            <li class="breadcrumb-item active">Dashboard</li>
                        </ol>
                    </div>
                </div>
            </div><!-- /.container-fluid -->
        </div>
        <!-- /.content-header -->

        <!-- Main content -->
        <section class="content">
            <div class="container-fluid">
                <!-- Welcome Section -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-primary card-outline">
                            <div class="card-body">
                                <div class="text-center">
                                    <h1 class="display-4">Welcome to PPC Management System</h1>
                                    <p class="lead">Hello <strong><?php echo htmlspecialchars($user['name']); ?></strong>!</p>
                                    <p class="mb-4">You are logged in as <strong><?php echo htmlspecialchars(ucfirst($user['role'])); ?></strong></p>

                                    <div class="row justify-content-center">
                                        <div class="col-md-8">
                                            <div class="alert alert-info">
                                                <h5><i class="icon fas fa-info"></i> Getting Started</h5>
                                                <p>Use the navigation menu to access different features of the system. As a <?php echo htmlspecialchars(ucfirst($user['role'])); ?>, you have access to:</p>
                                                <ul class="list-unstyled">
                                                    <li><i class="fas fa-check text-success"></i> View zone details and statistics</li>
                                                    <?php if ($_SESSION['role'] === ROLE_ADMIN): ?>
                                                    <li><i class="fas fa-check text-success"></i> Manage all users and their permissions</li>
                                                    <li><i class="fas fa-check text-success"></i> Approve or reject user registrations</li>
                                                    <?php else: ?>
                                                    <li><i class="fas fa-check text-success"></i> Access your assigned zone information</li>
                                                    <?php endif; ?>
                                                    <li><i class="fas fa-check text-success"></i> Update your profile information</li>
                                                </ul>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="row justify-content-center mt-4">
                                        <div class="col-md-6">
                                            <div class="card">
                                                <div class="card-body">
                                                    <h5 class="card-title">Quick Actions</h5>
                                                    <div class="d-grid gap-2">
                                                        <a href="zone_details.php" class="btn btn-primary btn-lg">
                                                            <i class="fas fa-map"></i> View Zone Details
                                                        </a>
                                                        <a href="profile.php" class="btn btn-secondary btn-lg">
                                                            <i class="fas fa-user"></i> Update Profile
                                                        </a>
                                                        <?php if ($_SESSION['role'] === ROLE_ADMIN): ?>
                                                        <a href="user_management.php" class="btn btn-success btn-lg">
                                                            <i class="fas fa-users"></i> Manage Users
                                                        </a>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Quick Stats Row (minimal) -->
                <div class="row">
                    <div class="col-md-4">
                        <div class="small-box bg-info">
                            <div class="inner">
                                <h3><?php echo htmlspecialchars(ucfirst($user['role'])); ?></h3>
                                <p>Your Role</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-user-tag"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="small-box bg-success">
                            <div class="inner">
                                <h3><?php echo htmlspecialchars($user['name']); ?></h3>
                                <p>Welcome Back!</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-smile"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="small-box bg-warning">
                            <div class="inner">
                                <h3><?php echo date('M j'); ?></h3>
                                <p><?php echo date('Y'); ?></p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-calendar"></i>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Latest Report Card -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-info">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h3 class="card-title">Latest Report Submitted</h3>
                                <div>
                                    <a href="reporting.php" class="btn btn-sm btn-primary"><i class="fas fa-plus"></i> Submit Report</a>
                                    <a href="reports.php" class="btn btn-sm btn-secondary"><i class="fas fa-table"></i> View All Reports</a>
                                </div>
                            </div>
                            <div class="card-body">
                                <?php if (!$latestReport): ?>
                                    <div class="text-center py-4">
                                        <i class="fas fa-file-alt fa-3x text-muted mb-3"></i>
                                        <p class="text-muted">No reports submitted yet.</p>
                                        <a href="reporting.php" class="btn btn-primary">
                                            <i class="fas fa-plus"></i> Submit Your First Report
                                        </a>
                                    </div>
                                <?php else: ?>
                                    <div class="row">
                                        <div class="col-md-8">
                                            <div class="mb-2">
                                                <strong>Category:</strong> 
                                                <span class="badge badge-info"><?php echo htmlspecialchars($latestReport['category_name'] ?? ''); ?></span>
                                            </div>
                                            <div class="mb-2">
                                                <strong>Submitted At:</strong> 
                                                <?php echo htmlspecialchars($latestReport['submitted_at'] ?? ''); ?>
                                            </div>
                                            <?php if ($isAdmin): ?>
                                                <div class="mb-2">
                                                    <strong>Submitted By:</strong> 
                                                    <?php echo htmlspecialchars(($latestReport['submitted_by_name'] ?? '') . ' (' . ucfirst($latestReport['role'] ?? '') . ')'); ?>
                                                </div>
                                            <?php endif; ?>
                                            <div class="mb-2">
                                                <strong>Report ID:</strong> 
                                                <code><?php echo htmlspecialchars($latestReport['id'] ?? ''); ?></code>
                                            </div>
                                        </div>
                                        <div class="col-md-4 text-right">
                                            <div class="btn-group-vertical">
                                                <a href="reports.php" class="btn btn-success mb-2">
                                                    <i class="fas fa-eye"></i> View Report
                                                </a>
                                                <?php 
                                                $canEdit = $isAdmin || (($latestReport['submitted_by'] ?? '') === ($_SESSION['user_id'] ?? ''));
                                                if ($canEdit): 
                                                ?>
                                                <a href="report_edit.php?id=<?php echo urlencode($latestReport['id']); ?>" class="btn btn-warning">
                                                    <i class="fas fa-edit"></i> Edit Report
                                                </a>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div><!-- /.container-fluid -->
        </section>
        <!-- /.content -->
    </div>
    <!-- /.content-wrapper -->

    <footer class="main-footer">
        <strong>Copyright &copy; 2024 <a href="#">PPC Management</a>.</strong>
        All rights reserved.
    </footer>
</div>
<!-- ./wrapper -->

<!-- jQuery -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<!-- Bootstrap 4 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<!-- AdminLTE App -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<!-- SweetAlert2 -->
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</body>
</html>
