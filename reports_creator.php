<?php
require_once 'config.php';

session_start();
requireAdmin();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | Reports Creator</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <style>
        .placeholder-box { border: 2px dashed #ced4da; padding: 40px; text-align: center; color: #6c757d; background: #f8f9fa; }
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
                        <h1 class="m-0">Reports Creator</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Reports Creator</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <!-- Quick Actions -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card card-primary">
                            <div class="card-header">
                                <h3 class="card-title">Quick Actions</h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4">
                                        <a href="report_categories.php" class="btn btn-primary btn-block">
                                            <i class="fas fa-list"></i> Manage Categories
                                        </a>
                                    </div>
                                    <div class="col-md-4">
                                        <a href="field_types.php" class="btn btn-success btn-block">
                                            <i class="fas fa-shapes"></i> Manage Field Types
                                        </a>
                                    </div>
                                    <div class="col-md-4">
                                        <a href="reports.php" class="btn btn-info btn-block">
                                            <i class="fas fa-table"></i> View All Reports
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- System Status -->
                <div class="row">
                    <div class="col-md-6">
                        <div class="card card-outline card-info">
                            <div class="card-header">
                                <h3 class="card-title">Report Categories</h3>
                            </div>
                            <div class="card-body">
                                <?php
                                $categories = getReportCategories();
                                $activeCategories = array_filter($categories, function($cat) {
                                    return ($cat['status'] ?? 'active') === 'active';
                                });
                                ?>
                                <div class="info-box">
                                    <span class="info-box-icon bg-info"><i class="fas fa-list"></i></span>
                                    <div class="info-box-content">
                                        <span class="info-box-text">Total Categories</span>
                                        <span class="info-box-number"><?php echo count($categories); ?></span>
                                        <div class="progress">
                                            <div class="progress-bar bg-info" style="width: <?php echo count($categories) > 0 ? '100%' : '0%'; ?>"></div>
                                        </div>
                                        <span class="progress-description">
                                            <?php echo count($activeCategories); ?> active
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card card-outline card-success">
                            <div class="card-header">
                                <h3 class="card-title">Field Types</h3>
                            </div>
                            <div class="card-body">
                                <?php
                                $fieldTypes = getFieldTypes();
                                ?>
                                <div class="info-box">
                                    <span class="info-box-icon bg-success"><i class="fas fa-shapes"></i></span>
                                    <div class="info-box-content">
                                        <span class="info-box-text">Available Types</span>
                                        <span class="info-box-number"><?php echo count($fieldTypes); ?></span>
                                        <div class="progress">
                                            <div class="progress-bar bg-success" style="width: <?php echo count($fieldTypes) > 0 ? '100%' : '0%'; ?>"></div>
                                        </div>
                                        <span class="progress-description">
                                            Ready for use
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
                        <div class="card card-outline card-warning">
                            <div class="card-header">
                                <h3 class="card-title">Getting Started</h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4">
                                        <div class="callout callout-info">
                                            <h5>1. Create Categories</h5>
                                            <p>Define report categories to organize your data collection forms.</p>
                                            <a href="report_categories.php" class="btn btn-sm btn-info">Create Categories</a>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="callout callout-success">
                                            <h5>2. Configure Fields</h5>
                                            <p>Add custom field types and configure dynamic options.</p>
                                            <a href="field_types.php" class="btn btn-sm btn-success">Manage Fields</a>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="callout callout-primary">
                                            <h5>3. Start Reporting</h5>
                                            <p>Begin collecting data with your configured forms.</p>
                                            <a href="reporting.php" class="btn btn-sm btn-primary">Submit Reports</a>
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
</body>
</html>

