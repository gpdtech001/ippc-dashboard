<?php
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);
$zones = getZones();
$users = getUsers();

// Filter data based on role
if ($_SESSION['role'] === ROLE_RZM) {
    // RZM can only see their zone data
    $userRegion = $user['region'];
    $userZone = $user['zone'];

    // Filter zones to show only the user's zone
    $filteredZones = [];
    if (isset($zones[$userRegion]) && isset($zones[$userRegion][$userZone])) {
        $filteredZones[$userRegion] = [$userZone => $zones[$userRegion][$userZone]];
    }

    // Filter users to show only users in the same zone (for RZM)
    $filteredUsers = array_filter($users, function($u) use ($userRegion, $userZone) {
        return isset($u['region']) && isset($u['zone']) &&
               $u['region'] === $userRegion && $u['zone'] === $userZone;
    });
} else {
    // Admin can see all
    $filteredZones = $zones;
    $filteredUsers = $users;
}

// Get statistics
$totalUsers = count($filteredUsers);
$totalZones = 0;
foreach ($filteredZones as $region => $regionZones) {
    $totalZones += count(array_filter($regionZones, function($zone) {
        return is_array($zone) && isset($zone['groups']);
    }));
}
$totalGroups = 0;
foreach ($filteredZones as $region => $regionZones) {
    foreach ($regionZones as $zoneKey => $zone) {
        if (is_array($zone) && isset($zone['groups'])) {
            $totalGroups += count($zone['groups']);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Zone Details</title>

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

    <!-- Main Sidebar Container -->
    <aside class="main-sidebar sidebar-dark-primary elevation-4">
        <!-- Brand Logo -->
        <a href="dashboard.php" class="brand-link">
            <span class="brand-text font-weight-light">IPPC Dashboard</span>
        </a>

        <!-- Sidebar -->
        <div class="sidebar">
            <!-- Sidebar user panel -->
            <div class="user-panel mt-3 pb-3 mb-3 d-flex">
                <div class="image">
                    <i class="fas fa-user-circle fa-2x text-white"></i>
                </div>
                <div class="info">
                    <a href="#" class="d-block"><?php echo htmlspecialchars($user['name']); ?></a>
                    <small class="text-muted"><?php echo htmlspecialchars(ucfirst($user['role'])); ?></small>
                </div>
            </div>

            <!-- Sidebar Menu -->
            <nav class="mt-2">
                <ul class="nav nav-pills nav-sidebar flex-column" data-widget="treeview" role="menu">
                    <li class="nav-item">
                        <a href="dashboard.php" class="nav-link">
                            <i class="nav-icon fas fa-tachometer-alt"></i>
                            <p>Dashboard</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="zone_details.php" class="nav-link active">
                            <i class="nav-icon fas fa-map"></i>
                            <p>Zone Details</p>
                        </a>
                    </li>
                    <?php if ($_SESSION['role'] === ROLE_ADMIN): ?>
                    <li class="nav-item">
                        <a href="user_management.php" class="nav-link">
                            <i class="nav-icon fas fa-users"></i>
                            <p>User Management</p>
                        </a>
                    </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a href="profile.php" class="nav-link">
                            <i class="nav-icon fas fa-user"></i>
                            <p>Profile</p>
                        </a>
                    </li>
                </ul>
            </nav>
            <!-- /.sidebar-menu -->
        </div>
        <!-- /.sidebar -->
    </aside>

    <!-- Content Wrapper. Contains page content -->
    <div class="content-wrapper">
        <!-- Content Header (Page header) -->
        <div class="content-header">
            <div class="container-fluid">
                <div class="row mb-2">
                    <div class="col-sm-6">
                        <h1 class="m-0">Zone Details</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Zone Details</li>
                        </ol>
                    </div>
                </div>
            </div><!-- /.container-fluid -->
        </div>
        <!-- /.content-header -->

        <!-- Main content -->
        <section class="content">
            <div class="container-fluid">
                <!-- Info boxes -->
                <div class="row">
                    <div class="col-12 col-sm-6 col-md-3">
                        <div class="info-box">
                            <span class="info-box-icon bg-info elevation-1"><i class="fas fa-users"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Total Users</span>
                                <span class="info-box-number"><?php echo $totalUsers; ?></span>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-sm-6 col-md-3">
                        <div class="info-box mb-3">
                            <span class="info-box-icon bg-danger elevation-1"><i class="fas fa-map"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Total Zones</span>
                                <span class="info-box-number"><?php echo $totalZones; ?></span>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-sm-6 col-md-3">
                        <div class="info-box mb-3">
                            <span class="info-box-icon bg-success elevation-1"><i class="fas fa-layer-group"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Total Groups</span>
                                <span class="info-box-number"><?php echo $totalGroups; ?></span>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-sm-6 col-md-3">
                        <div class="info-box mb-3">
                            <span class="info-box-icon bg-warning elevation-1"><i class="fas fa-user-tag"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Your Role</span>
                                <span class="info-box-number"><?php echo ucfirst($user['role']); ?></span>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- /.row -->

                <div class="row">
                    <!-- Zone Information -->
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">Zone Information</h3>
                            </div>
                            <div class="card-body">
                                <?php if ($_SESSION['role'] === ROLE_RZM): ?>
                                    <p><strong>Region:</strong> <?php echo htmlspecialchars($user['region']); ?></p>
                                    <p><strong>Zone:</strong> <?php echo htmlspecialchars($user['zone']); ?></p>
                                    <?php
                                    $zoneInfo = $zones[$user['region']][$user['zone']] ?? null;
                                    if ($zoneInfo && isset($zoneInfo['groups'])) {
                                        echo '<p><strong>Groups in Zone:</strong> ' . count($zoneInfo['groups']) . '</p>';
                                    }
                                    ?>
                                <?php else: ?>
                                    <p>You have access to all regions and zones as an administrator.</p>
                                    <p><strong>Total Regions:</strong> <?php echo count($zones); ?></p>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Users -->
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">Recent Users</h3>
                            </div>
                            <div class="card-body p-0">
                                <ul class="list-group list-group-flush">
                                    <?php
                                    $recentUsers = array_slice(array_reverse($filteredUsers), 0, 5);
                                    foreach ($recentUsers as $recentUser):
                                    ?>
                                    <li class="list-group-item">
                                        <div class="d-flex justify-content-between">
                                            <div>
                                                <strong><?php echo htmlspecialchars($recentUser['name']); ?></strong>
                                                <br><small class="text-muted"><?php echo htmlspecialchars($recentUser['email']); ?></small>
                                            </div>
                                            <small><?php echo htmlspecialchars(ucfirst($recentUser['role'])); ?></small>
                                        </div>
                                    </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- /.row -->

                <!-- Zone Details Table -->
                <div class="row">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">Zone Details</h3>
                            </div>
                            <div class="card-body table-responsive p-0">
                                <table class="table table-hover text-nowrap">
                                    <thead>
                                        <tr>
                                            <th>Region</th>
                                            <th>Zone</th>
                                            <th>Groups Count</th>
                                            <?php if ($_SESSION['role'] === ROLE_ADMIN): ?>
                                            <th>Users in Zone</th>
                                            <?php endif; ?>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($filteredZones as $regionName => $regionZones): ?>
                                            <?php foreach ($regionZones as $zoneKey => $zone): ?>
                                                <?php if (is_array($zone) && isset($zone['groups'])): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($regionName); ?></td>
                                                    <td><?php echo htmlspecialchars($zone['name'] ?? $zoneKey); ?></td>
                                                    <td><?php echo count($zone['groups']); ?></td>
                                                    <?php if ($_SESSION['role'] === ROLE_ADMIN): ?>
                                                    <td>
                                                        <?php
                                                        $zoneUsers = array_filter($users, function($u) use ($regionName, $zoneKey) {
                                                            return $u['region'] === $regionName && $u['zone'] === $zoneKey;
                                                        });
                                                        echo count($zoneUsers);
                                                        ?>
                                                    </td>
                                                    <?php endif; ?>
                                                </tr>
                                                <?php endif; ?>
                                            <?php endforeach; ?>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- /.row -->
            </div><!-- /.container-fluid -->
        </section>
        <!-- /.content -->
    </div>
    <!-- /.content-wrapper -->

    <footer class="main-footer">
        <strong>Copyright &copy; 2024 <a href="#">IPPC Dashboard</a>.</strong>
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
</body>
</html>

