<?php
// Sidebar include. Assumes session is started and config.php is already required in parent.
// Determines active page based on current script name.
$current = basename($_SERVER['PHP_SELF']);
?>
<aside class="main-sidebar sidebar-dark-primary elevation-4">
    <a href="dashboard.php" class="brand-link">
        <span class="brand-text font-weight-light">IPPC Dashboard</span>
    </a>
    <div class="sidebar">
        <div class="user-panel mt-3 pb-3 mb-3 d-flex">
            <div class="image">
                <i class="fas fa-user-circle fa-2x text-white"></i>
            </div>
            <div class="info">
                <a href="#" class="d-block"><?php echo htmlspecialchars($_SESSION['name'] ?? ''); ?></a>
                <small class="text-muted"><?php echo isset($_SESSION['role']) ? htmlspecialchars(ucfirst($_SESSION['role'])) : ''; ?></small>
            </div>
        </div>
        <nav class="mt-2">
            <ul class="nav nav-pills nav-sidebar flex-column" data-widget="treeview" role="menu">
                <li class="nav-item">
                    <a href="dashboard.php" class="nav-link <?php echo $current === 'dashboard.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-tachometer-alt"></i>
                        <p>Dashboard</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="reporting.php" class="nav-link <?php echo $current === 'reporting.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-clipboard-list"></i>
                        <p>Submit Report</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="reports.php" class="nav-link <?php echo $current === 'reports.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-table"></i>
                        <p>Reports</p>
                    </a>
                </li>
                <?php if (isset($_SESSION['role']) && $_SESSION['role'] === ROLE_ADMIN): ?>
                <li class="nav-item">
                    <a href="user_management.php" class="nav-link <?php echo $current === 'user_management.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-users"></i>
                        <p>User Management</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="field_types.php" class="nav-link <?php echo $current === 'field_types.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-shapes"></i>
                        <p>Field Types</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="base_types_manager.php" class="nav-link <?php echo $current === 'base_types_manager.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-cogs"></i>
                        <p>Base Types Manager</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="report_categories.php" class="nav-link <?php echo $current === 'report_categories.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-list"></i>
                        <p>Report Categories</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="reports_creator.php" class="nav-link <?php echo $current === 'reports_creator.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-file-circle-plus"></i>
                        <p>Reports Creator</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="backup_manager.php" class="nav-link <?php echo $current === 'backup_manager.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-shield-alt"></i>
                        <p>Backup Manager</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="system_monitor.php" class="nav-link <?php echo $current === 'system_monitor.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-chart-line"></i>
                        <p>System Monitor</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="analytics.php" class="nav-link <?php echo $current === 'analytics.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-trophy"></i>
                        <p>Analytics</p>
                    </a>
                </li>
                <?php endif; ?>
                <li class="nav-item">
                    <a href="profile.php" class="nav-link <?php echo $current === 'profile.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-user"></i>
                        <p>Profile</p>
                    </a>
                </li>
            </ul>
        </nav>
    </div>
</aside>
