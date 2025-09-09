<?php
require_once 'config.php';

session_start();
requireAdmin();

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'create_backup') {
        $description = sanitizeInput($_POST['description'] ?? '');
        $result = createBackup($description);

        if ($result['success']) {
            $_SESSION['flash_message'] = 'Backup created successfully: ' . $result['name'];
        } else {
            $_SESSION['flash_error'] = 'Failed to create backup';
        }
        header('Location: backup_manager.php');
        exit;
    } elseif ($action === 'restore_backup') {
        $backupName = sanitizeInput($_POST['backup_name'] ?? '');
        $result = restoreBackup($backupName);

        if ($result['success']) {
            $_SESSION['flash_message'] = $result['message'];
        } else {
            $_SESSION['flash_error'] = $result['message'];
        }
        header('Location: backup_manager.php');
        exit;
    }
}

$backups = listBackups();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Backup Manager</title>
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
                        <h1 class="m-0">Backup Manager</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Backup Manager</li>
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

                <!-- Create Backup -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card card-primary">
                            <div class="card-header">
                                <h3 class="card-title">Create New Backup</h3>
                            </div>
                            <form method="POST">
                                <div class="card-body">
                                    <div class="form-group">
                                        <label for="description">Description (Optional)</label>
                                        <input type="text" class="form-control" id="description" name="description"
                                               placeholder="e.g., Before major changes, Weekly backup">
                                    </div>
                                </div>
                                <div class="card-footer">
                                    <button type="submit" name="action" value="create_backup" class="btn btn-primary">
                                        <i class="fas fa-save"></i> Create Backup
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Existing Backups -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-info">
                            <div class="card-header">
                                <h3 class="card-title">Available Backups</h3>
                            </div>
                            <div class="card-body table-responsive p-0">
                                <?php if (empty($backups)): ?>
                                    <div class="text-center py-4">
                                        <i class="fas fa-database fa-3x text-muted mb-3"></i>
                                        <p class="text-muted">No backups found.</p>
                                        <p class="text-muted">Create your first backup using the form above.</p>
                                    </div>
                                <?php else: ?>
                                    <table class="table table-hover text-nowrap">
                                        <thead>
                                            <tr>
                                                <th>Backup Name</th>
                                                <th>Description</th>
                                                <th>Created</th>
                                                <th>Files</th>
                                                <th>Created By</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($backups as $backup): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($backup['name']); ?></td>
                                                    <td><?php echo htmlspecialchars($backup['description'] ?? ''); ?></td>
                                                    <td><?php echo htmlspecialchars(date('M j, Y H:i', strtotime($backup['timestamp']))); ?></td>
                                                    <td>
                                                        <span class="badge badge-info">
                                                            <?php echo count($backup['files'] ?? []); ?> files
                                                        </span>
                                                    </td>
                                                    <td><?php echo htmlspecialchars($backup['created_by'] ?? 'system'); ?></td>
                                                    <td>
                                                        <form method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to restore this backup? This will overwrite current data.');">
                                                            <input type="hidden" name="backup_name" value="<?php echo htmlspecialchars($backup['name']); ?>">
                                                            <button type="submit" name="action" value="restore_backup" class="btn btn-warning btn-sm">
                                                                <i class="fas fa-undo"></i> Restore
                                                            </button>
                                                        </form>
                                                        <a href="backup_download.php?backup=<?php echo urlencode($backup['name']); ?>" class="btn btn-info btn-sm">
                                                            <i class="fas fa-download"></i> Download
                                                        </a>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Backup Info -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-secondary">
                            <div class="card-header">
                                <h3 class="card-title">Backup Information</h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h5>What gets backed up?</h5>
                                        <ul>
                                            <li>User accounts and profiles</li>
                                            <li>Zone and region configurations</li>
                                            <li>Report categories and settings</li>
                                            <li>Field type definitions</li>
                                            <li>All submitted reports</li>
                                        </ul>
                                    </div>
                                    <div class="col-md-6">
                                        <h5>Best Practices</h5>
                                        <ul>
                                            <li>Create backups before major changes</li>
                                            <li>Regular automated backups (weekly)</li>
                                            <li>Test restore functionality periodically</li>
                                            <li>Store backups in secure locations</li>
                                        </ul>
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
        <strong>Copyright &copy; 2024 <a href="#">IPPC Dashboard</a>.</strong>
        All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
</body>
</html>
