<?php
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);
$zones = getZones();

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = sanitizeInput($_POST['name'] ?? '');
    $email = sanitizeInput($_POST['email'] ?? '');
    $phone = sanitizeInput($_POST['phone'] ?? '');
    $kingschat_username = sanitizeInput($_POST['kingschat_username'] ?? '');
    $current_password = $_POST['current_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Validate email uniqueness (if changed)
    if ($email !== $user['email']) {
        $existingUser = getUserByEmail($email);
        if ($existingUser && $existingUser['id'] !== $user['id']) {
            $error = 'Email address already exists.';
        }
    }

    if (empty($error)) {
        $updateData = [
            'name' => $name,
            'email' => $email
        ];

        // Update RZM-specific fields if user is RZM
        if ($user['role'] === ROLE_RZM) {
            $updateData['phone'] = $phone;
            $updateData['kingschat_username'] = $kingschat_username;
        }

        // Update password if provided
        if (!empty($new_password)) {
            if (!verifyPassword($current_password, $user['password'])) {
                $error = 'Current password is incorrect.';
            } elseif ($new_password !== $confirm_password) {
                $error = 'New passwords do not match.';
            } elseif (strlen($new_password) < 6) {
                $error = 'New password must be at least 6 characters long.';
            } else {
                $updateData['password'] = hashPassword($new_password);
            }
        }

        if (empty($error)) {
            // Update user data
            $users = getUsers();
            foreach ($users as &$u) {
                if ($u['id'] == $user['id']) {
                    $u = array_merge($u, $updateData);
                    break;
                }
            }
            saveUsers($users);

            // Update session data
            $_SESSION['name'] = $name;
            $_SESSION['email'] = $email;

            $message = 'Profile updated successfully!';
            $user = getUserById($_SESSION['user_id']); // Refresh user data
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Profile</title>

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
                        <a href="zone_details.php" class="nav-link">
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
                        <a href="profile.php" class="nav-link active">
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
                        <h1 class="m-0">Profile</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Profile</li>
                        </ol>
                    </div>
                </div>
            </div><!-- /.container-fluid -->
        </div>
        <!-- /.content-header -->

        <!-- Main content -->
        <section class="content">
            <div class="container-fluid">
                <!-- Success and error messages are now handled by SweetAlert2 toasts -->

                <div class="row">
                    <div class="col-md-3">
                        <!-- Profile Image -->
                        <div class="card card-primary card-outline">
                            <div class="card-body box-profile">
                                <div class="text-center">
                                    <i class="fas fa-user-circle fa-5x text-primary"></i>
                                </div>
                                <h3 class="profile-username text-center"><?php echo htmlspecialchars($user['name']); ?></h3>
                                <p class="text-muted text-center"><?php echo htmlspecialchars(ucfirst($user['role'])); ?></p>
                                <ul class="list-group list-group-unbordered mb-3">
                                    <li class="list-group-item">
                                        <b>Username</b> <a class="float-right"><?php echo htmlspecialchars($user['username']); ?></a>
                                    </li>
                                    <li class="list-group-item">
                                        <b>Role</b> <a class="float-right"><?php echo htmlspecialchars(ucfirst($user['role'])); ?></a>
                                    </li>
                                    <?php if ($user['role'] === ROLE_RZM): ?>
                                    <li class="list-group-item">
                                        <b>Region</b> <a class="float-right"><?php echo htmlspecialchars($user['region']); ?></a>
                                    </li>
                                    <li class="list-group-item">
                                        <b>Zone</b> <a class="float-right"><?php echo htmlspecialchars($user['zone']); ?></a>
                                    </li>
                                    <?php endif; ?>
                                    <li class="list-group-item">
                                        <b>Member Since</b> <a class="float-right"><?php echo htmlspecialchars(date('M Y', strtotime($user['created_at']))); ?></a>
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-9">
                        <div class="card">
                            <div class="card-header p-2">
                                <ul class="nav nav-pills">
                                    <li class="nav-item"><a class="nav-link active" href="#profile" data-toggle="tab">Profile Information</a></li>
                                    <li class="nav-item"><a class="nav-link" href="#password" data-toggle="tab">Change Password</a></li>
                                </ul>
                            </div><!-- /.card-header -->
                            <div class="card-body">
                                <div class="tab-content">
                                    <!-- Profile Information Tab -->
                                    <div class="active tab-pane" id="profile">
                                        <form method="post" class="form-horizontal">
                                            <div class="form-group row">
                                                <label for="name" class="col-sm-2 col-form-label">Name</label>
                                                <div class="col-sm-10">
                                                    <input type="text" class="form-control" id="name" name="name" value="<?php echo htmlspecialchars($user['name']); ?>" required>
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <label for="email" class="col-sm-2 col-form-label">Email</label>
                                                <div class="col-sm-10">
                                                    <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <label for="username" class="col-sm-2 col-form-label">Username</label>
                                                <div class="col-sm-10">
                                                    <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" readonly>
                                                    <small class="form-text text-muted">Username cannot be changed</small>
                                                </div>
                                            </div>
                                            <?php if ($user['role'] === ROLE_RZM): ?>
                                            <div class="form-group row">
                                                <label for="phone" class="col-sm-2 col-form-label">Phone</label>
                                                <div class="col-sm-10">
                                                    <input type="text" class="form-control" id="phone" name="phone" value="<?php echo htmlspecialchars($user['phone'] ?? ''); ?>">
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <label for="kingschat_username" class="col-sm-2 col-form-label">KingsChat Username</label>
                                                <div class="col-sm-10">
                                                    <input type="text" class="form-control" id="kingschat_username" name="kingschat_username" value="<?php echo htmlspecialchars($user['kingschat_username'] ?? ''); ?>">
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <label for="region" class="col-sm-2 col-form-label">Region</label>
                                                <div class="col-sm-10">
                                                    <input type="text" class="form-control" id="region" value="<?php echo htmlspecialchars($user['region'] ?? ''); ?>" readonly>
                                                    <small class="form-text text-muted">Region is assigned by admin</small>
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <label for="zone" class="col-sm-2 col-form-label">Zone</label>
                                                <div class="col-sm-10">
                                                    <input type="text" class="form-control" id="zone" value="<?php echo htmlspecialchars($user['zone'] ?? ''); ?>" readonly>
                                                    <small class="form-text text-muted">Zone is assigned by admin</small>
                                                </div>
                                            </div>
                                            <?php endif; ?>
                                            <div class="form-group row">
                                                <div class="offset-sm-2 col-sm-10">
                                                    <button type="submit" class="btn btn-primary">Update Profile</button>
                                                </div>
                                            </div>
                                        </form>
                                    </div>

                                    <!-- Change Password Tab -->
                                    <div class="tab-pane" id="password">
                                        <form method="post" class="form-horizontal">
                                            <div class="form-group row">
                                                <label for="current_password" class="col-sm-3 col-form-label">Current Password</label>
                                                <div class="col-sm-9">
                                                    <input type="password" class="form-control" id="current_password" name="current_password">
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <label for="new_password" class="col-sm-3 col-form-label">New Password</label>
                                                <div class="col-sm-9">
                                                    <input type="password" class="form-control" id="new_password" name="new_password">
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <label for="confirm_password" class="col-sm-3 col-form-label">Confirm Password</label>
                                                <div class="col-sm-9">
                                                    <input type="password" class="form-control" id="confirm_password" name="confirm_password">
                                                </div>
                                            </div>
                                            <div class="form-group row">
                                                <div class="offset-sm-3 col-sm-9">
                                                    <button type="submit" class="btn btn-primary">Change Password</button>
                                                </div>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div><!-- /.card-body -->
                        </div>
                    </div>
                </div>
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
<!-- SweetAlert2 -->
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<script>
// Show success toast notifications
<?php if ($message): ?>
Swal.fire({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    icon: 'success',
    title: '<?php echo addslashes($message); ?>'
});
<?php endif; ?>

// Show error toast notifications
<?php if ($error): ?>
Swal.fire({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 5000,
    timerProgressBar: true,
    icon: 'error',
    title: '<?php echo addslashes($error); ?>'
});
<?php endif; ?>
</script>
</body>
</html>
