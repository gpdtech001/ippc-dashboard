<?php
require_once 'config.php';

session_start();

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login_input = sanitizeInput($_POST['login_input'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']);

    if (empty($login_input) || empty($password)) {
        $error = 'Please fill in all fields.';
    } else {
        // Try to find user by email first, then by username
        $user = getUserByEmail($login_input);
        if (!$user) {
            $user = getUserByUsername($login_input);
        }

        if ($user && verifyPassword($password, $user['password'])) {
            // Check if user is approved and enabled
            if (!isUserApproved($user)) {
                if (isset($user['status']) && $user['status'] === STATUS_REJECTED) {
                    $error = 'Your account has been rejected. Please contact an administrator.';
                } elseif (isset($user['status']) && $user['status'] === STATUS_DISABLED) {
                    $error = 'Your account has been disabled. Please contact an administrator.';
                } elseif (isset($user['status']) && $user['status'] === STATUS_PENDING) {
                    $error = 'Your account is pending approval. Please wait for administrator approval.';
                } else {
                    $error = 'Your account is pending approval. Please contact an administrator.';
                }
            } else {
                // Set session
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['name'] = $user['name'];

                // Set remember cookie if requested
                if ($remember) {
                    $token = bin2hex(random_bytes(32));
                    setcookie('remember_token', $token, time() + (86400 * 30), '/'); // 30 days

                    // Store token in user data
                    $users = getUsers();
                    foreach ($users as &$u) {
                        if ($u['id'] == $user['id']) {
                            $u['remember_token'] = $token;
                            break;
                        }
                    }
                    saveUsers($users);
                }

                header('Location: dashboard.php');
                exit;
            }
        } else {
            $error = 'Invalid login credentials.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | Log in</title>

    <!-- Google Font: Source Sans Pro -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <!-- icheck bootstrap -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/icheck-bootstrap/3.0.1/icheck-bootstrap.min.css">
    <!-- Theme style -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
</head>
<body class="hold-transition login-page">
<div class="login-box">
    <div class="login-logo">
        <a href="#"><b>PPC</b> Management</a>
    </div>
    <!-- /.login-logo -->
    <div class="card">
        <div class="card-body login-card-body">
            <p class="login-box-msg">Sign in to start your session</p>

            <!-- Success and error messages are now handled by SweetAlert2 toasts -->

            <form action="login.php" method="post">
                <div class="input-group mb-3">
                    <input type="text" name="login_input" class="form-control" placeholder="Email or Username" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-envelope"></span>
                        </div>
                    </div>
                </div>
                <div class="input-group mb-3">
                    <input type="password" name="password" class="form-control" placeholder="Password" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-lock"></span>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-8">
                        <div class="icheck-primary">
                            <input type="checkbox" id="remember" name="remember">
                            <label for="remember">
                                Remember Me
                            </label>
                        </div>
                    </div>
                    <!-- /.col -->
                    <div class="col-4">
                        <button type="submit" class="btn btn-primary btn-block">Sign In</button>
                    </div>
                    <!-- /.col -->
                </div>
            </form>

            <p class="mb-0">
                <a href="register.php" class="text-center">Register a new account</a>
            </p>
        </div>
        <!-- /.login-card-body -->
    </div>
</div>
<!-- /.login-box -->

<!-- jQuery -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<!-- Bootstrap 4 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<!-- AdminLTE App -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<!-- SweetAlert2 -->
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<script>
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

// Show success toast notifications
<?php if ($success): ?>
Swal.fire({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    icon: 'success',
    title: '<?php echo addslashes($success); ?>'
});
<?php endif; ?>
</script>
</body>
</html>
