<?php
require_once 'config.php';

session_start();
requireCSRFToken();

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = $_SESSION['flash_error'] ?? '';
$success = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_error'], $_SESSION['flash_message']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login_input = sanitizeInput($_POST['login_input'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']);

    if (empty($login_input) || empty($password)) {
        $_SESSION['flash_error'] = 'Please fill in all fields.';
        header('Location: login.php');
        exit;
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
                    $_SESSION['flash_error'] = 'Your account has been rejected. Please contact an administrator.';
                } elseif (isset($user['status']) && $user['status'] === STATUS_DISABLED) {
                    $_SESSION['flash_error'] = 'Your account has been disabled. Please contact an administrator.';
                } elseif (isset($user['status']) && $user['status'] === STATUS_PENDING) {
                    $_SESSION['flash_error'] = 'Your account is pending approval. Please wait for administrator approval.';
                } else {
                    $_SESSION['flash_error'] = 'Your account is pending approval. Please contact an administrator.';
                }
                header('Location: login.php');
                exit;
            } else {
                establishUserSession($user);

                // Rotate remember token on every login
                clearRememberToken($user['id']);
                if ($remember) {
                    persistRememberToken($user['id']);
                }

                header('Location: dashboard.php');
                exit;
            }
        } else {
            $_SESSION['flash_error'] = 'Invalid login credentials.';
            header('Location: login.php');
            exit;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Log in</title>

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
        <a href="#"><b>IPPC</b> Dashboard</a>
    </div>
    <!-- /.login-logo -->
    <div class="card">
        <div class="card-body login-card-body">
            <p class="login-box-msg">Sign in to start your session</p>

            <!-- Success and error messages are now handled by SweetAlert2 toasts -->

            <form action="login.php" method="post">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <div class="input-group mb-3">
                    <input type="text" name="login_input" class="form-control" placeholder="Email or Username" maxlength="255" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-envelope"></span>
                        </div>
                    </div>
                </div>
                <div class="input-group mb-3">
                    <input type="password" name="password" class="form-control" placeholder="Password" maxlength="255" required>
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
    title: <?php echo json_encode($error); ?>
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
    title: <?php echo json_encode($success); ?>
});
<?php endif; ?>
</script>
</body>
</html>
