<?php
require_once 'config.php';

session_start();

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$zones = getZones();
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = sanitizeInput($_POST['name'] ?? '');
    $email = sanitizeInput($_POST['email'] ?? '');
    $phone = sanitizeInput($_POST['phone'] ?? '');
    $kingschat_username = sanitizeInput($_POST['kingschat_username'] ?? '');
    $username = sanitizeInput($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $role = sanitizeInput($_POST['role'] ?? '');
    $region = sanitizeInput($_POST['region'] ?? '');
    $zone = sanitizeInput($_POST['zone'] ?? '');

    // Validation
    if (empty($name) || empty($email) || empty($username) || empty($password) || empty($role)) {
        $error = 'Please fill in all required fields.';
    } elseif ($role === ROLE_ADMIN) {
        $error = 'Admin role cannot be selected during registration. Contact an administrator to request admin privileges.';
    } elseif ($role === ROLE_RZM && (empty($phone) || empty($kingschat_username) || empty($region) || empty($zone))) {
        $error = 'Please fill in all RZM required fields.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters long.';
    } elseif (getUserByEmail($email)) {
        $error = 'Email address already exists.';
    } elseif (getUserByUsername($username)) {
        $error = 'Username already exists.';
    } else {
        // Create user with pending status
        $user = [
            'id' => generateUserId(),
            'name' => $name,
            'email' => $email,
            'username' => $username,
            'password' => hashPassword($password),
            'role' => $role,
            'phone' => $phone,
            'kingschat_username' => $kingschat_username,
            'region' => $region,
            'zone' => $zone,
            'status' => STATUS_PENDING,
            'created_at' => date('Y-m-d H:i:s'),
            'remember_token' => null
        ];

        $users = getUsers();
        $users[] = $user;
        saveUsers($users);

                    $success = 'Registration successful! Your account is pending approval by an administrator. You will be able to login once approved.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Register</title>

    <!-- Google Font: Source Sans Pro -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <!-- icheck bootstrap -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/icheck-bootstrap/3.0.1/icheck-bootstrap.min.css">
    <!-- Theme style -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
</head>
<body class="hold-transition register-page">
<div class="register-box">
    <div class="register-logo">
        <a href="#"><b>IPPC</b> Dashboard</a>
    </div>

    <div class="card">
        <div class="card-body register-card-body">
            <p class="login-box-msg">Register a new membership</p>

            <!-- Success and error messages are now handled by SweetAlert2 toasts -->

            <form action="register.php" method="post">
                <div class="input-group mb-3">
                    <input type="text" name="name" class="form-control" placeholder="Full Name" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-user"></span>
                        </div>
                    </div>
                </div>
                <div class="input-group mb-3">
                    <input type="email" name="email" class="form-control" placeholder="Email" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-envelope"></span>
                        </div>
                    </div>
                </div>
                <div class="input-group mb-3">
                    <input type="text" name="username" class="form-control" placeholder="Username" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-at"></span>
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
                <div class="input-group mb-3">
                    <input type="password" name="confirm_password" class="form-control" placeholder="Confirm Password" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-lock"></span>
                        </div>
                    </div>
                </div>
                <div class="input-group mb-3">
                    <select name="role" class="form-control" required onchange="toggleRZMFields(this.value)">
                        <option value="">Select Role</option>
                        <option value="<?php echo ROLE_RZM; ?>">RZM (Rhapsody Zonal Manager)</option>
                    </select>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-user-tag"></span>
                        </div>
                    </div>
                </div>
                <div class="form-text text-muted mb-3">
                    <small>Note: Only administrators can assign admin roles. Contact an admin to request admin privileges.</small>
                </div>

                <!-- RZM specific fields -->
                <div id="rzm-fields" style="display: none;">
                    <div class="input-group mb-3">
                        <input type="text" name="phone" class="form-control" placeholder="Phone Number">
                        <div class="input-group-append">
                            <div class="input-group-text">
                                <span class="fas fa-phone"></span>
                            </div>
                        </div>
                    </div>
                    <div class="input-group mb-3">
                        <input type="text" name="kingschat_username" class="form-control" placeholder="KingsChat Username">
                        <div class="input-group-append">
                            <div class="input-group-text">
                                <span class="fas fa-users"></span>
                            </div>
                        </div>
                    </div>
                    <div class="input-group mb-3">
                        <select name="region" class="form-control" onchange="loadZones(this.value)">
                            <option value="">Select Region</option>
                            <?php for ($i = 1; $i <= 5; $i++): ?>
                                <option value="Region <?php echo $i; ?>">Region <?php echo $i; ?></option>
                            <?php endfor; ?>
                            <option value="Other Regions">Other Regions</option>
                        </select>
                        <div class="input-group-append">
                            <div class="input-group-text">
                                <span class="fas fa-map"></span>
                            </div>
                        </div>
                    </div>
                    <div class="input-group mb-3">
                        <select name="zone" class="form-control" id="zone-select">
                            <option value="">Select Zone</option>
                        </select>
                        <div class="input-group-append">
                            <div class="input-group-text">
                                <span class="fas fa-map-marker"></span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-8">
                        <div class="icheck-primary">
                            <input type="checkbox" id="agreeTerms" name="terms" value="agree" required>
                            <label for="agreeTerms">
                                I agree to the <a href="#">terms</a>
                            </label>
                        </div>
                    </div>
                    <!-- /.col -->
                    <div class="col-4">
                        <button type="submit" class="btn btn-primary btn-block">Register</button>
                    </div>
                    <!-- /.col -->
                </div>
            </form>

            <a href="login.php" class="text-center">I already have a membership</a>
        </div>
        <!-- /.form-box -->
    </div><!-- /.card -->
</div>
<!-- /.register-box -->

<!-- jQuery -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<!-- Bootstrap 4 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<!-- AdminLTE App -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<!-- SweetAlert2 -->
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<script>
function toggleRZMFields(role) {
    const rzmFields = document.getElementById('rzm-fields');
    const phoneField = document.querySelector('input[name="phone"]');
    const kingschatField = document.querySelector('input[name="kingschat_username"]');
    const regionField = document.querySelector('select[name="region"]');
    const zoneField = document.querySelector('select[name="zone"]');

    if (role === '<?php echo ROLE_RZM; ?>') {
        rzmFields.style.display = 'block';
        phoneField.required = true;
        kingschatField.required = true;
        regionField.required = true;
        zoneField.required = true;
    } else {
        rzmFields.style.display = 'none';
        phoneField.required = false;
        kingschatField.required = false;
        regionField.required = false;
        zoneField.required = false;
    }
}

function loadZones(region) {
    const zoneSelect = document.getElementById('zone-select');
    zoneSelect.innerHTML = '<option value="">Select Zone</option>';

    if (!region) return;

    const zones = <?php echo json_encode($zones); ?>;

    if (zones[region]) {
        Object.keys(zones[region]).forEach(zoneName => {
            if (zoneName !== 'name' && typeof zones[region][zoneName] === 'object') {
                const option = document.createElement('option');
                option.value = zoneName;
                option.textContent = zones[region][zoneName].name || zoneName;
                zoneSelect.appendChild(option);
            }
        });
    }
}

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
