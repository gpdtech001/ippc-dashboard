<?php
require_once 'config.php';

session_start();
requireAdmin();

$users = getUsers();
$zones = getZones();

// Handle user actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        $action = $_POST['action'];
        $userId = $_POST['user_id'] ?? '';

        if ($action === 'delete' && $userId) {
            $users = array_filter($users, function($user) use ($userId) {
                return $user['id'] !== $userId;
            });
            saveUsers($users);
            header('Location: user_management.php?success=User deleted successfully');
            exit;
        } elseif ($action === 'update_role' && $userId) {
            $newRole = $_POST['role'] ?? '';
            $region = $_POST['region'] ?? '';
            $zone = $_POST['zone'] ?? '';

            foreach ($users as &$user) {
                if ($user['id'] === $userId) {
                    $user['role'] = $newRole;
                    if ($newRole === ROLE_RZM) {
                        $user['region'] = $region;
                        $user['zone'] = $zone;
                    }
                    break;
                }
            }
            saveUsers($users);
            header('Location: user_management.php?success=User updated successfully');
            exit;
        } elseif ($action === 'approve_user' && $userId) {
            approveUser($userId);
            header('Location: user_management.php?success=User approved successfully');
            exit;
        } elseif ($action === 'reject_user' && $userId) {
            rejectUser($userId);
            header('Location: user_management.php?success=User rejected successfully');
            exit;
        } elseif ($action === 'disable_user' && $userId) {
            disableUser($userId);
            header('Location: user_management.php?success=User disabled successfully');
            exit;
        } elseif ($action === 'enable_user' && $userId) {
            enableUser($userId);
            header('Location: user_management.php?success=User enabled successfully');
            exit;
        } elseif ($action === 'add_user') {
            $name = sanitizeInput($_POST['name'] ?? '');
            $email = sanitizeInput($_POST['email'] ?? '');
            $username = sanitizeInput($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $role = sanitizeInput($_POST['role'] ?? '');
            $phone = sanitizeInput($_POST['phone'] ?? '');
            $kingschat_username = sanitizeInput($_POST['kingschat_username'] ?? '');
            $region = sanitizeInput($_POST['region'] ?? '');
            $zone = sanitizeInput($_POST['zone'] ?? '');

            // Validation
            if (empty($name) || empty($email) || empty($username) || empty($password) || empty($role)) {
                header('Location: user_management.php?error=Please fill in all required fields');
                exit;
            }
            if ($role === ROLE_RZM && (empty($phone) || empty($kingschat_username) || empty($region) || empty($zone))) {
                header('Location: user_management.php?error=Please fill in all RZM required fields');
                exit;
            }
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                header('Location: user_management.php?error=Please enter a valid email address');
                exit;
            }
            if (strlen($password) < 6) {
                header('Location: user_management.php?error=Password must be at least 6 characters long');
                exit;
            }
            if (getUserByEmail($email)) {
                header('Location: user_management.php?error=Email address already exists');
                exit;
            }
            if (getUserByUsername($username)) {
                header('Location: user_management.php?error=Username already exists');
                exit;
            }

            // Create new user
            $newUser = [
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
                'status' => STATUS_APPROVED, // Admin-created users are auto-approved
                'created_at' => date('Y-m-d H:i:s'),
                'approved_at' => date('Y-m-d H:i:s'),
                'approved_by' => $_SESSION['user_id'],
                'remember_token' => null
            ];

            $users[] = $newUser;
            saveUsers($users);
            header('Location: user_management.php?success=User created successfully');
            exit;
        }
    }
}

$message = '';
$error = '';
if (isset($_GET['success'])) {
    $message = $_GET['success'];
}
if (isset($_GET['error'])) {
    $error = $_GET['error'];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | User Management</title>

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
                        <h1 class="m-0">User Management</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">User Management</li>
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

                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">All Users</h3>
                        <div class="card-tools">
                            <button type="button" class="btn btn-primary btn-sm" data-toggle="modal" data-target="#addUserModal">
                                <i class="fas fa-plus"></i> Add User
                            </button>
                        </div>
                    </div>
                    <div class="card-body table-responsive p-0">
                        <table class="table table-hover text-nowrap">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Region</th>
                                    <th>Zone</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($user['name']); ?></td>
                                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                                    <td><?php echo htmlspecialchars($user['email']); ?></td>
                                    <td>
                                        <span class="badge badge-<?php echo $user['role'] === ROLE_ADMIN ? 'danger' : 'info'; ?>">
                                            <?php echo htmlspecialchars(ucfirst($user['role'])); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($user['region'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($user['zone'] ?? 'N/A'); ?></td>
                                    <td>
                                        <?php
                                        $status = $user['status'] ?? STATUS_APPROVED;
                                        $badgeClass = 'success';
                                        $statusText = 'Approved';
                                        if ($status === STATUS_PENDING) {
                                            $badgeClass = 'warning';
                                            $statusText = 'Pending';
                                        } elseif ($status === STATUS_DISABLED) {
                                            $badgeClass = 'secondary';
                                            $statusText = 'Disabled';
                                        } elseif ($status === STATUS_REJECTED) {
                                            $badgeClass = 'danger';
                                            $statusText = 'Rejected';
                                        }
                                        ?>
                                        <span class="badge badge-<?php echo $badgeClass; ?>"><?php echo $statusText; ?></span>
                                    </td>
                                    <td><?php echo htmlspecialchars($user['created_at']); ?></td>
                                    <td>
                                        <?php
                                        $userStatus = $user['status'] ?? STATUS_APPROVED;
                                        if ($userStatus === STATUS_PENDING):
                                        ?>
                                            <button type="button" class="btn btn-sm btn-success" onclick="approveUser('<?php echo $user['id']; ?>', '<?php echo htmlspecialchars($user['name']); ?>')">
                                                <i class="fas fa-check"></i> Approve
                                            </button>
                                            <button type="button" class="btn btn-sm btn-warning" onclick="rejectUser('<?php echo $user['id']; ?>', '<?php echo htmlspecialchars($user['name']); ?>')">
                                                <i class="fas fa-times"></i> Reject
                                            </button>
                                        <?php elseif ($userStatus === STATUS_APPROVED): ?>
                                            <button type="button" class="btn btn-sm btn-secondary" onclick="disableUser('<?php echo $user['id']; ?>', '<?php echo htmlspecialchars($user['name']); ?>')">
                                                <i class="fas fa-ban"></i> Disable
                                            </button>
                                            <span class="text-muted ml-1">
                                                <i class="fas fa-check-circle text-success"></i> Active
                                            </span>
                                        <?php elseif ($userStatus === STATUS_DISABLED): ?>
                                            <button type="button" class="btn btn-sm btn-success" onclick="enableUser('<?php echo $user['id']; ?>', '<?php echo htmlspecialchars($user['name']); ?>')">
                                                <i class="fas fa-check"></i> Enable
                                            </button>
                                            <span class="text-muted ml-1">
                                                <i class="fas fa-ban text-secondary"></i> Disabled
                                            </span>
                                        <?php elseif ($userStatus === STATUS_REJECTED): ?>
                                            <button type="button" class="btn btn-sm btn-success" onclick="approveUser('<?php echo $user['id']; ?>', '<?php echo htmlspecialchars($user['name']); ?>')">
                                                <i class="fas fa-check"></i> Re-approve
                                            </button>
                                            <span class="text-muted ml-1">
                                                <i class="fas fa-times-circle text-danger"></i> Rejected
                                            </span>
                                        <?php endif; ?>
                                        <button type="button" class="btn btn-sm btn-info ml-1" onclick="editUser('<?php echo $user['id']; ?>')">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button type="button" class="btn btn-sm btn-danger ml-1" onclick="deleteUser('<?php echo $user['id']; ?>', '<?php echo htmlspecialchars($user['name']); ?>')">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div><!-- /.container-fluid -->
        </section>
        <!-- /.content -->
    </div>
    <!-- /.content-wrapper -->

    <!-- Add User Modal -->
    <div class="modal fade" id="addUserModal" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Add New User</h4>
                    <button type="button" class="close" data-dismiss="modal">
                        <span>&times;</span>
                    </button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add_user">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Name *</label>
                                    <input type="text" name="name" class="form-control" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Email *</label>
                                    <input type="email" name="email" class="form-control" required>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Username *</label>
                                    <input type="text" name="username" class="form-control" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Password *</label>
                                    <input type="password" name="password" class="form-control" required minlength="6">
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Role *</label>
                            <select name="role" class="form-control" required onchange="toggleAddRZMFields(this.value)">
                                <option value="">Select Role</option>
                                <option value="<?php echo ROLE_RZM; ?>">RZM (Rhapsody Zonal Manager)</option>
                                <option value="<?php echo ROLE_ADMIN; ?>">Admin</option>
                            </select>
                        </div>
                        <div id="add_rzm_fields" style="display: none;">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label>Phone *</label>
                                        <input type="text" name="phone" class="form-control">
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label>KingsChat Username *</label>
                                        <input type="text" name="kingschat_username" class="form-control">
                                    </div>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label>Region *</label>
                                        <select name="region" class="form-control" onchange="loadAddZones(this.value)">
                                            <option value="">Select Region</option>
                                            <?php for ($i = 1; $i <= 5; $i++): ?>
                                                <option value="Region <?php echo $i; ?>">Region <?php echo $i; ?></option>
                                            <?php endfor; ?>
                                            <option value="Other Regions">Other Regions</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label>Zone *</label>
                                        <select name="zone" class="form-control" id="add_zone_select">
                                            <option value="">Select Zone</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Create User</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit User Modal -->
    <div class="modal fade" id="editUserModal" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Edit User</h4>
                    <button type="button" class="close" data-dismiss="modal">
                        <span>&times;</span>
                    </button>
                </div>
                <form id="editUserForm" method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="update_role">
                        <input type="hidden" name="user_id" id="edit_user_id">
                        <div class="form-group">
                            <label>Role</label>
                            <select name="role" id="edit_role" class="form-control" onchange="toggleEditRZMFields(this.value)">
                                <option value="<?php echo ROLE_RZM; ?>">RZM (Rhapsody Zonal Manager)</option>
                                <option value="<?php echo ROLE_ADMIN; ?>">Admin</option>
                            </select>
                        </div>
                        <div id="edit_rzm_fields">
                            <div class="form-group">
                                <label>Region</label>
                                <select name="region" id="edit_region" class="form-control" onchange="loadEditZones(this.value)">
                                    <option value="">Select Region</option>
                                    <?php for ($i = 1; $i <= 5; $i++): ?>
                                        <option value="Region <?php echo $i; ?>">Region <?php echo $i; ?></option>
                                    <?php endfor; ?>
                                    <option value="Other Regions">Other Regions</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Zone</label>
                                <select name="zone" id="edit_zone" class="form-control">
                                    <option value="">Select Zone</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update User</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

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

<script>
const zones = <?php echo json_encode($zones); ?>;
const users = <?php echo json_encode($users); ?>;

// Show success toast notifications
<?php if (isset($_GET['success'])): ?>
Swal.fire({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    icon: 'success',
    title: '<?php echo htmlspecialchars($_GET['success']); ?>'
});
<?php endif; ?>

// Show error toast notifications
<?php if (isset($_GET['error'])): ?>
Swal.fire({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 5000,
    timerProgressBar: true,
    icon: 'error',
    title: '<?php echo htmlspecialchars($_GET['error']); ?>'
});
<?php endif; ?>

function editUser(userId) {
    const user = users.find(u => u.id === userId);
    if (!user) return;

    document.getElementById('edit_user_id').value = userId;
    document.getElementById('edit_role').value = user.role;

    if (user.role === '<?php echo ROLE_RZM; ?>') {
        document.getElementById('edit_rzm_fields').style.display = 'block';
        document.getElementById('edit_region').value = user.region || '';
        loadEditZones(user.region);
        setTimeout(() => {
            document.getElementById('edit_zone').value = user.zone || '';
        }, 100);
    } else {
        document.getElementById('edit_rzm_fields').style.display = 'none';
    }

    $('#editUserModal').modal('show');
}

function toggleEditRZMFields(role) {
    const rzmFields = document.getElementById('edit_rzm_fields');
    if (role === '<?php echo ROLE_RZM; ?>') {
        rzmFields.style.display = 'block';
    } else {
        rzmFields.style.display = 'none';
    }
}

function loadEditZones(region) {
    const zoneSelect = document.getElementById('edit_zone');
    zoneSelect.innerHTML = '<option value="">Select Zone</option>';

    if (!region || !zones[region]) return;

    Object.keys(zones[region]).forEach(zoneName => {
        if (zoneName !== 'name' && typeof zones[region][zoneName] === 'object') {
            const option = document.createElement('option');
            option.value = zoneName;
            option.textContent = zones[region][zoneName].name || zoneName;
            zoneSelect.appendChild(option);
        }
    });
}

function approveUser(userId, userName) {
    Swal.fire({
        title: 'Approve User?',
        text: `Are you sure you want to approve "${userName}"? They will be able to login to the system.`,
        icon: 'question',
        showCancelButton: true,
        confirmButtonColor: '#28a745',
        cancelButtonColor: '#6c757d',
        confirmButtonText: 'Yes, Approve',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            const form = document.createElement('form');
            form.method = 'post';
            form.innerHTML = `
                <input type="hidden" name="action" value="approve_user">
                <input type="hidden" name="user_id" value="${userId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }
    });
}

function rejectUser(userId, userName) {
    Swal.fire({
        title: 'Reject User?',
        text: `Are you sure you want to reject "${userName}"? This action cannot be easily undone.`,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#dc3545',
        cancelButtonColor: '#6c757d',
        confirmButtonText: 'Yes, Reject',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            const form = document.createElement('form');
            form.method = 'post';
            form.innerHTML = `
                <input type="hidden" name="action" value="reject_user">
                <input type="hidden" name="user_id" value="${userId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }
    });
}

function disableUser(userId, userName) {
    Swal.fire({
        title: 'Disable User?',
        text: `Are you sure you want to disable "${userName}"? They will not be able to login until re-enabled.`,
        icon: 'question',
        showCancelButton: true,
        confirmButtonColor: '#6c757d',
        cancelButtonColor: '#28a745',
        confirmButtonText: 'Yes, Disable',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            const form = document.createElement('form');
            form.method = 'post';
            form.innerHTML = `
                <input type="hidden" name="action" value="disable_user">
                <input type="hidden" name="user_id" value="${userId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }
    });
}

function enableUser(userId, userName) {
    Swal.fire({
        title: 'Enable User?',
        text: `Are you sure you want to enable "${userName}"? They will be able to login again.`,
        icon: 'question',
        showCancelButton: true,
        confirmButtonColor: '#28a745',
        cancelButtonColor: '#6c757d',
        confirmButtonText: 'Yes, Enable',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            const form = document.createElement('form');
            form.method = 'post';
            form.innerHTML = `
                <input type="hidden" name="action" value="enable_user">
                <input type="hidden" name="user_id" value="${userId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }
    });
}

function deleteUser(userId, userName) {
    Swal.fire({
        title: 'Delete User?',
        text: `Are you sure you want to permanently delete "${userName}"? This action cannot be undone.`,
        icon: 'error',
        showCancelButton: true,
        confirmButtonColor: '#dc3545',
        cancelButtonColor: '#6c757d',
        confirmButtonText: 'Yes, Delete',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            const form = document.createElement('form');
            form.method = 'post';
            form.innerHTML = `
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="user_id" value="${userId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }
    });
}

function toggleAddRZMFields(role) {
    const rzmFields = document.getElementById('add_rzm_fields');
    const phoneField = document.querySelector('input[name="phone"]');
    const kingschatField = document.querySelector('input[name="kingschat_username"]');
    const regionField = document.querySelector('select[name="region"]');
    const zoneField = document.querySelector('select[name="zone"]');

    if (role === '<?php echo ROLE_RZM; ?>') {
        rzmFields.style.display = 'block';
        if (phoneField) phoneField.required = true;
        if (kingschatField) kingschatField.required = true;
        if (regionField) regionField.required = true;
        if (zoneField) zoneField.required = true;
    } else {
        rzmFields.style.display = 'none';
        if (phoneField) phoneField.required = false;
        if (kingschatField) kingschatField.required = false;
        if (regionField) regionField.required = false;
        if (zoneField) zoneField.required = false;
    }
}

function loadAddZones(region) {
    const zoneSelect = document.getElementById('add_zone_select');
    zoneSelect.innerHTML = '<option value="">Select Zone</option>';

    if (!region || !zones[region]) return;

    Object.keys(zones[region]).forEach(zoneName => {
        if (zoneName !== 'name' && typeof zones[region][zoneName] === 'object') {
            const option = document.createElement('option');
            option.value = zoneName;
            option.textContent = zones[region][zoneName].name || zoneName;
            zoneSelect.appendChild(option);
        }
    });
}
</script>
</body>
</html>
