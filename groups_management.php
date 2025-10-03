<?php
require_once 'config.php';

session_start();
requireLogin();
requireCSRFToken();

$user = getUserById($_SESSION['user_id']);
$isAdmin = ($user['role'] === 'admin');
$isRZM = ($user['role'] === 'rzm');
$isUser = ($user['role'] === 'user');

// Allow access to admin, RZM, and regular users
if (!$isAdmin && !$isRZM && !$isUser) {
    $_SESSION['flash_error'] = 'Access denied. You do not have permission to manage groups.';
    header('Location: dashboard.php');
    exit;
}

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

// Get all zones for dropdowns
$zones = getAllZones();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'create_group') {
        $name = trim($_POST['name'] ?? '');
        $zone_id = $_POST['zone_id'] ?? '';
        
        if (empty($name)) {
            $error = 'Group name is required';
        } elseif (empty($zone_id)) {
            $error = 'Zone selection is required';
        } else {
            // For RZM, validate they can only create groups in their zone
            // Regular users and admins can create groups in any zone
            $userZone = $user['zone'] ?? '';
            if ($isRZM && $zone_id != $userZone) {
                $error = 'You can only create groups in your assigned zone';
            } else {
                $result = createGroup($name, '', $zone_id, $_SESSION['user_id']); // Pass empty string for description
                if ($result['success']) {
                    $_SESSION['flash_message'] = 'Group created successfully';
                    header('Location: groups_management.php');
                    exit;
                } else {
                    $error = $result['message'];
                }
            }
        }
    } elseif ($action === 'edit_group') {
        $group_id = $_POST['group_id'] ?? '';
        $name = trim($_POST['name'] ?? '');
        $zone_id = $_POST['zone_id'] ?? '';
        
        if (empty($group_id) || empty($name)) {
            $error = 'Group ID and name are required';
        } else {
            // Get current group to verify permissions
            $currentGroup = getGroupById($group_id);
            $userZone = $user['zone'] ?? '';
            if (!$currentGroup) {
                $error = 'Group not found';
            } elseif ($isRZM && $currentGroup['zone_id'] != $userZone) {
                $error = 'You can only edit groups in your assigned zone';
            } elseif ($isRZM && $zone_id != $userZone) {
                $error = 'You cannot move groups to other zones';
            } else {
                $result = updateGroup($group_id, $name, '', $zone_id, $_SESSION['user_id']); // Pass empty string for description
                if ($result['success']) {
                    $_SESSION['flash_message'] = 'Group updated successfully';
                    header('Location: groups_management.php');
                    exit;
                } else {
                    $error = $result['message'];
                }
            }
        }
    } elseif ($action === 'delete_group') {
        $group_id = $_POST['group_id'] ?? '';
        
        if (empty($group_id)) {
            $error = 'Group ID is required';
        } else {
            // Get current group to verify permissions
            $currentGroup = getGroupById($group_id);
            $userZone = $user['zone'] ?? '';
            if (!$currentGroup) {
                $error = 'Group not found';
            } elseif ($isRZM && $currentGroup['zone_id'] != $userZone) {
                $error = 'You can only delete groups in your assigned zone';
            } else {
                $result = deleteGroup($group_id, $_SESSION['user_id']);
                if ($result['success']) {
                    $_SESSION['flash_message'] = 'Group deleted successfully';
                    header('Location: groups_management.php');
                    exit;
                } else {
                    $error = $result['message'];
                }
            }
        }
    }
}

// Get groups based on user role
if ($isAdmin || $isUser) {
    // Admin and regular users can see all groups
    $groups = getAllGroups();
} else {
    // RZM can only see groups in their zone
    $userZone = $user['zone'] ?? '';
    $groups = getGroupsByZone($userZone);
}

// Get zone filter from URL
$selectedZone = $_GET['zone'] ?? '';
if ($selectedZone && ($isAdmin || $isUser)) {
    $groups = array_filter($groups, function($group) use ($selectedZone) {
        return $group['zone_id'] == $selectedZone;
    });
}

// Get search filter from URL
$searchTerm = $_GET['search'] ?? '';
if ($searchTerm) {
    $groups = array_filter($groups, function($group) use ($searchTerm) {
        return stripos($group['name'], $searchTerm) !== false || 
               stripos($group['description'], $searchTerm) !== false;
    });
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Groups Management</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/datatables/1.10.21/css/dataTables.bootstrap4.min.css">
    <style>
    .group-card {
        transition: transform 0.2s ease;
        border-left: 4px solid transparent;
    }
    .group-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        border-left-color: #007bff;
    }
    .zone-badge {
        font-size: 0.8em;
        padding: 4px 8px;
    }
    .action-buttons .btn {
        margin: 2px;
    }
    .filter-section {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }
    .stats-card {
        text-align: center;
        padding: 20px;
    }
    .stats-number {
        font-size: 2em;
        font-weight: bold;
        color: #007bff;
    }
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
                        <h1 class="m-0">Groups Management</h1>
                        <p class="text-muted mb-0">
                            <?php if ($isAdmin || $isUser): ?>
                                Manage all groups across all zones
                            <?php else: ?>
                                Manage groups in <?php echo htmlspecialchars($user['zone'] ?? 'your zone'); ?>
                            <?php endif; ?>
                        </p>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item"><a href="bulk_reports.php">Bulk Upload</a></li>
                            <li class="breadcrumb-item active">Groups Management</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <!-- Info Banner -->
                <div class="row">
                    <div class="col-12">
                        <div class="alert alert-success">
                            <h5>
                                <i class="fas fa-info-circle mr-2"></i>
                                Groups Management
                            </h5>
                            <div class="row align-items-center">
                                <div class="col-md-10">
                                    <p class="mb-0">
                                        Groups are used in report templates and bulk uploads. Make sure to add any new groups here 
                                        so they appear in your download templates. System groups are automatically included from your zone, 
                                        but you can create additional custom groups as needed.
                                    </p>
                                </div>
                                <div class="col-md-2 text-right">
                                    <a href="bulk_reports.php" class="btn btn-success btn-sm">
                                        <i class="fas fa-file-upload mr-1"></i>
                                        Back to Bulk Upload
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Statistics Row -->
                <div class="row mb-4">
                    <div class="col-lg-3 col-6">
                        <div class="small-box bg-info">
                            <div class="inner">
                                <h3><?php echo count($groups); ?></h3>
                                <p>Total Groups</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-users"></i>
                            </div>
                        </div>
                    </div>
                    <?php if ($isAdmin): ?>
                        <?php
                        $zoneGroupCounts = [];
                        foreach ($zones as $zoneId => $zone) {
                            $zoneGroupCounts[$zoneId] = count(getGroupsByZone($zoneId));
                        }
                        $topZones = array_slice($zoneGroupCounts, 0, 3, true);
                        ?>
                        <?php foreach ($topZones as $zoneId => $count): ?>
                            <div class="col-lg-3 col-6">
                                <div class="small-box bg-success">
                                    <div class="inner">
                                        <h3><?php echo $count; ?></h3>
                                        <p><?php echo htmlspecialchars($zones[$zoneId]['name']); ?></p>
                                    </div>
                                    <div class="icon">
                                        <i class="fas fa-map-marker-alt"></i>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>

                <!-- Filters and Search -->
                <div class="row">
                    <div class="col-12">
                        <div class="filter-section">
                            <form method="GET" class="row align-items-end">
                                <div class="col-md-4">
                                    <label for="search" class="form-label">Search Groups</label>
                                    <input type="text" class="form-control" id="search" name="search" 
                                           value="<?php echo htmlspecialchars($searchTerm); ?>" 
                                           placeholder="Search by name or description">
                                </div>
                                <?php if ($isAdmin || $isUser): ?>
                                    <div class="col-md-3">
                                        <label for="zone" class="form-label">Filter by Zone</label>
                                        <select class="form-control" id="zone" name="zone">
                                            <option value="">All Zones</option>
                                            <?php foreach ($zones as $zoneId => $zone): ?>
                                                <option value="<?php echo $zoneId; ?>" <?php echo $selectedZone == $zoneId ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($zone['name']); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                <?php endif; ?>
                                <div class="col-md-2">
                                    <button type="submit" class="btn btn-primary btn-block">
                                        <i class="fas fa-search mr-1"></i> Filter
                                    </button>
                                </div>
                                <div class="col-md-2">
                                    <button type="button" class="btn btn-success btn-block" data-toggle="modal" data-target="#createGroupModal">
                                        <i class="fas fa-plus mr-1"></i> Add Group
                                    </button>
                                </div>
                                <?php if ($searchTerm || $selectedZone): ?>
                                    <div class="col-md-1">
                                        <a href="groups_management.php" class="btn btn-secondary btn-block">
                                            <i class="fas fa-times"></i>
                                        </a>
                                    </div>
                                <?php endif; ?>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Groups List -->
                <div class="row">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-users mr-2"></i>
                                    Groups List
                                </h3>
                            </div>
                            <div class="card-body">
                                <?php if (empty($groups)): ?>
                                    <div class="alert alert-info text-center">
                                        <i class="fas fa-info-circle mr-2"></i>
                                        No groups found. 
                                        <?php if (!$searchTerm && !$selectedZone): ?>
                                            <button type="button" class="btn btn-sm btn-primary ml-2" data-toggle="modal" data-target="#createGroupModal">
                                                Create your first group
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table id="groupsTable" class="table table-bordered table-striped">
                                            <thead>
                                                <tr>
                                                    <th>Group Name</th>
                                                    <th>Zone</th>
                                                    <th>Created</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($groups as $group): ?>
                                                    <tr>
                                                        <td>
                                                            <strong><?php echo htmlspecialchars($group['name']); ?></strong>
                                                            <?php if ($group['source'] === 'zones.json'): ?>
                                                                <span class="badge badge-light badge-sm ml-2">System</span>
                                                            <?php else: ?>
                                                                <span class="badge badge-success badge-sm ml-2">Custom</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td>
                                                            <span class="badge badge-primary zone-badge">
                                                                <?php echo htmlspecialchars($zones[$group['zone_id']]['name'] ?? 'Unknown Zone'); ?>
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <?php echo date('M d, Y', strtotime($group['created_at'])); ?>
                                                        </td>
                                                        <td class="action-buttons">
                                                            <!-- All users can now edit and delete all groups -->
                                                            <button type="button" class="btn btn-sm btn-info" 
                                                                    onclick="editGroup(<?php echo htmlspecialchars(json_encode($group)); ?>)">
                                                                <i class="fas fa-edit"></i> Edit
                                                            </button>
                                                            <button type="button" class="btn btn-sm btn-danger" 
                                                                    onclick="confirmDelete('<?php echo $group['id']; ?>', '<?php echo htmlspecialchars($group['name']); ?>')">
                                                                <i class="fas fa-trash"></i> Delete
                                                            </button>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </div>

    <footer class="main-footer">
        <strong>&copy; 2024 IPPC Dashboard.</strong> All rights reserved.
    </footer>
</div>

<!-- Create Group Modal -->
<div class="modal fade" id="createGroupModal" tabindex="-1" role="dialog" aria-labelledby="createGroupModalLabel" aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(generateCSRFToken()); ?>">
                <div class="modal-header">
                    <h5 class="modal-title" id="createGroupModalLabel">Create New Group</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="action" value="create_group">
                    
                    <div class="form-group">
                        <label for="create_name">Group Name <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="create_name" name="name" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="create_zone_id">Zone <span class="text-danger">*</span></label>
                        <select class="form-control" id="create_zone_id" name="zone_id" required>
                            <option value="">Select Zone</option>
                            <?php foreach ($zones as $zoneId => $zone): ?>
                                <?php if ($isAdmin || $isUser || $zoneId == $user['zone']): ?>
                                    <option value="<?php echo $zoneId; ?>" <?php echo ($isRZM && $zoneId == $user['zone']) ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($zone['name']); ?>
                                    </option>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-success">
                        <i class="fas fa-plus mr-1"></i> Create Group
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Edit Group Modal -->
<div class="modal fade" id="editGroupModal" tabindex="-1" role="dialog" aria-labelledby="editGroupModalLabel" aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(generateCSRFToken()); ?>">
                <div class="modal-header">
                    <h5 class="modal-title" id="editGroupModalLabel">Edit Group</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="action" value="edit_group">
                    <input type="hidden" name="group_id" id="edit_group_id">
                    
                    <div class="form-group">
                        <label for="edit_name">Group Name <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="edit_name" name="name" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="edit_zone_id">Zone <span class="text-danger">*</span></label>
                        <select class="form-control" id="edit_zone_id" name="zone_id" required>
                            <?php foreach ($zones as $zoneId => $zone): ?>
                                <?php if ($isAdmin || $isUser || $zoneId == $user['zone']): ?>
                                    <option value="<?php echo $zoneId; ?>">
                                        <?php echo htmlspecialchars($zone['name']); ?>
                                    </option>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save mr-1"></i> Update Group
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Delete Confirmation Modal -->
<div class="modal fade" id="deleteConfirmModal" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header bg-danger text-white">
                <h5 class="modal-title">
                    <i class="fas fa-exclamation-triangle mr-2"></i>
                    Confirm Deletion
                </h5>
                <button type="button" class="close text-white" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <form method="POST" id="deleteForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(generateCSRFToken()); ?>">
                <div class="modal-body text-center">
                    <input type="hidden" name="action" value="delete_group">
                    <input type="hidden" name="group_id" id="delete_group_id">
                    
                    <i class="fas fa-trash-alt fa-3x text-danger mb-3"></i>
                    <h5>Are you sure you want to delete this group?</h5>
                    <p class="text-muted mb-3">
                        Group: <strong id="delete_group_name"></strong>
                    </p>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle mr-2"></i>
                        This action cannot be undone. All reports associated with this group may be affected.
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">
                        <i class="fas fa-trash mr-1"></i> Delete Group
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/datatables/1.10.21/js/jquery.dataTables.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/datatables/1.10.21/js/dataTables.bootstrap4.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<script>
// Initialize DataTable
$(document).ready(function() {
    $('#groupsTable').DataTable({
        "responsive": true,
        "lengthChange": false,
        "autoWidth": false,
        "searching": false, // We have our own search
        "pageLength": 25,
        "order": [[3, "desc"]], // Sort by created date desc
        "columnDefs": [
            { "orderable": false, "targets": 4 } // Actions column not sortable
        ]
    });
});

// Show success/error messages
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

function editGroup(group) {
    document.getElementById('edit_group_id').value = group.id;
    document.getElementById('edit_name').value = group.name;
    document.getElementById('edit_zone_id').value = group.zone_id;
    $('#editGroupModal').modal('show');
}

function confirmDelete(groupId, groupName) {
    document.getElementById('delete_group_id').value = groupId;
    document.getElementById('delete_group_name').textContent = groupName;
    $('#deleteConfirmModal').modal('show');
}

// Auto-submit search form on Enter key
document.getElementById('search').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        this.form.submit();
    }
});
</script>
</body>
</html>
