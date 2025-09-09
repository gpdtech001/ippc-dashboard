<?php
require_once 'config.php';

session_start();
requireAdmin();

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'add_category') {
        $name = sanitizeInput($_POST['name'] ?? '');
        $description = sanitizeInput($_POST['description'] ?? '');

        if (empty($name)) {
            $error = 'Category name is required';
            app_log('validation_error', 'Category name missing');
        } else {
            $categories = getReportCategories();
            $new = [
                'id' => generateCategoryId(),
                'name' => $name,
                'description' => $description,
                'created_at' => date('Y-m-d H:i:s'),
                'created_by' => $_SESSION['user_id'] ?? null
            ];
            $categories[] = $new;
            $res = saveReportCategories($categories);
            if ($res !== false) {
                $_SESSION['flash_message'] = 'Category added successfully';
                header('Location: report_categories.php');
                exit;
            } else {
                $error = 'Failed to save category';
                app_log('write_error', 'Failed to save category', ['file' => REPORT_CATEGORIES_FILE]);
            }
        }
    } elseif ($action === 'edit_category') {
        $catId = $_POST['category_id'] ?? '';
        $name = sanitizeInput($_POST['name'] ?? '');
        $description = sanitizeInput($_POST['description'] ?? '');

        if (empty($catId)) {
            $error = 'Missing category ID';
            app_log('validation_error', 'Edit missing category_id');
        } elseif (empty($name)) {
            $error = 'Category name is required';
            app_log('validation_error', 'Category name missing for edit', ['category_id' => $catId]);
        } else {
            $categories = getReportCategories();
            $found = false;
            foreach ($categories as &$c) {
                if ($c['id'] === $catId) {
                    $c['name'] = $name;
                    $c['description'] = $description;
                    $c['updated_at'] = date('Y-m-d H:i:s');
                    $c['updated_by'] = $_SESSION['user_id'] ?? null;
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $error = 'Category not found';
                app_log('not_found', 'Edit attempted on non-existent category', ['category_id' => $catId]);
            } else {
                $res = saveReportCategories($categories);
                if ($res === false) {
                    $error = 'Failed to update category';
                    app_log('write_error', 'Failed to update category', ['category_id' => $catId, 'file' => REPORT_CATEGORIES_FILE]);
                } else {
                    $_SESSION['flash_message'] = 'Category updated successfully';
                    header('Location: report_categories.php');
                    exit;
                }
            }
        }
    } elseif ($action === 'delete_category') {
        $catId = $_POST['category_id'] ?? '';
        $categories = getReportCategories();
        $before = count($categories);
        $categories = array_values(array_filter($categories, function ($c) use ($catId) {
            return $c['id'] !== $catId;
        }));
        $res = saveReportCategories($categories);
        if ($res !== false) {
            if ($before === count($categories)) {
                $_SESSION['flash_error'] = 'Category not found';
                app_log('not_found', 'Delete attempted on non-existent category', ['category_id' => $catId]);
            } else {
                $_SESSION['flash_message'] = 'Category deleted';
            }
            header('Location: report_categories.php');
            exit;
        } else {
            $error = 'Failed to delete category';
            app_log('write_error', 'Failed to delete category', ['category_id' => $catId, 'file' => REPORT_CATEGORIES_FILE]);
        }
    }
}

$categories = getReportCategories();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PPC | Report Categories</title>
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
                        <h1 class="m-0">Report Categories</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Report Categories</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-5">
                        <div class="card card-primary">
                            <div class="card-header"><h3 class="card-title">Add Category</h3></div>
                            <form method="post">
                                <div class="card-body">
                                    <?php if (!empty($message)): ?>
                                        <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
                                    <?php endif; ?>
                                    <?php if (!empty($error)): ?>
                                        <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                                    <?php endif; ?>
                                    <input type="hidden" name="action" value="add_category">
                                    <div class="form-group">
                                        <label>Name *</label>
                                        <input type="text" name="name" class="form-control" placeholder="e.g. Seed, Donation, Givings" required>
                                    </div>
                                    <div class="form-group">
                                        <label>Description</label>
                                        <textarea name="description" class="form-control" rows="3" placeholder="Optional description"></textarea>
                                    </div>
                                </div>
                                <div class="card-footer">
                                    <button type="submit" class="btn btn-primary"><i class="fas fa-plus"></i> Add</button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <div class="col-md-7">
                        <div class="card card-outline card-secondary">
                            <div class="card-header"><h3 class="card-title">Existing Categories</h3></div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped mb-0">
                                        <thead>
                                            <tr>
                                                <th style="width:40%">Name</th>
                                                <th>Description</th>
                                                <th style="width:260px">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                        <?php if (empty($categories)): ?>
                                            <tr><td colspan="3" class="text-center text-muted">No categories yet</td></tr>
                                        <?php else: ?>
                                            <?php foreach ($categories as $cat): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($cat['name']); ?></td>
                                                <td><?php echo htmlspecialchars($cat['description'] ?? ''); ?></td>
                                                <td>
                                                    <a href="report_category_fields.php?category_id=<?php echo urlencode($cat['id']); ?>" class="btn btn-sm btn-secondary mr-1">
                                                        <i class="fas fa-sliders"></i> Fields
                                                    </a>
                                                    <button type="button" class="btn btn-sm btn-primary mr-1" data-toggle="modal" data-target="#editCategoryModal"
                                                        data-id="<?php echo htmlspecialchars($cat['id']); ?>"
                                                        data-name="<?php echo htmlspecialchars($cat['name']); ?>"
                                                        data-description="<?php echo htmlspecialchars($cat['description'] ?? ''); ?>">
                                                        <i class="fas fa-edit"></i>
                                                    </button>
                                                    <form method="post" onsubmit="return confirm('Delete this category?');" class="d-inline">
                                                        <input type="hidden" name="action" value="delete_category">
                                                        <input type="hidden" name="category_id" value="<?php echo htmlspecialchars($cat['id']); ?>">
                                                        <button type="submit" class="btn btn-sm btn-danger"><i class="fas fa-trash"></i></button>
                                                    </form>
                                                </td>
                                            </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </div>

    <!-- Edit Category Modal -->
    <div class="modal fade" id="editCategoryModal" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Edit Category</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="edit_category">
                        <input type="hidden" name="category_id" id="edit_category_id">
                        <div class="form-group">
                            <label>Name *</label>
                            <input type="text" class="form-control" name="name" id="edit_category_name" required>
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea class="form-control" name="description" id="edit_category_description" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <footer class="main-footer">
        <strong>&copy; 2024 PPC Management.</strong> All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script>
$('#editCategoryModal').on('show.bs.modal', function (event) {
    var button = $(event.relatedTarget);
    $('#edit_category_id').val(button.data('id'));
    $('#edit_category_name').val(button.data('name'));
    $('#edit_category_description').val(button.data('description'));
});
</script>
</body>
</html>
