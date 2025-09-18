<?php
require_once 'config.php';

session_start();
requireAdmin();

$categoryId = $_GET['category_id'] ?? '';
$category = getCategoryById($categoryId);
if (!$category) {
    app_log('not_found', 'Category fields page requested for non-existent category', ['category_id' => $categoryId]);
    header('Location: report_categories.php?error=Category not found');
    exit;
}

// Load available field types
$fieldTypes = getFieldTypes();

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $categories = getReportCategories();
    $index = -1;
    foreach ($categories as $i => $c) {
        if ($c['id'] === $categoryId) { $index = $i; break; }
    }
    if ($index === -1) {
        $error = 'Category not found';
        app_log('not_found', 'Fields modify on non-existent category', ['category_id' => $categoryId]);
    } else {
        if (!isset($categories[$index]['fields']) || !is_array($categories[$index]['fields'])) {
            $categories[$index]['fields'] = [];
        }

        if ($action === 'add_field') {
            $label = sanitizeInput($_POST['label'] ?? '');
            $type = sanitizeInput($_POST['type'] ?? 'text');
            $required = isset($_POST['required']) ? true : false;
            $placeholder = sanitizeInput($_POST['placeholder'] ?? '');
            $source = sanitizeInput($_POST['source'] ?? 'manual');
            $options_raw = trim($_POST['options'] ?? '');

            if (empty($label)) {
                $error = 'Field label is required';
                app_log('validation_error', 'Field label missing', ['category_id' => $categoryId]);
            } else {
                $options = [];
                // Normalize "groups" pseudo-type to select + zones_groups
                if ($type === 'groups') {
                    $type = 'select';
                    $source = 'zones_groups';
                }
                if ($type === 'select' && $source === 'manual' && $options_raw !== '') {
                    // Split by newlines or commas
                    $parts = preg_split('/[\r\n,]+/', $options_raw);
                    foreach ($parts as $opt) {
                        $opt = trim($opt);
                        if ($opt !== '') { $options[] = $opt; }
                    }
                }
                $field = [
                    'id' => generateFieldId(),
                    'label' => $label,
                    'type' => $type,
                    'required' => $required,
                    'placeholder' => $placeholder,
                    'options' => $options,
                    'source' => $type === 'select' ? $source : 'manual'
                ];
                $categories[$index]['fields'][] = $field;
                $result = saveReportCategories($categories);
                if ($result['success'] === false) {
                    $error = 'Failed to add field: ' . $result['message'];
                    app_log('write_error', 'Failed to add field', ['category_id' => $categoryId]);
                } else {
                    $_SESSION['flash_message'] = 'Field added successfully';
                    header('Location: report_category_fields.php?category_id=' . urlencode($categoryId));
                    exit;
                }
            }
        } elseif ($action === 'edit_field') {
            $fieldId = $_POST['field_id'] ?? '';
            $label = sanitizeInput($_POST['label'] ?? '');
            $type = sanitizeInput($_POST['type'] ?? 'text');
            $required = isset($_POST['required']) ? true : false;
            $placeholder = sanitizeInput($_POST['placeholder'] ?? '');
            $source = sanitizeInput($_POST['source'] ?? 'manual');
            $options_raw = trim($_POST['options'] ?? '');

            if (empty($fieldId)) {
                $error = 'Missing field ID';
                app_log('validation_error', 'Edit field missing field_id', ['category_id' => $categoryId]);
            } elseif (empty($label)) {
                $error = 'Field label is required';
                app_log('validation_error', 'Field label missing for edit', ['category_id' => $categoryId, 'field_id' => $fieldId]);
            } else {
                $found = false;
                foreach ($categories[$index]['fields'] as &$f) {
                    if ($f['id'] === $fieldId) {
                        $found = true;
                        $f['label'] = $label;
                        $f['type'] = $type;
                        $f['required'] = $required;
                        $f['placeholder'] = $placeholder;
                        // Normalize "groups" pseudo-type to select + zones_groups
                        if ($type === 'groups') {
                            $type = 'select';
                            $source = 'zones_groups';
                        }
                        $opts = [];
                        if ($type === 'select' && $source === 'manual' && $options_raw !== '') {
                            $parts = preg_split('/[\r\n,]+/', $options_raw);
                            foreach ($parts as $opt) { $opt = trim($opt); if ($opt !== '') { $opts[] = $opt; } }
                        }
                        $f['options'] = $opts;
                        $f['source'] = $type === 'select' ? $source : 'manual';
                        $f['updated_at'] = date('Y-m-d H:i:s');
                        break;
                    }
                }
                if (!$found) {
                    $error = 'Field not found';
                    app_log('not_found', 'Edit non-existent field', ['category_id' => $categoryId, 'field_id' => $fieldId]);
                } else {
                    $result = saveReportCategories($categories);
                    if ($result['success'] === false) {
                        $error = 'Failed to update field: ' . $result['message'];
                        app_log('write_error', 'Failed to update field', ['category_id' => $categoryId, 'field_id' => $fieldId]);
                    } else {
                        $_SESSION['flash_message'] = 'Field updated successfully';
                        header('Location: report_category_fields.php?category_id=' . urlencode($categoryId));
                        exit;
                    }
                }
            }
        } elseif ($action === 'delete_field') {
            $fieldId = $_POST['field_id'] ?? '';
            $before = count($categories[$index]['fields']);
            $categories[$index]['fields'] = array_values(array_filter($categories[$index]['fields'], function ($f) use ($fieldId) {
                return $f['id'] !== $fieldId;
            }));
            $result = saveReportCategories($categories);
            if ($result['success'] === false) {
                $error = 'Failed to delete field: ' . $result['message'];
                app_log('write_error', 'Failed to delete field', ['category_id' => $categoryId, 'field_id' => $fieldId]);
            } else {
                if ($before === count($categories[$index]['fields'])) {
                    $_SESSION['flash_error'] = 'Field not found';
                    app_log('not_found', 'Delete non-existent field', ['category_id' => $categoryId, 'field_id' => $fieldId]);
                } else {
                    $_SESSION['flash_message'] = 'Field deleted';
                }
                header('Location: report_category_fields.php?category_id=' . urlencode($categoryId));
                exit;
            }
        }
    }
}

// Normalize fields for view
$fields = isset($category['fields']) && is_array($category['fields']) ? $category['fields'] : [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Category Fields</title>
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
                <a href="report_categories.php" class="nav-link"><i class="fas fa-arrow-left"></i> Back</a>
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
                    <div class="col-sm-8">
                        <h1 class="m-0">Fields: <?php echo htmlspecialchars($category['name']); ?></h1>
                        <p class="text-muted mb-0">Customize the data fields for this report category.</p>
                    </div>
                    <div class="col-sm-4">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item"><a href="report_categories.php">Report Categories</a></li>
                            <li class="breadcrumb-item active">Fields</li>
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
                            <div class="card-header"><h3 class="card-title">Add Field</h3></div>
                            <form method="post">
                                <div class="card-body">
                                    <?php // Flash messages handled via SweetAlert2 ?>
                                    <input type="hidden" name="action" value="add_field">
                                    <div class="form-group">
                                        <label>Label *</label>
                                        <input type="text" name="label" class="form-control" required>
                                    </div>
                                    <div class="form-group">
                                        <label>Type *</label>
                                        <select name="type" class="form-control" id="add_field_type" onchange="toggleOptions('add')" required>
                                            <?php foreach ($fieldTypes as $type): ?>
                                                <option value="<?php echo htmlspecialchars($type['key']); ?>">
                                                    <?php echo htmlspecialchars($type['label']); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="form-group" id="add_source_group" style="display:none;">
                                        <label>Options Source</label>
                                        <select name="source" class="form-control" id="add_field_source" onchange="toggleOptions('add')">
                                            <option value="manual" selected>Manual (enter options)</option>
                                            <option value="zones_groups">Zones: Groups (from zones.json)</option>
                                        </select>
                                    </div>
                                    <div class="form-group" id="add_options_group" style="display:none;">
                                        <label>Options (one per line or comma-separated)</label>
                                        <textarea name="options" class="form-control" rows="3" placeholder="Option A\nOption B"></textarea>
                                    </div>
                                    <div class="form-group">
                                        <label>Placeholder</label>
                                        <input type="text" name="placeholder" class="form-control" placeholder="Optional placeholder">
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" name="required" id="add_required" class="form-check-input">
                                        <label for="add_required" class="form-check-label">Required</label>
                                    </div>
                                </div>
                                <div class="card-footer">
                                    <button type="submit" class="btn btn-primary"><i class="fas fa-plus"></i> Add Field</button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <div class="col-md-7">
                        <div class="card card-outline card-secondary">
                            <div class="card-header"><h3 class="card-title">Existing Fields</h3></div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped mb-0">
                                        <thead>
                                            <tr>
                                                <th>Label</th>
                                                <th>Type</th>
                                                <th>Required</th>
                                                <th style="width:160px">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                        <?php if (empty($fields)): ?>
                                            <tr><td colspan="4" class="text-center text-muted">No fields yet</td></tr>
                                        <?php else: ?>
                                            <?php foreach ($fields as $f): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($f['label']); ?></td>
                                                <td><?php echo htmlspecialchars($f['type']); ?></td>
                                                <td><?php echo !empty($f['required']) ? 'Yes' : 'No'; ?></td>
                                                <td>
                                                    <button type="button" class="btn btn-sm btn-primary mr-1" data-toggle="modal" data-target="#editFieldModal"
                                                        data-id="<?php echo htmlspecialchars($f['id']); ?>"
                                                        data-label="<?php echo htmlspecialchars($f['label']); ?>"
                                                        data-type="<?php echo htmlspecialchars(($f['type'] === 'select' && ($f['source'] ?? 'manual') === 'zones_groups') ? 'groups' : $f['type']); ?>"
                                                        data-required="<?php echo !empty($f['required']) ? '1' : '0'; ?>"
                                                        data-placeholder="<?php echo htmlspecialchars($f['placeholder'] ?? ''); ?>"
                                                        data-options="<?php echo htmlspecialchars(isset($f['options']) ? implode("\n", (array)$f['options']) : ''); ?>"
                                                        data-source="<?php echo htmlspecialchars($f['source'] ?? 'manual'); ?>">
                                                        <i class="fas fa-edit"></i>
                                                    </button>
                                                    <form method="post" class="d-inline" data-confirm="Delete this field?" data-confirm-title="Delete field" data-confirm-action="Delete">
                                                        <input type="hidden" name="action" value="delete_field">
                                                        <input type="hidden" name="field_id" value="<?php echo htmlspecialchars($f['id']); ?>">
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

    <!-- Edit Field Modal -->
    <div class="modal fade" id="editFieldModal" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Edit Field</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="edit_field">
                        <input type="hidden" name="field_id" id="edit_field_id">
                        <div class="form-group">
                            <label>Label *</label>
                            <input type="text" class="form-control" name="label" id="edit_field_label" required>
                        </div>
                        <div class="form-group">
                            <label>Type *</label>
                            <select name="type" class="form-control" id="edit_field_type" onchange="toggleOptions('edit')" required>
                                <?php foreach ($fieldTypes as $type): ?>
                                    <option value="<?php echo htmlspecialchars($type['key']); ?>">
                                        <?php echo htmlspecialchars($type['label']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group" id="edit_source_group" style="display:none;">
                            <label>Options Source</label>
                            <select name="source" class="form-control" id="edit_field_source" onchange="toggleOptions('edit')">
                                <option value="manual">Manual (enter options)</option>
                                <option value="zones_groups">Zones: Groups (from zones.json)</option>
                            </select>
                        </div>
                        <div class="form-group" id="edit_options_group" style="display:none;">
                            <label>Options (one per line or comma-separated)</label>
                            <textarea name="options" id="edit_field_options" class="form-control" rows="3"></textarea>
                        </div>
                        <div class="form-group">
                            <label>Placeholder</label>
                            <input type="text" class="form-control" name="placeholder" id="edit_field_placeholder" placeholder="Optional placeholder">
                        </div>
                        <div class="form-check">
                            <input type="checkbox" name="required" id="edit_field_required" class="form-check-input">
                            <label for="edit_field_required" class="form-check-label">Required</label>
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
        <strong>&copy; 2024 IPPC Dashboard.</strong> All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script src="assets/js/sweetalert-init.js"></script>
<script>
window.__FLASH_MESSAGES__ = {
    success: <?php echo json_encode($message ?? ''); ?>,
    error: <?php echo json_encode($error ?? ''); ?>,
    errorTitle: 'Error'
};
</script>
<script>
// Field types data from PHP
var fieldTypesData = <?php echo json_encode($fieldTypes); ?>;

function getFieldTypeByKey(key) {
    return fieldTypesData.find(function(type) { return type.key === key; }) || null;
}

function toggleOptions(prefix) {
    var typeSel = document.getElementById(prefix + '_field_type');
    var sourceGroup = document.getElementById(prefix + '_source_group');
    var sourceSel = document.getElementById(prefix + '_field_source');
    var optionsGroup = document.getElementById(prefix + '_options_group');
    if (!typeSel) return;
    
    var selectedType = getFieldTypeByKey(typeSel.value);
    if (!selectedType) return;
    
    var isGroups = selectedType.key === 'groups';
    var isSelect = selectedType.base_type === 'select';
    
    if (sourceGroup) {
        sourceGroup.style.display = isSelect ? '' : 'none';
        // If groups selected, force source to zones_groups and disable the selector
        if (isGroups && sourceSel) {
            sourceSel.value = 'zones_groups';
            sourceSel.disabled = true;
        } else if (sourceSel) {
            sourceSel.disabled = false;
            // Set default source based on field type
            if (selectedType.source) {
                sourceSel.value = selectedType.source;
            }
        }
    }
    if (optionsGroup) {
        var useManual = (!sourceSel || sourceSel.value === 'manual') && !isGroups;
        optionsGroup.style.display = isSelect && useManual ? '' : 'none';
    }
}

$('#editFieldModal').on('show.bs.modal', function (event) {
    var button = $(event.relatedTarget);
    $('#edit_field_id').val(button.data('id'));
    $('#edit_field_label').val(button.data('label'));
    $('#edit_field_type').val(button.data('type'));
    $('#edit_field_placeholder').val(button.data('placeholder'));
    $('#edit_field_required').prop('checked', button.data('required') == '1');
    $('#edit_field_options').val(button.data('options'));
    var src = button.data('source') || 'manual';
    $('#edit_field_source').val(src);
    toggleOptions('edit');
});

// Initialize options visibility on add form
document.addEventListener('DOMContentLoaded', function(){ toggleOptions('add'); });
</script>
</body>
</html>
