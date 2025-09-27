<?php
require_once 'config.php';

session_start();
requireAdmin();
requireCSRFToken();

$categoryId = $_GET['category_id'] ?? '';
$category = getCategoryById($categoryId);
if (!$category) {
    app_log('not_found', 'Category fields page requested for non-existent category', ['category_id' => $categoryId]);
    header('Location: report_categories.php?error=Category not found');
    exit;
}

// Load available field types
$fieldTypes = getFieldTypes();

$csrfToken = generateCSRFToken();

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
                // Normalize "currency" pseudo-type to select + currency
                if ($type === 'groups') {
                    $type = 'select';
                    $source = 'zones_groups';
                } elseif ($type === 'currency') {
                    $type = 'select';
                    $source = 'currency';
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
                        // Normalize "currency" pseudo-type to select + currency
                        if ($type === 'groups') {
                            $type = 'select';
                            $source = 'zones_groups';
                        } elseif ($type === 'currency') {
                            $type = 'select';
                            $source = 'currency';
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
        } elseif ($action === 'reorder_fields') {
            $fieldOrder = $_POST['field_order'] ?? [];
            if (!is_array($fieldOrder) || empty($fieldOrder)) {
                $error = 'Invalid field order data';
                app_log('validation_error', 'Invalid field order', ['category_id' => $categoryId]);
            } else {
                // Create a map of existing fields by ID
                $fieldsById = [];
                foreach ($categories[$index]['fields'] as $field) {
                    $fieldsById[$field['id']] = $field;
                }
                
                // Reorder fields according to the provided order
                $reorderedFields = [];
                foreach ($fieldOrder as $fieldId) {
                    if (isset($fieldsById[$fieldId])) {
                        $reorderedFields[] = $fieldsById[$fieldId];
                    }
                }
                
                // Update the category with reordered fields
                $categories[$index]['fields'] = $reorderedFields;
                
                $result = saveReportCategories($categories);
                if ($result['success'] === false) {
                    $error = 'Failed to reorder fields: ' . $result['message'];
                    app_log('write_error', 'Failed to reorder fields', ['category_id' => $categoryId]);
                } else {
                    app_log('field_reorder', 'Fields reordered', ['category_id' => $categoryId, 'new_order' => $fieldOrder]);
                    echo json_encode(['success' => true, 'message' => 'Fields reordered successfully']);
                    exit;
                }
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
    <style>
    /* Sortable drag and drop styles */
    .sortable-ghost {
        opacity: 0.4;
        background-color: #f8f9fa;
    }
    
    .sortable-chosen {
        background-color: #e3f2fd !important;
    }
    
    .sortable-drag {
        background-color: #fff !important;
        box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        transform: rotate(5deg);
    }
    
    .drag-handle {
        text-align: center;
        vertical-align: middle;
        border-radius: 4px;
        transition: all 0.2s ease;
    }
    
    .drag-handle {
        text-align: center;
        vertical-align: middle;
        border-radius: 4px;
        transition: all 0.2s ease;
        padding: 8px 4px;
    }
    
    .drag-handle:hover {
        background-color: #e3f2fd;
        color: #007bff !important;
    }
    
    .drag-handle:active {
        cursor: grabbing !important;
        background-color: #bbdefb;
    }
    
    
    /* Smooth transitions */
    #sortable-fields tr {
        transition: all 0.2s ease;
    }
    
    /* Disable text selection during drag */
    .sortable-fallback {
        user-select: none;
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
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
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
                                            <option value="currency">Currency (from currency.json)</option>
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
                            <div class="card-header">
                                <h3 class="card-title">Existing Fields</h3>
                                <?php if (!empty($fields)): ?>
                                <div class="card-tools">
                                    <small class="text-muted"><i class="fas fa-arrows-alt"></i> Drag rows to reorder fields</small>
                                </div>
                                <?php endif; ?>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped mb-0">
                                        <thead>
                                            <tr>
                                                <th style="width:30px"></th>
                                                <th>Label</th>
                                                <th>Type</th>
                                                <th>Required</th>
                                                <th style="width:160px">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="sortable-fields">
                                        <?php if (empty($fields)): ?>
                                            <tr><td colspan="5" class="text-center text-muted">No fields yet</td></tr>
                                        <?php else: ?>
                                            <?php foreach ($fields as $index => $f): ?>
                                            <tr data-field-id="<?php echo htmlspecialchars($f['id']); ?>">
                                                <td class="drag-handle" style="cursor: grab;" title="Drag to reorder">
                                                    <i class="fas fa-grip-vertical text-muted"></i>
                                                    <small class="text-muted ml-1"><?php echo $index + 1; ?></small>
                                                </td>
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
                                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
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
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
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
                                <option value="currency">Currency (from currency.json)</option>
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
<script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"></script>
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
var csrfToken = <?php echo json_encode($csrfToken); ?>;

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
    var isCurrency = selectedType.key === 'currency';
    var isQuantity = selectedType.key === 'quantity';
    var isCurrencyAmount = selectedType.key === 'currency_amount';
    var isSelect = selectedType.base_type === 'select';
    
    if (sourceGroup) {
        sourceGroup.style.display = isSelect ? '' : 'none';
        // If groups selected, force source to zones_groups and disable the selector
        // If currency selected, force source to currency and disable the selector
        if (isGroups && sourceSel) {
            sourceSel.value = 'zones_groups';
            sourceSel.disabled = true;
        } else if (isCurrency && sourceSel) {
            sourceSel.value = 'currency';
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
        var useManual = (!sourceSel || sourceSel.value === 'manual') && !isGroups && !isCurrency;
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
document.addEventListener('DOMContentLoaded', function(){ 
    toggleOptions('add');
    initializeSortable();
});

// Initialize sortable functionality
function initializeSortable() {
    const sortableElement = document.getElementById('sortable-fields');
    if (!sortableElement || sortableElement.children.length <= 1) {
        return; // No fields or only one field, no need to initialize
    }
    
    const sortable = new Sortable(sortableElement, {
        handle: '.drag-handle',
        animation: 150,
        ghostClass: 'sortable-ghost',
        chosenClass: 'sortable-chosen',
        dragClass: 'sortable-drag',
        onStart: function(evt) {
            evt.item.style.cursor = 'grabbing';
        },
        onEnd: function(evt) {
            evt.item.style.cursor = 'grab';
            if (evt.oldIndex !== evt.newIndex) {
                updateOrderNumbers();
                saveFieldOrder();
            }
        }
    });
}

// Update order numbers after reordering
function updateOrderNumbers() {
    const fieldRows = document.querySelectorAll('#sortable-fields tr[data-field-id]');
    fieldRows.forEach(function(row, index) {
        const orderNumber = row.querySelector('.drag-handle small');
        if (orderNumber) {
            orderNumber.textContent = index + 1;
        }
    });
}

// Save the new field order
function saveFieldOrder() {
    const fieldRows = document.querySelectorAll('#sortable-fields tr[data-field-id]');
    const fieldOrder = [];
    
    fieldRows.forEach(function(row) {
        const fieldId = row.getAttribute('data-field-id');
        if (fieldId) {
            fieldOrder.push(fieldId);
        }
    });
    
    if (fieldOrder.length === 0) {
        return;
    }
    
    // Show loading indicator
    Swal.fire({
        title: 'Saving order...',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });
    
    // Send AJAX request to save the new order
    const formData = new FormData();
    formData.append('action', 'reorder_fields');
    fieldOrder.forEach(function(fieldId, index) {
        formData.append('field_order[]', fieldId);
    });
    formData.append('csrf_token', csrfToken);
    
    fetch(window.location.href, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        Swal.close();
        if (data.success) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                showConfirmButton: false,
                timer: 2000,
                icon: 'success',
                title: 'Field order saved!'
            });
        } else {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: data.message || 'Failed to save field order'
            });
        }
    })
    .catch(error => {
        Swal.close();
        console.error('Error:', error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: 'Failed to save field order'
        });
    });
}
</script>
</body>
</html>
