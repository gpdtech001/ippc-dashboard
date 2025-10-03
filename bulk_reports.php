<?php
require_once 'config.php';

session_start();
requireLogin();

// Log all requests to this page for debugging
error_log("BULK UPLOAD PAGE: " . $_SERVER['REQUEST_METHOD'] . " request to " . $_SERVER['REQUEST_URI']);
error_log("BULK UPLOAD PAGE: POST data: " . print_r($_POST, true));
error_log("BULK UPLOAD PAGE: GET data: " . print_r($_GET, true));

$user = getUserById($_SESSION['user_id']);
$isAdmin = ($_SESSION['role'] === ROLE_ADMIN);

// Handle flash messages
$message = '';
$error = $_SESSION['flash_error'] ?? '';
$show_results_modal = false;
unset($_SESSION['flash_error']);

// Handle clearing results when modal is closed
if (isset($_GET['clear_results']) && $_GET['clear_results'] == '1') {
    unset($_SESSION['upload_results']);
    header('Location: bulk_reports.php');
    exit;
}

// Check for upload results to show in modal
if (isset($_GET['show_results']) && $_GET['show_results'] == '1' && isset($_SESSION['upload_results'])) {
    error_log("BULK UPLOAD: show_results=1 detected, session upload_results exists");
    $message = $_SESSION['upload_results'];
    $show_results_modal = true;
    error_log("BULK UPLOAD: Modal will be displayed, message length: " . strlen($message));
} else {
    error_log("BULK UPLOAD: Modal conditions not met:");
    error_log("BULK UPLOAD: - show_results GET param: " . ($_GET['show_results'] ?? 'NOT SET'));
    error_log("BULK UPLOAD: - session upload_results: " . (isset($_SESSION['upload_results']) ? 'EXISTS' : 'NOT SET'));
}

// Parse upload results for structured display
$upload_results = null;
if ($message) {
    $upload_results = [
        'total' => 0,
        'created' => [],
        'updated' => [],
        'auto_groups' => [],
        'created_count' => 0,
        'updated_count' => 0,
        'auto_groups_count' => 0,
        'raw_message' => $message
    ];
    
    // Extract auto-created groups details (look for AUTO-CREATED pattern)
    if (preg_match('/AUTO-CREATED (\d+) NEW GROUPS:\s*([\s\S]*?)(?=CREATED|UPDATED|$)/i', $message, $matches)) {
        $upload_results['auto_groups_count'] = (int)$matches[1];
        $auto_groups_text = trim($matches[2]);
        if ($auto_groups_text) {
            $lines = explode("\n", $auto_groups_text);
            foreach ($lines as $line) {
                $line = trim($line);
                // Remove bullet point and clean up
                $line = preg_replace('/^[•\*\-\s]+/', '', $line);
                $line = preg_replace('/\s*\(now available for future uploads\)\s*$/', '', $line);
                if ($line && $line !== '' && !empty($line)) {
                    $upload_results['auto_groups'][] = $line;
                }
            }
        }
    }
    
    // Extract created groups details (look for CREATED pattern)
    if (preg_match('/CREATED (\d+) NEW REPORTS:\s*([\s\S]*?)(?=UPDATED|$)/i', $message, $matches)) {
        $upload_results['created_count'] = (int)$matches[1];
        $created_text = trim($matches[2]);
        if ($created_text) {
            $lines = explode("\n", $created_text);
            foreach ($lines as $line) {
                $line = trim($line);
                // Remove bullet point and clean up
                $line = preg_replace('/^[•\*\-\s]+/', '', $line);
                if ($line && $line !== '' && !empty($line)) {
                    $upload_results['created'][] = $line;
                }
            }
        }
    }
    
    // Extract updated groups details (look for UPDATED pattern)
    if (preg_match('/UPDATED (\d+) EXISTING REPORTS:\s*([\s\S]*?)$/i', $message, $matches)) {
        $upload_results['updated_count'] = (int)$matches[1];
        $updated_text = trim($matches[2]);
        if ($updated_text) {
            $lines = explode("\n", $updated_text);
            foreach ($lines as $line) {
                $line = trim($line);
                // Remove bullet point and clean up
                $line = preg_replace('/^[•\*\-\s]+/', '', $line);
                if ($line && $line !== '' && !empty($line)) {
                    $upload_results['updated'][] = $line;
                }
            }
        }
    }
    
    // Calculate total from created + updated counts
    $upload_results['total'] = $upload_results['created_count'] + $upload_results['updated_count'];
}

// Generate CSRF token for form security
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle bulk upload with proper PRG pattern
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'bulk_upload') {
    error_log("BULK UPLOAD: POST request received with action=bulk_upload");
    error_log("BULK UPLOAD: Session user_id: " . ($_SESSION['user_id'] ?? 'NOT SET'));
    error_log("BULK UPLOAD: CSRF token check - POST: " . (isset($_POST['csrf_token']) ? 'SET' : 'NOT SET'));
    error_log("BULK UPLOAD: CSRF token check - SESSION: " . (isset($_SESSION['csrf_token']) ? 'SET' : 'NOT SET'));
    
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("BULK UPLOAD: CSRF token validation FAILED");
        $_SESSION['flash_error'] = 'Security token mismatch. Please try again.';
        header('Location: bulk_reports.php?error=1');
        exit;
    }
    
    error_log("BULK UPLOAD: CSRF token validation PASSED");
    
    // Generate a unique token to prevent duplicate submissions
    $uploadToken = bin2hex(random_bytes(16));
    
    $categoryId = $_POST['category_id'] ?? '';
    error_log("BULK UPLOAD: Category ID received: '" . $categoryId . "'");
    
    if (empty($categoryId)) {
        error_log("BULK UPLOAD: ERROR - No category selected");
        $_SESSION['flash_error'] = 'Please select a report category';
        header('Location: bulk_reports.php?error=1&token=' . $uploadToken);
        exit;
    }
    
    error_log("BULK UPLOAD: File upload check - FILES isset: " . (isset($_FILES['csv_file']) ? 'YES' : 'NO'));
    if (isset($_FILES['csv_file'])) {
        error_log("BULK UPLOAD: File error code: " . ($_FILES['csv_file']['error'] ?? 'NOT SET'));
        error_log("BULK UPLOAD: File name: " . ($_FILES['csv_file']['name'] ?? 'NOT SET'));
        error_log("BULK UPLOAD: File size: " . ($_FILES['csv_file']['size'] ?? 'NOT SET'));
    }
    
    if (!isset($_FILES['csv_file']) || $_FILES['csv_file']['error'] !== UPLOAD_ERR_OK) {
        error_log("BULK UPLOAD: ERROR - File upload failed or missing");
        $_SESSION['flash_error'] = 'Please upload a valid CSV file';
        header('Location: bulk_reports.php?error=1&token=' . $uploadToken);
        exit;
    } else {
        $uploadedFile = $_FILES['csv_file'];
        error_log("BULK UPLOAD: Processing file: " . $uploadedFile['name']);
        error_log("BULK UPLOAD: Temp file path: " . $uploadedFile['tmp_name']);
        
        // Validate file type
        $fileExtension = pathinfo($uploadedFile['name'], PATHINFO_EXTENSION);
        error_log("BULK UPLOAD: File extension: " . $fileExtension);
        
        if ($fileExtension !== 'csv') {
            error_log("BULK UPLOAD: ERROR - Invalid file type: " . $fileExtension);
            $_SESSION['flash_error'] = 'Please upload a CSV file only';
            header('Location: bulk_reports.php?error=1&token=' . $uploadToken);
            exit;
        } else {
            error_log("BULK UPLOAD: Calling processBulkUpload with user_id: " . $_SESSION['user_id']);
            $result = processBulkUpload($uploadedFile['tmp_name'], $categoryId, $_SESSION['user_id']);
            
            error_log("BULK UPLOAD: processBulkUpload returned - success: " . ($result['success'] ? 'YES' : 'NO'));
            error_log("BULK UPLOAD: processBulkUpload message length: " . strlen($result['message'] ?? ''));
            
            if ($result['success']) {
                error_log("BULK UPLOAD: SUCCESS - Setting session and redirecting to show_results");
                $_SESSION['upload_results'] = $result['message'];
                // Regenerate CSRF token to prevent reuse
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                header('Location: bulk_reports.php?show_results=1&token=' . $uploadToken);
                exit;
            } else {
                error_log("BULK UPLOAD: ERROR - Setting flash_error and redirecting");
                error_log("BULK UPLOAD: Error message: " . substr($result['message'], 0, 200));
                $_SESSION['flash_error'] = $result['message'];
                // Regenerate CSRF token even on error to prevent reuse
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                header('Location: bulk_reports.php?error=1&token=' . $uploadToken);
                exit;
            }
        }
    }
}

// Load report categories
$categories = getReportCategories();
$currencies = [];
$currencyFile = __DIR__ . '/currency.json';
if (file_exists($currencyFile)) {
    $currencies = json_decode(@file_get_contents($currencyFile), true) ?: [];
}
$currencySettings = getCurrencySettings();
$preferredCurrencyCode = $currencySettings['base_currency']['code'] ?? ($currencies[0]['code'] ?? 'E');

// Filter categories based on user permissions if needed
if (!$isAdmin) {
    // RZMs can upload to all categories, but we might add restrictions later
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Bulk Report Upload</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <style>
        .upload-area {
            border: 2px dashed #dee2e6;
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            transition: all 0.3s ease;
            background-color: #f8f9fa;
        }
        .upload-area:hover {
            border-color: #007bff;
            background-color: #e7f3ff;
        }
        .upload-area.dragover {
            border-color: #28a745;
            background-color: #e8f5e9;
        }
        .template-card {
            transition: transform 0.2s ease;
            border: 1px solid #dee2e6;
        }
        .template-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .category-info {
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 10px;
            margin-bottom: 15px;
        }
        .field-preview {
            max-height: 200px;
            overflow-y: auto;
        }
        .field-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        .field-item:last-child {
            border-bottom: none;
        }
        .field-type-badge {
            font-size: 0.75em;
            padding: 2px 6px;
            border-radius: 3px;
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
                        <h1 class="m-0">Bulk Report Upload</h1>
                        <p class="text-muted mb-0">Upload multiple reports from Excel or CSV files</p>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item"><a href="reports.php">Reports</a></li>
                            <li class="breadcrumb-item active">Bulk Upload</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <!-- Group Management CTA -->
                <div class="row">
                    <div class="col-12">
                        <div class="alert alert-warning alert-dismissible border-left-warning" style="background-color: #fff3cd; border: 1px solid #ffeaa7;">
                            <button type="button" class="close" data-dismiss="alert" aria-hidden="true" style="color: #856404;">&times;</button>
                            <div class="row align-items-center">
                                <div class="col-md-8">
                                    <h5 class="mb-2" style="color: #856404;">
                                        <i class="fas fa-users-cog text-warning mr-2"></i>
                                        <strong>Important: Keep Your Groups Updated!</strong>
                                    </h5>
                                    <p class="mb-0" style="color: #856404;">
                                        Before downloading templates, make sure all your groups are properly set up. 
                                        Your templates will be pre-filled with the groups you have configured. 
                                        Missing a group? Add it now!
                                    </p>
                                </div>
                                <div class="col-md-4 text-right">
                                    <?php if (isset($_SESSION['role']) && ($_SESSION['role'] === ROLE_ADMIN || $_SESSION['role'] === 'rzm')): ?>
                                        <a href="groups_management.php" class="btn btn-primary btn-lg">
                                            <i class="fas fa-users-cog mr-1"></i>
                                            <strong>Manage Groups Now</strong>
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Step 1: Download Template -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-primary">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-download mr-2"></i>
                                    Step 1: Download Upload Template
                                </h3>
                                <div class="card-tools">
                                    <button type="button" class="btn btn-tool" data-card-widget="collapse">
                                        <i class="fas fa-minus"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-center mb-4">
                                    <p class="text-muted mb-0">
                                        Choose a report category and download the template with your groups pre-filled.
                                    </p>
                                    <a href="currencies.php" class="btn btn-outline-info btn-sm" target="_blank">
                                        <i class="fas fa-coins mr-1"></i>
                                        View Currencies
                                    </a>
                                </div>

                                <?php if (empty($categories)): ?>
                                    <div class="alert alert-info">
                                        <i class="fas fa-info-circle mr-2"></i>
                                        No report categories are available. Please ask an administrator to create report categories first.
                                    </div>
                                <?php else: ?>
                                    <div class="row">
                                        <?php foreach ($categories as $category): ?>
                                            <?php
                                            // Apply currency field fixes and automatic currency field addition for display
                                            $categoryWithFields = fixCurrencyFields($category);
                                            $categoryWithFields = addAutomaticCurrencyField($categoryWithFields);
                                            $fields = $categoryWithFields['fields'] ?? [];
                                            $nonAutoFields = array_filter($fields, function($f) {
                                                return $f['type'] !== 'auto_currency';
                                            });
                                            ?>
                                            <div class="col-md-6 col-lg-4 mb-4">
                                                <div class="template-card card h-100">
                                                    <div class="card-header bg-light">
                                                        <h5 class="card-title mb-0">
                                                            <i class="fas fa-file-alt text-primary mr-2"></i>
                                                            <?php echo htmlspecialchars($category['name']); ?>
                                                        </h5>
                                                    </div>
                                                    <div class="card-body">
                                                        <?php if (!empty($category['description'])): ?>
                                                            <p class="text-muted small mb-3">
                                                                <?php echo htmlspecialchars($category['description']); ?>
                                                            </p>
                                                        <?php endif; ?>

                                                        <div class="category-info">
                                                            <div class="d-flex justify-content-between align-items-center mb-2">
                                                                <span class="font-weight-bold">Fields:</span>
                                                                <span class="badge badge-secondary"><?php echo count($nonAutoFields); ?> fields</span>
                                                            </div>
                                                            
                                                            <div class="field-preview">
                                                                <?php foreach (array_slice($nonAutoFields, 0, 5) as $field): ?>
                                                                    <div class="field-item">
                                                                        <span class="text-sm">
                                                                            <?php echo htmlspecialchars($field['label'] ?? $field['id']); ?>
                                                                            <?php if ($field['required'] ?? false): ?>
                                                                                <i class="fas fa-asterisk text-danger" style="font-size: 0.6em;"></i>
                                                                            <?php endif; ?>
                                                                        </span>
                                                                        <span class="field-type-badge badge badge-light">
                                                                            <?php echo htmlspecialchars($field['type']); ?>
                                                                        </span>
                                                                    </div>
                                                                <?php endforeach; ?>
                                                                
                                                                <?php if (count($nonAutoFields) > 5): ?>
                                                                    <div class="text-center text-muted small mt-2">
                                                                        ... and <?php echo count($nonAutoFields) - 5; ?> more fields
                                                                    </div>
                                                                <?php endif; ?>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div class="card-footer bg-white">
                                                        <div class="d-flex flex-column flex-sm-row">
                                                            <button type="button"
                                                                    class="btn btn-success btn-block mb-2 mb-sm-0 mr-sm-2 download-template-btn"
                                                                    data-category-id="<?php echo htmlspecialchars($category['id']); ?>"
                                                                    data-category-name="<?php echo htmlspecialchars($category['name']); ?>">
                                                                <i class="fas fa-download mr-2"></i>
                                                                Download Template
                                                            </button>
                                                            <a href="report_category_fields.php?category_id=<?php echo urlencode($category['id']); ?>"
                                                               class="btn btn-outline-secondary btn-block">
                                                                <i class="fas fa-sliders-h mr-2"></i>
                                                                Manage Fields
                                                            </a>
                                                        </div>
                                                        <div class="text-center mt-2">
                                                            <small class="text-muted">
                                                                <i class="fas fa-info-circle mr-1"></i>
                                                                Pre-filled with your groups
                                                            </small>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Template Download Modal -->
                <div class="modal fade" id="templateDownloadModal" tabindex="-1" role="dialog" aria-hidden="true">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <form id="templateDownloadForm" method="get" action="report_template_download.php">
                                <div class="modal-header">
                                    <h5 class="modal-title">
                                        <i class="fas fa-file-download mr-2"></i>
                                        Download Template
                                    </h5>
                                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                        <span aria-hidden="true">&times;</span>
                                    </button>
                                </div>
                                <div class="modal-body">
                                    <input type="hidden" name="category" id="templateCategoryInput">
                                    <div class="form-group">
                                        <label for="templateCategoryLabel">Report Category</label>
                                        <input type="text" class="form-control" id="templateCategoryLabel" readonly>
                                    </div>
                                    <div class="form-group">
                                        <label for="templateCurrencySelect">Default Currency</label>
                                        <select class="form-control" name="currency" id="templateCurrencySelect" required data-preferred="<?php echo htmlspecialchars($preferredCurrencyCode); ?>">
                                            <?php if (!empty($currencies)): ?>
                                                <?php foreach ($currencies as $currency): ?>
                                                    <option value="<?php echo htmlspecialchars($currency['code']); ?>" <?php echo ($currency['code'] === $preferredCurrencyCode) ? 'selected' : ''; ?>>
                                                        <?php echo htmlspecialchars($currency['code'] . ' - ' . $currency['name']); ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <option value="E" selected>E - Espees</option>
                                            <?php endif; ?>
                                        </select>
                                        <small class="form-text text-muted">
                                            This value will pre-fill all currency fields in the downloaded template.
                                        </small>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-success">
                                        <i class="fas fa-download mr-2"></i>Download
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Step 2: Upload Your Completed File -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-success">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-upload mr-2"></i>
                                    Step 2: Upload Your Completed File
                                </h3>
                                <div class="card-tools">
                                    <button type="button" class="btn btn-tool" data-card-widget="collapse">
                                        <i class="fas fa-minus"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="card-body">
                                <form id="bulkUploadForm" method="POST" enctype="multipart/form-data">
                                    <input type="hidden" name="action" value="bulk_upload">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="form-group">
                                                <label for="category_select">Select Report Category <span class="text-danger">*</span></label>
                                                <select class="form-control" id="category_select" name="category_id" required>
                                                    <option value="">Choose the category for your reports...</option>
                                                    <?php foreach ($categories as $category): ?>
                                                        <option value="<?php echo htmlspecialchars($category['id']); ?>">
                                                            <?php echo htmlspecialchars($category['name']); ?>
                                                        </option>
                                                    <?php endforeach; ?>
                                                </select>
                                                <small class="form-text text-muted">
                                                    Make sure this matches the category you used for the template download.
                                                </small>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="form-group">
                                                <label for="csv_file">Upload CSV File <span class="text-danger">*</span></label>
                                                <div class="custom-file">
                                                    <input type="file" class="custom-file-input" id="csv_file" name="csv_file" accept=".csv" required>
                                                    <label class="custom-file-label" for="csv_file">Choose CSV file...</label>
                                                </div>
                                                <small class="form-text text-muted">
                                                    Upload the completed CSV template you downloaded and filled out.
                                                </small>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="row">
                                        <div class="col-12">
                                            <div class="alert alert-info">
                                                <h5><i class="fas fa-info-circle mr-2"></i>Before You Upload:</h5>
                                                <ul class="mb-0">
                                                    <li>Make sure you've filled out all required fields in your CSV</li>
                                                    <li>Remove any instruction rows or comments from the file</li>
                                                    <li>Verify that group names and currency codes are correct</li>
                                                    <li>Save your file as a CSV format (not Excel)</li>
                                                </ul>
                                            </div>
                                            
                                            <div class="alert alert-success">
                                                <h5><i class="fas fa-sync-alt mr-2"></i>Smart Updates:</h5>
                                                <p class="mb-0">
                                                    <strong>New Groups:</strong> Will be added as new reports<br>
                                                    <strong>Existing Groups:</strong> Will update your previous submission with the new data
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="row">
                                        <div class="col-12 text-center">
                                            <button type="submit" class="btn btn-success btn-lg" id="uploadBtn">
                                                <i class="fas fa-cloud-upload-alt mr-2"></i>
                                                Process Bulk Upload
                                            </button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                                </div>

                                <!-- Placeholder for future upload interface -->
                                <div class="upload-area" id="upload-area" style="opacity: 0.5;">
                                    <i class="fas fa-cloud-upload-alt fa-3x text-muted mb-3"></i>
                                    <h4 class="text-muted">Drag & Drop Your File Here</h4>
                                    <p class="text-muted mb-3">or click to browse files</p>
                                    <input type="file" id="file-input" accept=".xlsx,.xls,.csv" style="display: none;" disabled>
                                    <button type="button" class="btn btn-primary" disabled>
                                        <i class="fas fa-folder-open mr-2"></i>Choose File
                                    </button>
                                    <div class="mt-3">
                                        <small class="text-muted">Supported formats: CSV (.csv) - works with Excel, Google Sheets, etc.</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>


                <!-- Instructions -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-secondary">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-question-circle mr-2"></i>
                                    How to Use Bulk Upload
                                </h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h5><i class="fas fa-list-ol text-primary mr-2"></i>How to Use:</h5>
                                        <ol class="pl-3">
                                            <li class="mb-2">
                                                <strong>Download Template:</strong> Click the template for your category
                                            </li>
                                            <li class="mb-2">
                                                <strong>Update Values:</strong> Change the sample data in each row to your actual data
                                            </li>
                                            <li class="mb-2">
                                                <strong>Upload File:</strong> Upload your completed file (coming soon)
                                            </li>
                                        </ol>
                                    </div>
                                    <div class="col-md-6">
                                        <h5><i class="fas fa-info-circle text-info mr-2"></i>Template Features:</h5>
                                        <ul class="pl-3">
                                            <li class="mb-2">
                                                <strong>Pre-filled Groups:</strong> All your available groups are already listed
                                            </li>
                                            <li class="mb-2">
                                                <strong>Sample Data:</strong> Each field shows example values to guide you
                                            </li>
                                            <li class="mb-2">
                                                <strong>Excel Compatible:</strong> Opens perfectly in Excel, Google Sheets, etc.
                                            </li>
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
        <strong>&copy; 2024 IPPC Dashboard.</strong> All rights reserved.
    </footer>
</div>

<!-- Upload Results Modal -->
<?php if ($show_results_modal && $upload_results): ?>
<div class="modal fade" id="uploadResultsModal" tabindex="-1" role="dialog" aria-labelledby="uploadResultsModalLabel" aria-hidden="true" data-backdrop="static" data-keyboard="false">
    <div class="modal-dialog modal-xl" role="document">
        <div class="modal-content">
            <div class="modal-header bg-success text-white">
                <h4 class="modal-title" id="uploadResultsModalLabel">
                    <i class="fas fa-check-circle mr-2"></i>
                    Bulk Upload Completed Successfully!
                </h4>
            </div>
            <div class="modal-body">
                <!-- Summary Stats -->
                <div class="row mb-4">
                    <div class="col-md-4">
                        <div class="info-box bg-success">
                            <span class="info-box-icon"><i class="fas fa-check"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Total Processed</span>
                                <span class="info-box-number"><?php echo $upload_results['total']; ?> groups</span>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="info-box bg-primary">
                            <span class="info-box-icon"><i class="fas fa-plus"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">New Reports</span>
                                <span class="info-box-number"><?php echo $upload_results['created_count']; ?></span>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="info-box bg-warning">
                            <span class="info-box-icon"><i class="fas fa-sync"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Updated Reports</span>
                                <span class="info-box-number"><?php echo $upload_results['updated_count']; ?></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Auto-Created Groups -->
                <?php if (!empty($upload_results['auto_groups'])): ?>
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="alert alert-info">
                            <h5><i class="fas fa-magic mr-2"></i>New Groups Automatically Created</h5>
                            <p class="mb-2">The following groups from your CSV were automatically added to your zone and are now available for future uploads:</p>
                            <ul class="mb-0">
                                <?php foreach ($upload_results['auto_groups'] as $group_name): ?>
                                <li><strong><?php echo htmlspecialchars($group_name); ?></strong></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <!-- Detailed Results -->
                <?php if (!empty($upload_results['created']) || !empty($upload_results['updated'])): ?>
                <div class="row">
                    <?php if (!empty($upload_results['created'])): ?>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="card-title mb-0">
                                    <i class="fas fa-plus-circle mr-2"></i>
                                    New Reports Created (<?php echo count($upload_results['created']); ?>)
                                </h5>
                            </div>
                            <div class="card-body p-0" style="max-height: 300px; overflow-y: auto;">
                                <ul class="list-group list-group-flush">
                                    <?php foreach ($upload_results['created'] as $group_info): ?>
                                    <li class="list-group-item">
                                        <i class="fas fa-users text-primary mr-2"></i>
                                        <?php echo htmlspecialchars($group_info); ?>
                                    </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                    <?php if (!empty($upload_results['updated'])): ?>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-warning text-white">
                                <h5 class="card-title mb-0">
                                    <i class="fas fa-sync-alt mr-2"></i>
                                    Reports Updated (<?php echo count($upload_results['updated']); ?>)
                                </h5>
                            </div>
                            <div class="card-body p-0" style="max-height: 300px; overflow-y: auto;">
                                <ul class="list-group list-group-flush">
                                    <?php foreach ($upload_results['updated'] as $group_info): ?>
                                    <li class="list-group-item">
                                        <i class="fas fa-users text-warning mr-2"></i>
                                        <?php echo htmlspecialchars($group_info); ?>
                                    </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            </div>
            <div class="modal-footer">
                <div class="row w-100">
                    <div class="col-md-6">
                        <a href="reports.php" class="btn btn-primary btn-lg btn-block">
                            <i class="fas fa-table mr-2"></i>
                            View All Reports
                        </a>
                    </div>
                    <div class="col-md-6">
                        <button type="button" class="btn btn-success btn-lg btn-block" data-dismiss="modal" onclick="closeResultsModal()">
                            <i class="fas fa-check mr-2"></i>
                            Close & Upload Another
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<script>
// Function to close the results modal and clear session
function closeResultsModal() {
    $('#uploadResultsModal').modal('hide');
    window.location.href = 'bulk_reports.php?clear_results=1';
}

// Auto-show upload results modal if flagged
<?php if ($show_results_modal): ?>
$(document).ready(function() {
    $('#uploadResultsModal').modal('show');
});
<?php endif; ?>

<?php if ($error): ?>
Swal.fire({
    icon: 'error',
    title: 'Upload Failed',
    html: '<div style="text-align: left; max-height: 400px; overflow-y: auto;"><pre style="font-size: 11px; white-space: pre-wrap;"><?php echo htmlspecialchars($error); ?></pre></div>',
    width: '80%',
    showConfirmButton: true,
    confirmButtonText: 'OK'
});
<?php endif; ?>

// Future: Drag and drop functionality
$(document).ready(function() {
    // Template card hover effects
    $('.template-card').hover(
        function() {
            $(this).find('.card-footer .btn').addClass('btn-hover');
        },
        function() {
            $(this).find('.card-footer .btn').removeClass('btn-hover');
        }
    );

    const $currencySelect = $('#templateCurrencySelect');
    if ($currencySelect.length) {
        const preferred = $currencySelect.data('preferred');
        if (preferred && $currencySelect.find(`option[value="${preferred}"]`).length) {
            $currencySelect.val(preferred);
        }
    }

    // Handle template download modal
    $('.download-template-btn').on('click', function() {
        const categoryId = $(this).data('category-id');
        const categoryName = $(this).data('category-name');
        $('#templateCategoryInput').val(categoryId);
        $('#templateCategoryLabel').val(categoryName);

        if ($currencySelect.length) {
            const preferred = $currencySelect.data('preferred');
            if (preferred && $currencySelect.find(`option[value="${preferred}"]`).length) {
                $currencySelect.val(preferred);
            } else {
                $currencySelect.prop('selectedIndex', 0);
            }
        }

        $('#templateDownloadModal').modal('show');
    });

    $('#templateDownloadForm').on('submit', function() {
        $('#templateDownloadModal').modal('hide');
        setTimeout(function() {
            Swal.fire({
                toast: true,
                position: 'top-end',
                showConfirmButton: false,
                timer: 2000,
                timerProgressBar: true,
                icon: 'success',
                title: 'Template download started'
            });
        }, 400);
    });
    
    // Handle file upload UI
    $('.custom-file-input').on('change', function() {
        const fileName = $(this).val().split('\\').pop();
        $(this).siblings('.custom-file-label').addClass('selected').html(fileName);
    });
    
    // Prevent form resubmission on page refresh/back button
    let formSubmitted = false;
    
    // Handle bulk upload form submission
    $('#bulkUploadForm').on('submit', function(e) {
        // Prevent double submission
        if (formSubmitted) {
            e.preventDefault();
            return false;
        }
        
        const fileInput = $('#csv_file')[0];
        const categorySelect = $('#category_select');
        
        if (!fileInput.files.length) {
            e.preventDefault();
            Swal.fire({
                icon: 'error',
                title: 'No File Selected',
                text: 'Please select a CSV file to upload.'
            });
            return;
        }
        
        if (!categorySelect.val()) {
            e.preventDefault();
            Swal.fire({
                icon: 'error',
                title: 'No Category Selected',
                text: 'Please select the report category that matches your CSV file.'
            });
            return;
        }
        
        // Mark form as submitted
        formSubmitted = true;
        
        // Show processing indicator
        const uploadBtn = $('#uploadBtn');
        uploadBtn.prop('disabled', true);
        uploadBtn.html('<i class="fas fa-spinner fa-spin mr-2"></i>Processing Upload...');
        
        // Show processing message
        Swal.fire({
            title: 'Processing Your Upload',
            text: 'Please wait while we process your CSV file...',
            allowOutsideClick: false,
            allowEscapeKey: false,
            showConfirmButton: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        // Disable the form inputs AFTER showing the processing message to prevent interaction
        // but not before form submission (which would prevent data from being sent)
        setTimeout(() => {
            $('#bulkUploadForm input, #bulkUploadForm select').prop('disabled', true);
        }, 100);
    });
    
    // Prevent back button form resubmission
    window.addEventListener('pageshow', function(event) {
        if (event.persisted || formSubmitted) {
            // Page was loaded from cache (back button) or form was already submitted
            // Reset the form state
            $('#bulkUploadForm')[0].reset();
            $('#uploadBtn').prop('disabled', false).html('<i class="fas fa-cloud-upload-alt mr-2"></i>Process Bulk Upload');
            $('#bulkUploadForm input, #bulkUploadForm select, #bulkUploadForm button').prop('disabled', false);
            $('.custom-file-label').removeClass('selected').html('Choose CSV file...');
            formSubmitted = false;
        }
    });
});
</script>
</body>
</html>
