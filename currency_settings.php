<?php
require_once 'config.php';

session_start();
requireAdmin();

$user = getUserById($_SESSION['user_id']);
$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

// Load current settings
$settings = getCurrencySettings();
$currencies = json_decode(file_get_contents(__DIR__ . '/currency.json'), true);

// Sort currencies alphabetically by name, but keep Espees (E) at the top
$espees = [];
$otherCurrencies = [];

foreach ($currencies as $currency) {
    if ($currency['code'] === 'E') {
        $espees[] = $currency;
    } else {
        $otherCurrencies[] = $currency;
    }
}

// Sort other currencies alphabetically by name
usort($otherCurrencies, function($a, $b) {
    return strcmp($a['name'], $b['name']);
});

// Combine with Espees first, then alphabetical currencies
$currencies = array_merge($espees, $otherCurrencies);

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'update_rates') {
        $newRates = [];
        $hasErrors = false;
        $errors = [];
        
        // Start with existing rates to preserve unchanged currencies
        $newRates = $settings['exchange_rates'] ?? [];
        
        // Validate and process each exchange rate
        foreach ($currencies as $currency) {
            $code = $currency['code'];
            $rate = $_POST['rate_' . $code] ?? '';
            
            if ($code === 'E') {
                $newRates[$code] = 1.0; // Base currency is always 1
                continue;
            }
            
            // Skip validation if rate field is empty (preserve existing rate)
            if (empty($rate)) {
                // Keep existing rate if no new rate provided
                if (!isset($newRates[$code])) {
                    $newRates[$code] = 1.0; // Default rate if none exists
                }
                continue;
            }
            
            // Validate only provided rates
            $rate = (float)$rate;
            if ($rate <= 0) {
                $errors[] = "Exchange rate for {$currency['name']} ({$code}) must be greater than 0";
                $hasErrors = true;
            } else {
                $newRates[$code] = $rate;
            }
        }
        
        if ($hasErrors) {
            $error = implode('; ', $errors);
            app_log('validation_error', 'Currency settings validation failed', ['errors' => $errors]);
        } else {
            // Update settings
            $settings['exchange_rates'] = $newRates;
            $settings['updated_by'] = $_SESSION['user_id'];
            
            $result = saveCurrencySettings($settings);
            if ($result['success']) {
                $_SESSION['flash_message'] = 'Exchange rates updated successfully';
                app_log('currency_update', 'Currency exchange rates updated', [
                    'updated_by' => $_SESSION['user_id'],
                    'rates_count' => count($newRates)
                ]);
                header('Location: currency_settings.php');
                exit;
            } else {
                $error = $result['message'];
            }
        }
    } elseif ($action === 'bulk_update') {
        $multiplier = (float)($_POST['multiplier'] ?? 1);
        $selectedCurrencies = $_POST['selected_currencies'] ?? [];
        
        if (empty($selectedCurrencies)) {
            $error = 'Please select at least one currency to update';
        } elseif ($multiplier <= 0) {
            $error = 'Multiplier must be greater than 0';
        } else {
            $rates = $settings['exchange_rates'];
            $updated = 0;
            
            foreach ($selectedCurrencies as $code) {
                if ($code !== 'E' && isset($rates[$code])) {
                    $rates[$code] = $rates[$code] * $multiplier;
                    $updated++;
                }
            }
            
            if ($updated > 0) {
                $settings['exchange_rates'] = $rates;
                $settings['updated_by'] = $_SESSION['user_id'];
                
                $result = saveCurrencySettings($settings);
                if ($result['success']) {
                    $_SESSION['flash_message'] = "Bulk updated {$updated} exchange rates";
                    app_log('currency_bulk_update', 'Bulk currency rate update', [
                        'multiplier' => $multiplier,
                        'currencies' => $selectedCurrencies,
                        'updated_count' => $updated
                    ]);
                    header('Location: currency_settings.php');
                    exit;
                } else {
                    $error = $result['message'];
                }
            } else {
                $error = 'No currencies were updated';
            }
        }
    }
}

// Reload settings after any updates
$settings = getCurrencySettings();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Currency Settings</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <style>
    .rate-input {
        width: 140px;
        text-align: right;
    }
    .currency-row:hover {
        background-color: #f8f9fa;
    }
    .base-currency {
        background-color: #e8f5e8;
        font-weight: bold;
    }
    .bulk-actions {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 20px;
    }
    .conversion-preview {
        background-color: #e3f2fd;
        border-radius: 8px;
        padding: 15px;
        margin-top: 10px;
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
                        <h1 class="m-0">Currency Conversion Settings</h1>
                        <p class="text-muted mb-0">Manage exchange rates to <strong>Espees (E)</strong> - the base currency for analytics</p>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Currency Settings</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <!-- Info Box -->
                <div class="row">
                    <div class="col-md-3 col-sm-6 col-12">
                        <div class="info-box">
                            <span class="info-box-icon bg-info"><i class="fas fa-coins"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Base Currency</span>
                                <span class="info-box-number">Espees (E)</span>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-sm-6 col-12">
                        <div class="info-box">
                            <span class="info-box-icon bg-success"><i class="fas fa-exchange-alt"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Exchange Rates</span>
                                <span class="info-box-number"><?php echo count($settings['exchange_rates'] ?? []); ?></span>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-sm-6 col-12">
                        <div class="info-box">
                            <span class="info-box-icon bg-warning"><i class="fas fa-clock"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Last Updated</span>
                                <span class="info-box-number text-sm">
                                    <?php 
                                    $lastUpdated = $settings['last_updated'] ?? '';
                                    if ($lastUpdated) {
                                        echo date('M j, Y', strtotime($lastUpdated));
                                    } else {
                                        echo 'Never';
                                    }
                                    ?>
                                </span>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-sm-6 col-12">
                        <div class="info-box">
                            <span class="info-box-icon bg-danger"><i class="fas fa-calculator"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Conversion Tool</span>
                                <span class="info-box-number text-sm">
                                    <button class="btn btn-sm btn-outline-primary" onclick="showConverter()">
                                        <i class="fas fa-calculator"></i> Open
                                    </button>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Bulk Actions -->
                <div class="bulk-actions">
                    <form method="post" id="bulkForm">
                        <input type="hidden" name="action" value="bulk_update">
                        <div class="row align-items-center">
                            <div class="col-md-4">
                                <label class="mb-0"><strong>Bulk Update Selected Currencies:</strong></label>
                            </div>
                            <div class="col-md-3">
                                <div class="input-group">
                                    <input type="number" name="multiplier" class="form-control" step="0.001" min="0.001" value="1.0" placeholder="Multiplier">
                                    <div class="input-group-append">
                                        <span class="input-group-text">×</span>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <button type="submit" class="btn btn-warning btn-block" onclick="return confirmBulkUpdate()">
                                    <i class="fas fa-bolt"></i> Apply Multiplier
                                </button>
                            </div>
                            <div class="col-md-2">
                                <button type="button" class="btn btn-outline-secondary btn-block" onclick="selectAllCurrencies()">
                                    <i class="fas fa-check-square"></i> Select All
                                </button>
                            </div>
                        </div>
                    </form>
                </div>

                <!-- Exchange Rates Table -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Exchange Rates (1 unit = X Espees)</h3>
                        <div class="card-tools">
                            <button type="button" class="btn btn-tool" data-card-widget="collapse">
                                <i class="fas fa-minus"></i>
                            </button>
                        </div>
                    </div>
                    <div class="card-body p-0">
                        <form method="post">
                            <input type="hidden" name="action" value="update_rates">
                            <div class="table-responsive" style="max-height: 600px;">
                                <table class="table table-striped table-hover mb-0">
                                    <thead class="thead-light sticky-top">
                                        <tr>
                                            <th width="40px">
                                                <input type="checkbox" id="selectAll" onchange="toggleAllCheckboxes()">
                                            </th>
                                            <th>Currency</th>
                                            <th>Code</th>
                                            <th>Country</th>
                                            <th width="150px">1 Unit = ? Espees</th>
                                            <th width="120px">Preview</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($currencies as $currency): ?>
                                            <?php 
                                            $code = $currency['code'];
                                            $rate = $settings['exchange_rates'][$code] ?? 1;
                                            $isBase = $code === 'E';
                                            ?>
                                            <tr class="currency-row <?php echo $isBase ? 'base-currency' : ''; ?>">
                                                <td>
                                                    <?php if (!$isBase): ?>
                                                        <input type="checkbox" name="selected_currencies[]" value="<?php echo htmlspecialchars($code); ?>" class="currency-checkbox">
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <strong><?php echo htmlspecialchars($currency['name']); ?></strong>
                                                    <span class="text-muted"><?php echo htmlspecialchars($currency['symbol']); ?></span>
                                                    <?php if ($isBase): ?>
                                                        <span class="badge badge-success ml-2">Base Currency</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td><code><?php echo htmlspecialchars($code); ?></code></td>
                                                <td class="text-muted"><?php echo htmlspecialchars($currency['country']); ?></td>
                                                <td>
                                                    <?php if ($isBase): ?>
                                                        <input type="hidden" name="rate_<?php echo htmlspecialchars($code); ?>" value="1">
                                                        <span class="text-success font-weight-bold">E 1.00 (Fixed)</span>
                                                    <?php else: ?>
                                                        <div class="input-group input-group-sm">
                                                            <div class="input-group-prepend">
                                                                <span class="input-group-text">E</span>
                                                            </div>
                                                            <input type="number" 
                                                                   name="rate_<?php echo htmlspecialchars($code); ?>" 
                                                                   class="form-control rate-input" 
                                                                   step="0.001" 
                                                                   min="0.001" 
                                                                   value="<?php echo number_format($rate, 3); ?>"
                                                                   data-currency="<?php echo htmlspecialchars($code); ?>"
                                                                   oninput="updatePreview('<?php echo htmlspecialchars($code); ?>')">
                                                        </div>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <small class="text-muted">
                                                        <span id="preview_<?php echo htmlspecialchars($code); ?>">
                                                            <?php if (!$isBase): ?>
                                                                E 1 = <?php echo htmlspecialchars($currency['symbol']); ?> <?php echo number_format($rate, 2); ?>
                                                            <?php endif; ?>
                                                        </span>
                                                    </small>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            <div class="card-footer">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save"></i> Save Exchange Rates
                                </button>
                                <button type="button" class="btn btn-outline-secondary ml-2" onclick="resetRates()">
                                    <i class="fas fa-undo"></i> Reset Changes
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </section>
    </div>

    <!-- Currency Converter Modal -->
    <div class="modal fade" id="converterModal" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Currency Converter</h5>
                    <button type="button" class="close" data-dismiss="modal">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-12">
                            <div class="form-group">
                                <label>Amount</label>
                                <input type="number" id="convertAmount" class="form-control" step="0.01" min="0" value="100" oninput="performConversion()">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>From Currency</label>
                                <select id="fromCurrency" class="form-control" onchange="performConversion()">
                                    <?php foreach ($currencies as $currency): ?>
                                        <option value="<?php echo htmlspecialchars($currency['code']); ?>">
                                            <?php echo htmlspecialchars($currency['code']); ?> - <?php echo htmlspecialchars($currency['name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>To Currency</label>
                                <select id="toCurrency" class="form-control" onchange="performConversion()">
                                    <option value="E">E - Espees</option>
                                    <?php foreach ($currencies as $currency): ?>
                                        <option value="<?php echo htmlspecialchars($currency['code']); ?>">
                                            <?php echo htmlspecialchars($currency['code']); ?> - <?php echo htmlspecialchars($currency['name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="conversion-preview">
                        <div id="conversionResult" class="text-center">
                            <h4>Select amount and currencies to convert</h4>
                        </div>
                    </div>
                </div>
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

<script>
// Exchange rates data from PHP
const exchangeRates = <?php echo json_encode($settings['exchange_rates'] ?? []); ?>;

// Show success/error messages
<?php if ($message): ?>
Swal.fire({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    icon: 'success',
    title: '<?php echo htmlspecialchars($message); ?>'
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
    title: '<?php echo htmlspecialchars($error); ?>'
});
<?php endif; ?>

// Update preview calculation
function updatePreview(currencyCode) {
    const input = document.querySelector(`input[name="rate_${currencyCode}"]`);
    const preview = document.getElementById(`preview_${currencyCode}`);
    
    if (input && preview) {
        const rate = parseFloat(input.value) || 0;
        if (rate > 0) {
            // Get currency symbol from the currency data
            const currencyData = <?php echo json_encode(array_column($currencies, null, 'code')); ?>;
            const symbol = currencyData[currencyCode] ? currencyData[currencyCode].symbol : '';
            preview.textContent = `E 1 = ${symbol} ${rate.toFixed(2)}`;
        } else {
            preview.textContent = '';
        }
    }
}

// Toggle all checkboxes
function toggleAllCheckboxes() {
    const selectAll = document.getElementById('selectAll');
    const checkboxes = document.querySelectorAll('.currency-checkbox');
    
    checkboxes.forEach(function(checkbox) {
        checkbox.checked = selectAll.checked;
    });
}

// Select all currencies
function selectAllCurrencies() {
    document.getElementById('selectAll').checked = true;
    toggleAllCheckboxes();
}

// Confirm bulk update
function confirmBulkUpdate() {
    const selectedBoxes = document.querySelectorAll('.currency-checkbox:checked');
    const multiplier = document.querySelector('input[name="multiplier"]').value;
    
    if (selectedBoxes.length === 0) {
        Swal.fire('Error', 'Please select at least one currency to update', 'error');
        return false;
    }
    
    return confirm(`Are you sure you want to multiply ${selectedBoxes.length} exchange rates by ${multiplier}?`);
}

// Reset rates to original values
function resetRates() {
    if (confirm('Reset all changes to the last saved values?')) {
        location.reload();
    }
}

// Show currency converter
function showConverter() {
    $('#converterModal').modal('show');
    performConversion();
}

// Perform currency conversion
function performConversion() {
    const amount = parseFloat(document.getElementById('convertAmount').value) || 0;
    const fromCode = document.getElementById('fromCurrency').value;
    const toCode = document.getElementById('toCurrency').value;
    const result = document.getElementById('conversionResult');
    
    if (amount === 0) {
        result.innerHTML = '<h4>Enter an amount to convert</h4>';
        return;
    }
    
    let convertedAmount = 0;
    
    if (fromCode === toCode) {
        convertedAmount = amount;
    } else if (fromCode === 'E') {
        // From Espees to other currency
        // Rate represents: X Currency = 1 Espee, so 1 Espee = X Currency
        const rate = exchangeRates[toCode] || 1;
        convertedAmount = amount * rate;
    } else if (toCode === 'E') {
        // From other currency to Espees  
        // Rate represents: X Currency = 1 Espee, so to get Espees we divide
        const rate = exchangeRates[fromCode] || 1;
        convertedAmount = amount / rate;
    } else {
        // Between two non-base currencies
        // First convert to Espees, then to target currency
        const fromRate = exchangeRates[fromCode] || 1;
        const toRate = exchangeRates[toCode] || 1;
        const espeesAmount = amount / fromRate; // Convert to Espees
        convertedAmount = espeesAmount * toRate; // Convert to target currency
    }
    
    result.innerHTML = `
        <h4 class="text-primary">
            ${amount.toFixed(2)} ${fromCode} = ${convertedAmount.toFixed(2)} ${toCode}
        </h4>
        <small class="text-muted">Based on current exchange rates</small>
    `;
}
</script>
</body>
</html>