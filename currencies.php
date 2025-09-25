<?php
require_once 'config.php';

session_start();
requireLogin(); // Only require login, not admin

$user = getUserById($_SESSION['user_id']);

// Load current settings and currencies
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

// Get exchange rates
$exchangeRates = $settings['exchange_rates'] ?? [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Currencies</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <style>
    .currency-card {
        transition: transform 0.2s ease;
        border: 2px solid transparent;
    }
    .currency-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        border-color: #007bff;
    }
    .currency-symbol {
        font-size: 2em;
        font-weight: bold;
        margin-bottom: 10px;
    }
    .currency-code {
        background-color: #f8f9fa;
        border: 2px dashed #dee2e6;
        border-radius: 5px;
        padding: 8px;
        font-family: 'Courier New', monospace;
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
        <h1 class="m-0">Currency Reference</h1>
                        <p class="text-muted mb-0">Use these three-letter currency codes in your upload templates</p>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Currencies</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-coins mr-2"></i>
                                    Supported Currencies
                                </h3>
                                <div class="card-tools">
                                    <span class="badge badge-info">
                                        <?php echo count($currencies); ?> currencies
                                    </span>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-primary">
                                    <i class="fas fa-info-circle mr-2"></i>
                                    <strong>For Upload Templates:</strong> Use the three-letter currency code exactly as shown below in your CSV files.
                                </div>
                                
                                <div class="row">
                                    <?php foreach ($currencies as $currency): ?>
                                        <?php
                                        $code = $currency['code'];
                                        $isBase = ($code === 'E');
                                        ?>
                                        <div class="col-md-6 col-lg-4 mb-3">
                                            <div class="card currency-card h-100">
                                                <div class="card-body text-center">
                                                    <div class="currency-symbol text-primary mb-2">
                                                        <?php echo htmlspecialchars($currency['symbol'] ?? $code); ?>
                                                    </div>
                                                    <h5 class="card-title mb-2">
                                                        <?php echo htmlspecialchars($currency['name']); ?>
                                                    </h5>
                                                    <div class="currency-code">
                                                        <strong><?php echo htmlspecialchars($code); ?></strong>
                                                        <br>
                                                        <small class="text-muted">Use this code in uploads</small>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
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

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>

</body>
</html>