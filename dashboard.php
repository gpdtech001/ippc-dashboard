<?php
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);
$isAdmin = (isset($_SESSION['role']) && $_SESSION['role'] === ROLE_ADMIN);

// Create analytics.php if it doesn't exist
$analytics_path = __DIR__ . '/analytics.php';
if (!file_exists($analytics_path) && $isAdmin) {
    $analytics_content = '<?php
require_once \'config.php\';

session_start();
requireLogin();

// Only admin can access analytics
if (!isset($_SESSION[\'role\']) || $_SESSION[\'role\'] !== ROLE_ADMIN) {
    header(\'Location: dashboard.php\');
    exit();
}

$user = getUserById($_SESSION[\'user_id\']);

// Get filter parameters
$selected_category = $_GET[\'category\'] ?? \'\';
$selected_region = $_GET[\'region\'] ?? \'\';
$selected_zone = $_GET[\'zone\'] ?? \'\';
$top_limit = $_GET[\'limit\'] ?? 10;
$view_type = $_GET[\'view\'] ?? \'overall\';

// Load all data
$reports = getReports() ?: [];
$report_categories = getReportCategories() ?: [];

// Function to aggregate sponsorship data
function aggregateSponsorshipData($reports, $filters = []) {
    $aggregated_data = [];

    foreach ($reports as $report) {
        // Apply filters
        if (!empty($filters[\'category\']) && $report[\'category_name\'] !== $filters[\'category\']) {
            continue;
        }
        if (!empty($filters[\'region\']) && $report[\'region\'] !== $filters[\'region\']) {
            continue;
        }
        if (!empty($filters[\'zone\']) && $report[\'zone\'] !== $filters[\'zone\']) {
            continue;
        }

        $submitter_name = $report[\'submitted_by_name\'];
        $category = $report[\'category_name\'];
        $region = $report[\'region\'] ?: \'Unknown\';
        $zone = $report[\'zone\'] ?: \'Unknown\';

        if (!isset($aggregated_data[$submitter_name])) {
            $aggregated_data[$submitter_name] = [
                \'name\' => $submitter_name,
                \'role\' => $report[\'role\'],
                \'region\' => $region,
                \'zone\' => $zone,
                \'total_amount\' => 0,
                \'total_quantity\' => 0,
                \'categories\' => [],
                \'report_count\' => 0
            ];
        }

        $aggregated_data[$submitter_name][\'report_count\']++;

        // Process each field in the report
        foreach ($report[\'data\'] as $field_id => $value) {
            if (is_numeric($value) && $value > 0) {
                // Check if this is likely an amount or quantity field
                $field_label = strtolower(getFieldLabel($field_id, $category));

                // Categorize as amount or quantity
                if (strpos($field_label, \'amount\') !== false ||
                    strpos($field_label, \'total\') !== false ||
                    strpos($field_label, \'given\') !== false ||
                    strpos($field_label, \'received\') !== false) {
                    $aggregated_data[$submitter_name][\'total_amount\'] += (float)$value;
                } else {
                    $aggregated_data[$submitter_name][\'total_quantity\'] += (float)$value;
                }
            }
        }
    }

    return $aggregated_data;
}

// Helper function to get field label
function getFieldLabel($field_id, $category_name) {
    $categories = getReportCategories() ?: [];
    foreach ($categories as $category) {
        if ($category[\'name\'] === $category_name) {
            foreach ($category[\'fields\'] as $field) {
                if ($field[\'id\'] === $field_id) {
                    return $field[\'label\'];
                }
            }
        }
    }
    return $field_id;
}

// Get data based on view type
$filters = [];
if ($selected_category) $filters[\'category\'] = $selected_category;
if ($selected_region) $filters[\'region\'] = $selected_region;
if ($selected_zone) $filters[\'zone\'] = $selected_zone;

$sponsorship_data = aggregateSponsorshipData($reports, $filters);

// Sort data based on view type
if ($view_type === \'amount\') {
    uasort($sponsorship_data, function($a, $b) {
        return $b[\'total_amount\'] <=> $a[\'total_amount\'];
    });
} elseif ($view_type === \'quantity\') {
    uasort($sponsorship_data, function($a, $b) {
        return $b[\'total_quantity\'] <=> $a[\'total_quantity\'];
    });
} else {
    // Overall ranking (amount + quantity combined)
    uasort($sponsorship_data, function($a, $b) {
        $score_a = $a[\'total_amount\'] + ($a[\'total_quantity\'] * 10);
        $score_b = $b[\'total_amount\'] + ($b[\'total_quantity\'] * 10);
        return $score_b <=> $score_a;
    });
}

// Limit results
$sponsorship_data = array_slice($sponsorship_data, 0, $top_limit, true);

// Get unique categories, regions, zones for filters
$unique_categories = [];
$unique_regions = [];
$unique_zones = [];

foreach ($reports as $report) {
    if (!in_array($report[\'category_name\'], $unique_categories)) {
        $unique_categories[] = $report[\'category_name\'];
    }
    if ($report[\'region\'] && !in_array($report[\'region\'], $unique_regions)) {
        $unique_regions[] = $report[\'region\'];
    }
    if ($report[\'zone\'] && !in_array($report[\'zone\'], $unique_zones)) {
        $unique_zones[] = $report[\'zone\'];
    }
}

sort($unique_categories);
sort($unique_regions);
sort($unique_zones);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Partnership Analytics Dashboard</title>

    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.min.css">
    <style>
        .leaderboard-card { transition: transform 0.2s; }
        .leaderboard-card:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .rank-badge { width: 40px; height: 40px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-weight: bold; }
        .rank-1 { background: linear-gradient(45deg, #FFD700, #FFA500); color: #000; }
        .rank-2 { background: linear-gradient(45deg, #C0C0C0, #A8A8A8); color: #000; }
        .rank-3 { background: linear-gradient(45deg, #CD7F32, #A0522D); color: #fff; }
        .rank-other { background: #6c757d; color: #fff; }
        .metric-value { font-size: 1.2em; font-weight: bold; color: #007bff; }
        .filter-section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
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

    <?php include __DIR__ . \'/includes/sidebar.php\'; ?>

    <div class="content-wrapper">
        <div class="content-header">
            <div class="container-fluid">
                <div class="row mb-2">
                    <div class="col-sm-6">
                        <h1 class="m-0">Partnership Analytics Dashboard</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="dashboard.php">Home</a></li>
                            <li class="breadcrumb-item active">Analytics</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <section class="content">
            <div class="container-fluid">
                <div class="filter-section">
                    <form method="GET" class="row g-3">
                        <div class="col-md-2">
                            <label for="view" class="form-label">View Type</label>
                            <select name="view" id="view" class="form-select">
                                <option value="overall" <?php echo $view_type === \'overall\' ? \'selected\' : \'\'; ?>>Overall Ranking</option>
                                <option value="amount" <?php echo $view_type === \'amount\' ? \'selected\' : \'\'; ?>>By Amount</option>
                                <option value="quantity" <?php echo $view_type === \'quantity\' ? \'selected\' : \'\'; ?>>By Quantity</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label for="category" class="form-label">Category</label>
                            <select name="category" id="category" class="form-select">
                                <option value="">All Categories</option>
                                <?php foreach ($unique_categories as $category): ?>
                                    <option value="<?php echo htmlspecialchars($category); ?>" <?php echo $selected_category === $category ? \'selected\' : \'\'; ?>>
                                        <?php echo htmlspecialchars($category); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label for="region" class="form-label">Region</label>
                            <select name="region" id="region" class="form-select">
                                <option value="">All Regions</option>
                                <?php foreach ($unique_regions as $region): ?>
                                    <option value="<?php echo htmlspecialchars($region); ?>" <?php echo $selected_region === $region ? \'selected\' : \'\'; ?>>
                                        <?php echo htmlspecialchars($region); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label for="zone" class="form-label">Zone</label>
                            <select name="zone" id="zone" class="form-select">
                                <option value="">All Zones</option>
                                <?php foreach ($unique_zones as $zone): ?>
                                    <option value="<?php echo htmlspecialchars($zone); ?>" <?php echo $selected_zone === $zone ? \'selected\' : \'\'; ?>>
                                        <?php echo htmlspecialchars($zone); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label for="limit" class="form-label">Top</label>
                            <select name="limit" id="limit" class="form-select">
                                <option value="10" <?php echo $top_limit == 10 ? \'selected\' : \'\'; ?>>Top 10</option>
                                <option value="20" <?php echo $top_limit == 20 ? \'selected\' : \'\'; ?>>Top 20</option>
                                <option value="50" <?php echo $top_limit == 50 ? \'selected\' : \'\'; ?>>Top 50</option>
                                <option value="100" <?php echo $top_limit == 100 ? \'selected\' : \'\'; ?>>Top 100</option>
                            </select>
                        </div>
                        <div class="col-md-2 d-flex align-items-end">
                            <button type="submit" class="btn btn-primary me-2">
                                <i class="fas fa-search"></i> Apply Filters
                            </button>
                            <a href="analytics.php" class="btn btn-secondary">
                                <i class="fas fa-times"></i> Clear
                            </a>
                        </div>
                    </form>
                </div>

                <div class="row">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-trophy text-warning"></i>
                                    Top <?php echo $top_limit; ?> Sponsors Leaderboard
                                    <?php if ($selected_category): ?>
                                        <small class="text-muted">(<?php echo htmlspecialchars($selected_category); ?>)</small>
                                    <?php endif; ?>
                                </h3>
                                <div class="card-tools">
                                    <span class="badge badge-primary"><?php echo count($sponsorship_data); ?> Contributors</span>
                                </div>
                            </div>
                            <div class="card-body p-0">
                                <?php if (empty($sponsorship_data)): ?>
                                    <div class="text-center py-5">
                                        <i class="fas fa-chart-line fa-3x text-muted mb-3"></i>
                                        <p class="text-muted">No data available for the selected filters.</p>
                                    </div>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-striped mb-0">
                                            <thead class="bg-light">
                                                <tr>
                                                    <th width="80">Rank</th>
                                                    <th>Sponsor Name</th>
                                                    <th>Role</th>
                                                    <th>Region/Zone</th>
                                                    <th class="text-right">Total Amount</th>
                                                    <th class="text-right">Total Quantity</th>
                                                    <th class="text-right">Reports</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php
                                                $rank = 1;
                                                foreach ($sponsorship_data as $sponsor):
                                                    $rank_class = $rank <= 3 ? "rank-$rank" : "rank-other";
                                                ?>
                                                <tr class="leaderboard-row">
                                                    <td>
                                                        <span class="rank-badge <?php echo $rank_class; ?>">
                                                            <?php echo $rank; ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <strong><?php echo htmlspecialchars($sponsor[\'name\']); ?></strong>
                                                    </td>
                                                    <td>
                                                        <span class="badge badge-info"><?php echo htmlspecialchars(ucfirst($sponsor[\'role\'])); ?></span>
                                                    </td>
                                                    <td>
                                                        <small class="text-muted">
                                                            <?php echo htmlspecialchars($sponsor[\'region\']); ?> /
                                                            <?php echo htmlspecialchars($sponsor[\'zone\']); ?>
                                                        </small>
                                                    </td>
                                                    <td class="text-right">
                                                        <span class="metric-value text-success">
                                                            ₦<?php echo number_format($sponsor[\'total_amount\'], 2); ?>
                                                        </span>
                                                    </td>
                                                    <td class="text-right">
                                                        <span class="metric-value text-primary">
                                                            <?php echo number_format($sponsor[\'total_quantity\']); ?>
                                                        </span>
                                                    </td>
                                                    <td class="text-right">
                                                        <span class="badge badge-secondary"><?php echo $sponsor[\'report_count\']; ?></span>
                                                    </td>
                                                </tr>
                                                <?php $rank++; endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Zone Rankings -->
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-map-marker-alt text-info"></i>
                                    Top <?php echo $top_limit; ?> Most Active Zones
                                </h3>
                            </div>
                            <div class="card-body p-0">
                                <?php
                                // Zone rankings logic
                                $zone_rankings = [];
                                foreach ($reports as $report) {
                                    $zone = $report[\'zone\'] ?: \'Unknown\';
                                    $region = $report[\'region\'] ?: \'Unknown\';

                                    if (!isset($zone_rankings[$zone])) {
                                        $zone_rankings[$zone] = [
                                            \'zone\' => $zone,
                                            \'region\' => $region,
                                            \'total_amount\' => 0,
                                            \'total_quantity\' => 0,
                                            \'contributors\' => [],
                                            \'report_count\' => 0
                                        ];
                                    }

                                    $zone_rankings[$zone][\'report_count\']++;

                                    if (!in_array($report[\'submitted_by_name\'], $zone_rankings[$zone][\'contributors\'])) {
                                        $zone_rankings[$zone][\'contributors\'][] = $report[\'submitted_by_name\'];
                                    }

                                    foreach ($report[\'data\'] as $field_id => $value) {
                                        if (is_numeric($value) && $value > 0) {
                                            $field_label = strtolower(getFieldLabel($field_id, $report[\'category_name\']));

                                            if (strpos($field_label, \'amount\') !== false ||
                                                strpos($field_label, \'total\') !== false ||
                                                strpos($field_label, \'given\') !== false ||
                                                strpos($field_label, \'received\') !== false) {
                                                $zone_rankings[$zone][\'total_amount\'] += (float)$value;
                                            } else {
                                                $zone_rankings[$zone][\'total_quantity\'] += (float)$value;
                                            }
                                        }
                                    }
                                }

                                uasort($zone_rankings, function($a, $b) {
                                    return $b[\'total_amount\'] <=> $a[\'total_amount\'];
                                });

                                $zone_rankings = array_slice($zone_rankings, 0, $top_limit, true);
                                ?>

                                <?php if (empty($zone_rankings)): ?>
                                    <div class="text-center py-5">
                                        <i class="fas fa-map fa-3x text-muted mb-3"></i>
                                        <p class="text-muted">No zone data available.</p>
                                    </div>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-striped mb-0">
                                            <thead class="bg-light">
                                                <tr>
                                                    <th width="80">Rank</th>
                                                    <th>Zone</th>
                                                    <th>Region</th>
                                                    <th class="text-right">Total Amount</th>
                                                    <th class="text-right">Total Quantity</th>
                                                    <th class="text-right">Contributors</th>
                                                    <th class="text-right">Reports</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php
                                                $rank = 1;
                                                foreach ($zone_rankings as $zone):
                                                    $rank_class = $rank <= 3 ? "rank-$rank" : "rank-other";
                                                ?>
                                                <tr>
                                                    <td>
                                                        <span class="rank-badge <?php echo $rank_class; ?>">
                                                            <?php echo $rank; ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <strong><?php echo htmlspecialchars($zone[\'zone\']); ?></strong>
                                                    </td>
                                                    <td>
                                                        <?php echo htmlspecialchars($zone[\'region\']); ?>
                                                    </td>
                                                    <td class="text-right">
                                                        <span class="metric-value text-success">
                                                            ₦<?php echo number_format($zone[\'total_amount\'], 2); ?>
                                                        </span>
                                                    </td>
                                                    <td class="text-right">
                                                        <span class="metric-value text-primary">
                                                            <?php echo number_format($zone[\'total_quantity\']); ?>
                                                        </span>
                                                    </td>
                                                    <td class="text-right">
                                                        <span class="badge badge-warning"><?php echo count($zone[\'contributors\']); ?></span>
                                                    </td>
                                                    <td class="text-right">
                                                        <span class="badge badge-secondary"><?php echo $zone[\'report_count\']; ?></span>
                                                    </td>
                                                </tr>
                                                <?php $rank++; endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-chart-pie text-success"></i>
                                    Category Performance Summary
                                </h3>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <?php
                                    $category_totals = [];
                                    foreach ($reports as $report) {
                                        $category = $report[\'category_name\'];
                                        if (!isset($category_totals[$category])) {
                                            $category_totals[$category] = [\'amount\' => 0, \'quantity\' => 0, \'count\' => 0];
                                        }
                                        $category_totals[$category][\'count\']++;

                                        foreach ($report[\'data\'] as $field_id => $value) {
                                            if (is_numeric($value) && $value > 0) {
                                                $field_label = strtolower(getFieldLabel($field_id, $category));

                                                if (strpos($field_label, \'amount\') !== false ||
                                                    strpos($field_label, \'total\') !== false ||
                                                    strpos($field_label, \'given\') !== false ||
                                                    strpos($field_label, \'received\') !== false) {
                                                    $category_totals[$category][\'amount\'] += (float)$value;
                                                } else {
                                                    $category_totals[$category][\'quantity\'] += (float)$value;
                                                }
                                            }
                                        }
                                    }

                                    arsort($category_totals);
                                    foreach ($category_totals as $category => $totals):
                                    ?>
                                    <div class="col-md-6 col-lg-4 mb-3">
                                        <div class="small-box bg-light">
                                            <div class="inner">
                                                <h4><?php echo htmlspecialchars($category); ?></h4>
                                                <p class="mb-1">
                                                    <strong>₦<?php echo number_format($totals[\'amount\'], 2); ?></strong> Amount
                                                </p>
                                                <p class="mb-1">
                                                    <strong><?php echo number_format($totals[\'quantity\']); ?></strong> Quantity
                                                </p>
                                                <p class="mb-0">
                                                    <strong><?php echo $totals[\'count\']; ?></strong> Reports
                                                </p>
                                            </div>
                                            <div class="icon">
                                                <i class="fas fa-chart-line"></i>
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
        <strong>Copyright &copy; 2024 <a href="#">IPPC Dashboard</a>.</strong>
        All rights reserved.
    </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"></script>
<script>
$(document).ready(function() {
    $(\'#view, #category, #region, #zone, #limit\').on(\'change\', function() {
        $(this).closest(\'form\').submit();
    });
});
</script>
</body>
</html>';
    file_put_contents($analytics_path, $analytics_content);
}
// Latest report: admin -> any; RZM -> own
$latestReport = null;
if (function_exists('getReports')) {
    $allReports = getReports();
    // Sort by created_at desc
    usort($allReports, function($a, $b){ return strcmp($b['created_at'] ?? '', $a['created_at'] ?? ''); });
    if ($isAdmin) {
        $latestReport = $allReports[0] ?? null;
    } else {
        foreach ($allReports as $r) {
            if (($r['submitted_by'] ?? '') === ($user['id'] ?? '')) { $latestReport = $r; break; }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IPPC | Dashboard</title>

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
                        <h1 class="m-0">Dashboard</h1>
                    </div>
                    <div class="col-sm-6">
                        <ol class="breadcrumb float-sm-right">
                            <li class="breadcrumb-item"><a href="#">Home</a></li>
                            <li class="breadcrumb-item active">Dashboard</li>
                        </ol>
                    </div>
                </div>
            </div><!-- /.container-fluid -->
        </div>
        <!-- /.content-header -->

        <!-- Main content -->
        <section class="content">
            <div class="container-fluid">
                <!-- Welcome Section -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-primary card-outline">
                            <div class="card-body">
                                <div class="text-center">
                                    <h1 class="display-4">Welcome to IPPC - Reporting and Analytics Dashboard</h1>
                                    <p class="lead">Hello <strong><?php echo htmlspecialchars($user['name'] ?? 'User'); ?></strong>!</p>
                                    <p class="mb-4">You are logged in as <strong><?php echo htmlspecialchars(ucfirst($user['role'] ?? 'user')); ?></strong></p>


                                    <div class="row justify-content-center mt-4">
                                        <div class="col-md-6">
                                            <div class="card">
                                                <div class="card-body">
                                                    <h5 class="card-title">Quick Actions</h5>
                                                    <div class="d-grid gap-2">
                                                        <a href="profile.php" class="btn btn-secondary btn-lg">
                                                            <i class="fas fa-user"></i> Update Profile
                                                        </a>
                                                        <?php if ($_SESSION['role'] === ROLE_ADMIN): ?>
                                                        <a href="user_management.php" class="btn btn-success btn-lg">
                                                            <i class="fas fa-users"></i> Manage Users
                                                        </a>
                                                        <a href="analytics.php" class="btn btn-info btn-lg">
                                                            <i class="fas fa-chart-line"></i> Analytics
                                                        </a>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Quick Stats Row (minimal) -->
                <div class="row">
                    <div class="col-md-4">
                        <div class="small-box bg-info">
                            <div class="inner">
                                <h3><?php echo htmlspecialchars(ucfirst($user['role'] ?? 'user')); ?></h3>
                                <p>Your Role</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-user-tag"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="small-box bg-success">
                            <div class="inner">
                                <h3><?php echo htmlspecialchars($user['name'] ?? 'User'); ?></h3>
                                <p>Welcome Back!</p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-smile"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="small-box bg-warning">
                            <div class="inner">
                                <h3><?php echo date('M j'); ?></h3>
                                <p><?php echo date('Y'); ?></p>
                            </div>
                            <div class="icon">
                                <i class="fas fa-calendar"></i>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Latest Report Card -->
                <div class="row">
                    <div class="col-12">
                        <div class="card card-outline card-info">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h3 class="card-title">Latest Report Submitted</h3>
                                <div>
                                    <a href="reporting.php" class="btn btn-sm btn-primary"><i class="fas fa-plus"></i> Submit Report</a>
                                    <a href="reports.php" class="btn btn-sm btn-secondary"><i class="fas fa-table"></i> View All Reports</a>
                                </div>
                            </div>
                            <div class="card-body">
                                <?php if (!$latestReport): ?>
                                    <div class="text-center py-4">
                                        <i class="fas fa-file-alt fa-3x text-muted mb-3"></i>
                                        <p class="text-muted">No reports submitted yet.</p>
                                        <a href="reporting.php" class="btn btn-primary">
                                            <i class="fas fa-plus"></i> Submit Your First Report
                                        </a>
                                    </div>
                                <?php else: ?>
                                    <div class="row">
                                        <div class="col-md-8">
                                            <div class="mb-2">
                                                <strong>Category:</strong> 
                                                <span class="badge badge-info"><?php echo htmlspecialchars($latestReport['category_name'] ?? ''); ?></span>
                                            </div>
                                            <div class="mb-2">
                                                <strong>Submitted At:</strong> 
                                                <?php echo htmlspecialchars($latestReport['created_at'] ?? ''); ?>
                                            </div>
                                            <?php if ($isAdmin): ?>
                                                <div class="mb-2">
                                                    <strong>Submitted By:</strong> 
                                                    <?php echo htmlspecialchars(($latestReport['submitted_by_name'] ?? '') . ' (' . ucfirst($latestReport['role'] ?? '') . ')'); ?>
                                                </div>
                                            <?php endif; ?>
                                            <div class="mb-2">
                                                <strong>Report ID:</strong> 
                                                <code><?php echo htmlspecialchars($latestReport['id'] ?? ''); ?></code>
                                            </div>
                                        </div>
                                        <div class="col-md-4 text-right">
                                            <div class="btn-group-vertical">
                                                <a href="reports.php" class="btn btn-success mb-2">
                                                    <i class="fas fa-eye"></i> View Report
                                                </a>
                                                <?php 
                                                $canEdit = $isAdmin || (($latestReport['submitted_by'] ?? '') === ($_SESSION['user_id'] ?? ''));
                                                if ($canEdit): 
                                                ?>
                                                <a href="report_edit.php?id=<?php echo urlencode($latestReport['id']); ?>" class="btn btn-warning">
                                                    <i class="fas fa-edit"></i> Edit Report
                                                </a>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div><!-- /.container-fluid -->
        </section>
        <!-- /.content -->
    </div>
    <!-- /.content-wrapper -->

    <footer class="main-footer">
        <strong>Copyright &copy; 2024 <a href="#">IPPC Dashboard</a>.</strong>
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
</body>
</html>
