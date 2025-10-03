<?php
require_once 'config.php';

session_start();
requireLogin();

$user = getUserById($_SESSION['user_id']);
$isAdmin = ($_SESSION['role'] === ROLE_ADMIN);

// Get parameters
$categoryId = $_GET['category'] ?? '';
$format = $_GET['format'] ?? 'excel'; // excel or csv

if (empty($categoryId)) {
    $_SESSION['flash_error'] = 'No report category specified';
    header('Location: reports.php');
    exit;
}

// Get the category
$category = getCategoryById($categoryId);
if (!$category) {
    $_SESSION['flash_error'] = 'Report category not found';
    header('Location: reports.php');
    exit;
}

// Apply currency field fixes and automatic currency field addition
$category = fixCurrencyFields($category);
$category = addAutomaticCurrencyField($category);

$fields = $category['fields'] ?? [];
$categoryName = $category['name'] ?? 'Unknown';

// Clean category name for filename
$safeFileName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $categoryName);
$timestamp = date('Y-m-d_H-i-s');

$requestedCurrency = $_GET['currency'] ?? '';
$availableCurrencies = json_decode(@file_get_contents(__DIR__ . '/currency.json'), true) ?: [];
$currencyCodes = array_column($availableCurrencies, 'code');

if ($requestedCurrency && in_array($requestedCurrency, $currencyCodes, true)) {
    $selectedCurrency = $requestedCurrency;
} else {
    $settings = getCurrencySettings();
    $selectedCurrency = $settings['base_currency']['code'] ?? ($currencyCodes[0] ?? 'E');
}

// Only one template format now - the enhanced version
generateEnhancedTemplate($category, $fields, $safeFileName, $timestamp, $user, $selectedCurrency);

function generateEnhancedTemplate($category, $fields, $safeFileName, $timestamp, $user, $selectedCurrency) {
    $filename = "template_{$safeFileName}_{$timestamp}.csv";
    
    // Set headers for Excel-compatible CSV
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: max-age=0');
    
    // Create output stream
    $output = fopen('php://output', 'w');
    
    // Add BOM for UTF-8 (helps Excel recognize encoding)
    fwrite($output, "\xEF\xBB\xBF");
    
    // Get available groups for the user
    $groupOptions = [];
    $currencyField = null;
    
    foreach ($fields as $field) {
        if ($field['type'] === 'groups' || ($field['type'] === 'select' && ($field['source'] ?? '') === 'zones_groups')) {
            $groupOptions = getFieldOptions($field, $user);
        }
        if ($field['type'] === 'currency' || ($field['type'] === 'select' && ($field['source'] ?? '') === 'currency')) {
            $currencyField = $field;
        }
    }
    
    // Create headers (excluding auto_currency and groups field)
    $headers = [];
    $fieldMap = []; // Map to track field positions
    $fieldIndex = 0;
    
    foreach ($fields as $field) {
        if ($field['type'] === 'auto_currency') {
            continue; // Skip auto currency fields
        }
        if ($field['type'] === 'groups' || ($field['type'] === 'select' && ($field['source'] ?? '') === 'zones_groups')) {
            continue; // Skip groups field - we'll use groups as rows instead
        }
        
        $headers[] = $field['label'] ?? $field['id'];
        $fieldMap[$fieldIndex] = $field;
        $fieldIndex++;
    }
    
    // Add Groups column at the beginning
    array_unshift($headers, 'Groups');
    
    // Add headers
    fputcsv($output, $headers);
    
    // Add a row for each available group
    if (!empty($groupOptions)) {
        foreach ($groupOptions as $group) {
            $row = [$group['label']]; // Start with group name
            
            // Add sample/default values for each field
            foreach ($fieldMap as $field) {
                if ($field['type'] === 'currency' || ($field['type'] === 'select' && ($field['source'] ?? '') === 'currency')) {
                    $row[] = $selectedCurrency;
                } else {
                    $row[] = getSampleValue($field, $user, $selectedCurrency);
                }
            }
            
            fputcsv($output, $row);
        }
    } else {
        // Fallback if no groups available
        $row = ['Your Group Name']; // Placeholder
        foreach ($fieldMap as $field) {
            $row[] = getSampleValue($field, $user, $selectedCurrency);
        }
        fputcsv($output, $row);
    }
    
    fclose($output);
    exit;
}


function needsDropdownValidation($field) {
    return in_array($field['type'], ['select', 'groups', 'currency']) || 
           ($field['type'] === 'select' && in_array($field['source'], ['zones_groups', 'currency']));
}

function getSampleValue($field, $user = null, $selectedCurrency = 'E') {
    switch ($field['type']) {
        case 'text':
            return 'Sample text';
        case 'textarea':
            return 'Sample description';
        case 'number':
        case 'quantity':
            return '0';
        case 'currency_amount':
            return '0';
        case 'date':
            return date('Y-m-d');
        case 'email':
            return 'example@domain.com';
        case 'select':
        case 'groups':
        case 'currency':
            $options = getFieldOptions($field, $user);
            if (!empty($options)) {
                foreach ($options as $option) {
                    if (($option['id'] ?? null) === $selectedCurrency) {
                        return $selectedCurrency;
                    }
                }
                return $options[0]['id'];
            }
            if ($field['type'] === 'currency') {
                return $selectedCurrency;
            }
            return 'Select option';
        default:
            return $field['placeholder'] ?? 'Enter value';
    }
}

function getFieldInstruction($field, $user) {
    switch ($field['type']) {
        case 'groups':
            return 'Select from available groups in your zone/region';
        case 'currency':
            return 'Select currency code (e.g., NGN, USD, EUR)';
        case 'select':
            if ($field['source'] === 'zones_groups') {
                return 'Select from available groups in your zone/region';
            } elseif ($field['source'] === 'currency') {
                return 'Select currency code (e.g., NGN, USD, EUR)';
            } else {
                $options = $field['options'] ?? [];
                if (!empty($options)) {
                    return 'Options: ' . implode(', ', array_slice($options, 0, 3)) . (count($options) > 3 ? '...' : '');
                }
            }
            return 'Select from dropdown options';
        case 'currency_amount':
            return 'Enter numeric amount (e.g., 1000.50)';
        case 'quantity':
        case 'number':
            return 'Enter numeric value';
        case 'date':
            return 'Format: YYYY-MM-DD (e.g., 2024-12-31)';
        case 'email':
            return 'Enter valid email address';
        case 'required':
            return $field['required'] ? 'Required field' : 'Optional field';
        default:
            return null;
    }
}

function getFieldOptions($field, $user = null) {
    try {
        if (!$user) {
            global $user;
        }
        return resolveFieldOptions($field, $user);
    } catch (Exception $e) {
        return [];
    }
}

function createValidationSheet($excel, $field, $user) {
    $options = getFieldOptions($field, $user);
    if (empty($options)) {
        return;
    }
    
    $sheetName = substr(preg_replace('/[^a-zA-Z0-9]/', '', $field['label'] ?? $field['id']), 0, 30);
    $excel->addWorksheet($sheetName);
    
    // Add validation options
    foreach ($options as $option) {
        $excel->addRow([$option['label'], $option['id']]);
    }
}

// Simple Excel Generator Class
class SimpleExcelGenerator {
    private $worksheets = [];
    private $currentWorksheet = null;
    private $sharedStrings = [];
    private $stringCount = 0;
    
    public function createWorkbook() {
        $this->worksheets = [];
        $this->sharedStrings = [];
        $this->stringCount = 0;
    }
    
    public function addWorksheet($name) {
        $this->currentWorksheet = [
            'name' => $name,
            'rows' => [],
            'rowCount' => 0
        ];
        $this->worksheets[] = &$this->currentWorksheet;
    }
    
    public function addRow($data) {
        if (!$this->currentWorksheet) {
            return;
        }
        
        $row = [];
        foreach ($data as $value) {
            $row[] = $this->addString($value);
        }
        
        $this->currentWorksheet['rows'][] = $row;
        $this->currentWorksheet['rowCount']++;
    }
    
    private function addString($string) {
        $string = (string)$string;
        if (!isset($this->sharedStrings[$string])) {
            $this->sharedStrings[$string] = $this->stringCount;
            $this->stringCount++;
        }
        return $this->sharedStrings[$string];
    }
    
    public function output() {
        // For simplicity, we'll create a basic XML-based Excel file
        // In a production environment, you might want to use PhpSpreadsheet
        
        $zip = new ZipArchive();
        $tempFile = tempnam(sys_get_temp_dir(), 'excel_template_');
        if ($tempFile === false) {
            $fallbackDir = __DIR__ . '/temp';
            if (!is_dir($fallbackDir)) {
                @mkdir($fallbackDir, 0755, true);
            }
            $tempFilePath = $fallbackDir . '/excel_template_' . uniqid();
            $fh = @fopen($tempFilePath, 'w');
            if ($fh === false) {
                throw new Exception('Cannot create temporary file for Excel export');
            }
            fclose($fh);
            $tempFile = $tempFilePath;
        }
        
        if ($zip->open($tempFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
            @unlink($tempFile);
            throw new Exception('Cannot create Excel file');
        }
        
        // Add basic Excel structure
        $this->addExcelStructure($zip);
        
        $zip->close();
        
        if (!@readfile($tempFile)) {
            @unlink($tempFile);
            throw new Exception('Failed to stream generated Excel file');
        }
        @unlink($tempFile);
    }
    
    private function addExcelStructure($zip) {
        // Content Types
        $contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
    <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
    <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>';
        
        $zip->addFromString('[Content_Types].xml', $contentTypes);
        
        // App properties
        $zip->addFromString('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>');
        
        // Workbook
        $workbookXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <sheets>
        <sheet name="' . htmlspecialchars($this->worksheets[0]['name']) . '" sheetId="1" r:id="rId1"/>
    </sheets>
</workbook>';
        
        $zip->addFromString('xl/workbook.xml', $workbookXml);
        
        // Workbook relationships
        $zip->addFromString('xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>');
        
        // Shared strings
        $sharedStringsXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="' . $this->stringCount . '" uniqueCount="' . count($this->sharedStrings) . '">';
        
        foreach ($this->sharedStrings as $string => $index) {
            $sharedStringsXml .= '<si><t>' . htmlspecialchars($string) . '</t></si>';
        }
        
        $sharedStringsXml .= '</sst>';
        $zip->addFromString('xl/sharedStrings.xml', $sharedStringsXml);
        
        // Worksheet
        $worksheetXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData>';
        
        $rowNum = 1;
        foreach ($this->worksheets[0]['rows'] as $row) {
            $worksheetXml .= '<row r="' . $rowNum . '">';
            $colNum = 1;
            foreach ($row as $cellValue) {
                $cellRef = $this->numberToColumn($colNum) . $rowNum;
                $worksheetXml .= '<c r="' . $cellRef . '" t="s"><v>' . $cellValue . '</v></c>';
                $colNum++;
            }
            $worksheetXml .= '</row>';
            $rowNum++;
        }
        
        $worksheetXml .= '</sheetData></worksheet>';
        $zip->addFromString('xl/worksheets/sheet1.xml', $worksheetXml);
    }
    
    private function numberToColumn($num) {
        $str = '';
        while ($num > 0) {
            $num--;
            $str = chr(65 + ($num % 26)) . $str;
            $num = intval($num / 26);
        }
        return $str;
    }
}
