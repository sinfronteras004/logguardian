<?php
/**
 * post-install.php
 * 
 * This script runs automatically after installing or updating
 * the LogGuardianSF extension in Plesk.
 *
 * It performs the following tasks:
 *  - Creates the CRON jobs (parser and notifier)
 *  - Ensures execution permissions on the scripts
 *  - Logs actions during installation
 */

date_default_timezone_set('UTC');

$basePath = '/usr/local/psa/admin/plib/modules/LogGuardianSF';
$logFile  = "$basePath/install_log.txt";

// Helper function for logging
function logMessage($msg) {
    global $logFile;
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] " . $msg . "\n", FILE_APPEND);
    echo $msg . "\n";
}

logMessage("=== Starting automatic installation of LogGuardianSF ===");

// Detect available PHP version (prefers 8.3, then 8.2)
$phpBinary = null;
if (file_exists('/opt/plesk/php/8.3/bin/php')) {
    $phpBinary = '/opt/plesk/php/8.3/bin/php';
} elseif (file_exists('/opt/plesk/php/8.2/bin/php')) {
    $phpBinary = '/opt/plesk/php/8.2/bin/php';
} else {
    logMessage("⚠️  PHP 8.2 or 8.3 not found in /opt/plesk/php/. CRON jobs will not be created.");
    exit(1);
}

logMessage("Using PHP binary: $phpBinary");

// ===============================
// Create scheduled tasks (CRON)
// ===============================
$tasks = [
    [
        'name'     => 'LogGuardianSF Parser',
        'command'  => "$phpBinary $basePath/scripts/parser.php",
        'schedule' => '*/10 * * * *', // every 10 minutes
    ],
    [
        'name'     => 'LogGuardianSF Notifier',
        'command'  => "$phpBinary $basePath/scripts/notifier.php",
        'schedule' => '0 * * * *', // every hour
    ],
];

foreach ($tasks as $task) {
    $cmd = "plesk bin task --create '{$task['name']}' "
         . "-schedule '{$task['schedule']}' "
         . "-cmd '{$task['command']}' "
         . "-enabled true 2>&1";

    logMessage("Creating CRON task: {$task['name']}");
    $output = shell_exec($cmd);
    logMessage($output);
}

// ===============================
// Set execution permissions
// ===============================
$scripts = [
    "$basePath/scripts/parser.php",
    "$basePath/scripts/notifier.php",
];

foreach ($scripts as $script) {
    if (file_exists($script)) {
        chmod($script, 0755);
        logMessage("Execution permissions set for: $script");
    } else {
        logMessage("⚠️  Script not found: $script");
    }
}

logMessage("✅ Automatic installation completed successfully.");
