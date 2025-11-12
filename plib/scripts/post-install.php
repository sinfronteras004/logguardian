<?php
/**
 * post-install.php
 * 
 * Este script se ejecuta automáticamente después de instalar o actualizar
 * la extensión LogGuardianSF en Plesk.
 *
 * Su función es:
 *  - Crear las tareas CRON (parser y notifier)
 *  - Asegurar permisos de ejecución en los scripts
 *  - Registrar mensajes en el log de instalación
 */

date_default_timezone_set('UTC');

$basePath = '/usr/local/psa/admin/plib/modules/LogGuardianSF';
$logFile  = "$basePath/install_log.txt";

// Registrar log
function logMessage($msg) {
    global $logFile;
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] " . $msg . "\n", FILE_APPEND);
    echo $msg . "\n";
}

logMessage("=== Iniciando instalación automática de LogGuardianSF ===");

// Detectar versión PHP disponible (prioriza 8.3, luego 8.2)
$phpBinary = null;
if (file_exists('/opt/plesk/php/8.3/bin/php')) {
    $phpBinary = '/opt/plesk/php/8.3/bin/php';
} elseif (file_exists('/opt/plesk/php/8.2/bin/php')) {
    $phpBinary = '/opt/plesk/php/8.2/bin/php';
} else {
    logMessage("⚠️  No se encontró PHP 8.2/8.3 en /opt/plesk/php/. Las tareas no se crearán.");
    exit(1);
}

logMessage("Usando binario PHP: $phpBinary");

// ===============================
// Crear tareas programadas (CRON)
// ===============================
$tasks = [
    [
        'name'     => 'LogGuardianSF Parser',
        'command'  => "$phpBinary $basePath/scripts/parser.php",
        'schedule' => '*/10 * * * *', // cada 10 minutos
    ],
    [
        'name'     => 'LogGuardianSF Notifier',
        'command'  => "$phpBinary $basePath/scripts/notifier.php",
        'schedule' => '0 * * * *', // cada hora
    ],
];

foreach ($tasks as $task) {
    $cmd = "plesk bin task --create '{$task['name']}' "
         . "-schedule '{$task['schedule']}' "
         . "-cmd '{$task['command']}' "
         . "-enabled true 2>&1";

    logMessage("Creando tarea CRON: {$task['name']}");
    $output = shell_exec($cmd);
    logMessage($output);
}

// ===============================
// Asignar permisos de ejecución
// ===============================
$scripts = [
    "$basePath/scripts/parser.php",
    "$basePath/scripts/notifier.php",
];

foreach ($scripts as $script) {
    if (file_exists($script)) {
        chmod($script, 0755);
        logMessage("Permisos asignados correctamente a: $script");
    } else {
        logMessage("⚠️  No se encontró el script: $script");
    }
}

logMessage("✅ Instalación automática completada.");
