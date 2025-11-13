<?php
/**
 * LogGuardianSF Parser v3.7 - Multi-Dominio + Múltiples Ubicaciones
 * Compatible con el dashboard (formato "|") y con manejo avanzado de alertas.
 * ACTUALIZADO: Busca logs en /logs Y en /system/domain/logs
 */
$vhosts_base = '/var/www/vhosts';
$data_dir = '/var/modules/logguardianSF';

// Crear directorio si no existe
if (!is_dir($data_dir)) {
    @mkdir($data_dir, 0755, true);
}

// Patrones comunes de logs - ACTUALIZADO para incluir error_log
$log_name_patterns = [
    'access',
    'access_log', 
    'access_ssl_log',
    'error',
    'error_log',
    'error_ssl_log',
    'proxy',
    'proxy_access',
    'proxy_access_log',
    'proxy_access_ssl_log',
    'proxy_error_log',
    'ssl_access_log',
    'ssl_error_log'
];

// Configuración general
$retention_days = 7;
$alert_error_threshold = 10;      // errores 4xx/5xx para alerta
$critical_error_threshold = 20;   // errores en 10 min = CRÍTICO
$suspicious_ip_threshold = 2;     // patrones sospechosos mínimos

function logError($msg) {
    global $data_dir;
    $ts = date('Y-m-d H:i:s');
    file_put_contents("$data_dir/parser_errors.log", "[$ts] $msg\n", FILE_APPEND);
}

/* ---------------------------------------------------
 * Buscar todos los dominios con logs accesibles
 * ACTUALIZADO: Busca en AMBAS ubicaciones
 * --------------------------------------------------- */
function findDomains($base, $patterns) {
    $result = [];
    
    if (!is_dir($base) || !is_readable($base)) {
        logError("No se puede acceder a $base");
        return $result;
    }
    
    foreach (scandir($base) ?: [] as $dir) {
        if ($dir[0] === '.' || $dir === 'system') continue;
        
        // UBICACIÓN 1: /var/www/vhosts/domain/logs/
        $path1 = "$base/$dir/logs";
        
        // UBICACIÓN 2: /var/www/vhosts/system/domain/logs/
        $path2 = "$base/system/$dir/logs";
        
        $paths_to_check = [];
        if (is_dir($path1) && is_readable($path1)) {
            $paths_to_check[] = $path1;
        }
        if (is_dir($path2) && is_readable($path2)) {
            $paths_to_check[] = $path2;
        }
        
        foreach ($paths_to_check as $path) {
            foreach (scandir($path) ?: [] as $file) {
                // Buscar coincidencia con cualquier patrón
                foreach ($patterns as $p) {
                    if (stripos($file, $p) !== false) {
                        $f = "$path/$file";
                        // Solo agregar si el archivo tiene contenido
                        if (is_file($f) && is_readable($f) && filesize($f) > 0) {
                            $result[$dir][] = $f;
                            break; // Evitar duplicados si coincide con múltiples patrones
                        }
                    }
                }
            }
        }
    }
    
    return $result;
}

/* ---------------------------------------------------
 * Procesar un log de ACCESO y extraer errores/sospechas
 * --------------------------------------------------- */
function processAccessLog($domain, $file, $posfile) {
    $entries = [];
    $errors = [];
    $size = @filesize($file);
    
    if (!$size) return [$entries, $errors];
    
    $last = file_exists($posfile) ? (int)file_get_contents($posfile) : 0;
    if ($last > $size) $last = 0;
    
    $fp = @fopen($file, 'r');
    if (!$fp) return [$entries, $errors];
    
    fseek($fp, $last);
    
    // Regex para logs de acceso estilo Apache/Nginx
    $regex = '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/';
    
    $line_count = 0;
    while (($line = fgets($fp)) !== false) {
        $line_count++;
        if (preg_match($regex, $line, $m)) {
            [$ip, $dt, $method, $url, $code, $bytes, $ref, $ua] =
                [$m[1], $m[2], $m[3], $m[4], (int)$m[5], $m[6], $m[7] ?? '-', $m[8] ?? '-'];
            
            $ts = date('Y-m-d H:i:s', strtotime($dt));
            $entries[] = "$ts | $domain | $ip | $method | $url | $code | $bytes | $ref | $ua\n";
            
            $is_error = in_array($code, [400,401,403,404,405,408,429,500,502,503]);
            $is_tool = preg_match('/sqlmap|wpscan|burp|acunetix|nmap|masscan|nikto|metasploit/i', $ua);
            $is_bot = ($ref === '-' && preg_match('/bot|crawler|spider|scraper/i', $ua));
            
            if ($is_error || $is_tool || $is_bot) {
                $errors[$ip]['times'][] = strtotime($dt);
                if ($is_tool) $errors[$ip]['flags'][] = 'tool';
                if ($is_bot)  $errors[$ip]['flags'][] = 'bot';
                if ($is_error) $errors[$ip]['flags'][] = 'error';
            }
        }
    }
    
    file_put_contents($posfile, ftell($fp));
    fclose($fp);
    
    return [$entries, $errors];
}

/* ---------------------------------------------------
 * Procesar un log de ERRORES
 * --------------------------------------------------- */
function processErrorLog($domain, $file, $posfile) {
    $entries = [];
    $errors = [];
    $size = @filesize($file);
    
    if (!$size) return [$entries, $errors];
    
    $last = file_exists($posfile) ? (int)file_get_contents($posfile) : 0;
    if ($last > $size) $last = 0;
    
    $fp = @fopen($file, 'r');
    if (!$fp) return [$entries, $errors];
    
    fseek($fp, $last);
    
    while (($line = fgets($fp)) !== false) {
        // Intentar extraer información del error log
        // Formato común: [fecha] [nivel] [pid] mensaje
        if (preg_match('/\[(.*?)\].*?client[:\s]+(\S+)/', $line, $m)) {
            $dt = $m[1];
            $ip = $m[2];
            $ts = date('Y-m-d H:i:s', strtotime($dt));
            
            $entries[] = "$ts | $domain | $ip | ERROR | - | - | - | - | Error: " . trim($line) . "\n";
            
            // Contar como error
            $errors[$ip]['times'][] = strtotime($dt);
            $errors[$ip]['flags'][] = 'error';
        } else {
            // Log de error sin IP identificable
            $ts = date('Y-m-d H:i:s');
            $entries[] = "$ts | $domain | - | ERROR | - | - | - | - | " . trim($line) . "\n";
        }
    }
    
    file_put_contents($posfile, ftell($fp));
    fclose($fp);
    
    return [$entries, $errors];
}

/* ---------------------------------------------------
 * Procesar un log (detectar tipo automáticamente)
 * --------------------------------------------------- */
function processLog($domain, $file, $posfile) {
    $filename = basename($file);
    
    // Determinar tipo de log por el nombre
    if (stripos($filename, 'error') !== false) {
        return processErrorLog($domain, $file, $posfile);
    } else {
        return processAccessLog($domain, $file, $posfile);
    }
}

/* ---------------------------------------------------
 * Analizar errores y generar alertas/críticas
 * --------------------------------------------------- */
function analyzeAlerts($domain, $errors) {
    global $data_dir, $alert_error_threshold, $critical_error_threshold;
    
    $alert_file = "$data_dir/logguardian_alerts.log";
    $crit_file  = "$data_dir/logguardian_critical.log";
    
    $alerts = 0;
    $criticals = 0;
    
    foreach ($errors as $ip => $data) {
        $recent = array_filter($data['times'], fn($t) => $t > time() - 600);
        $count = count($recent);
        $flags = array_unique($data['flags'] ?? []);
        
        $ts = date('Y-m-d H:i:s');
        
        if ($count >= $critical_error_threshold || in_array('tool', $flags)) {
            $msg = "$ts | [$domain] $ip | errores recientes ($count en 10min), posible herramienta o ataque crítico detectado\n";
            file_put_contents($crit_file, $msg, FILE_APPEND);
            $criticals++;
        } elseif ($count >= $alert_error_threshold || in_array('bot', $flags)) {
            $msg = "$ts | [$domain] $ip | actividad sospechosa ($count errores/10min)\n";
            file_put_contents($alert_file, $msg, FILE_APPEND);
            $alerts++;
        }
    }
    
    return [$alerts, $criticals];
}

/* ---------------------------------------------------
 * MAIN EXECUTION
 * --------------------------------------------------- */
try {
    echo "=== LogGuardianSF v3.7 - Iniciando procesamiento multi-dominio ===\n";
    echo "Buscando logs en: $vhosts_base\n";
    echo "Ubicaciones: /domain/logs/ Y /system/domain/logs/\n";
    echo "Patrones de búsqueda: " . implode(', ', $log_name_patterns) . "\n\n";
    
    $domains = findDomains($vhosts_base, $log_name_patterns);
    
    if (!$domains) {
        echo "⚠ ADVERTENCIA: No se encontraron logs.\n";
        echo "Verificar:\n";
        echo "  1. Que existan dominios en $vhosts_base\n";
        echo "  2. Que tengan carpeta /logs o /system/domain/logs\n";
        echo "  3. Que los archivos de log coincidan con los patrones\n";
        echo "  4. Que tengas permisos de lectura\n";
        exit(1);
    }
    
    $total = 0; 
    $alerts = 0; 
    $criticals = 0; 
    $suspicious = 0;
    $datafile = "$data_dir/logguardian_data.log";
    
    foreach ($domains as $domain => $logs) {
        echo "--- Procesando dominio: $domain ---\n";
        
        foreach ($logs as $log) {
            $logname = basename($log);
            $logpath = dirname($log);
            echo "  Procesando: $logname";
            
            // Mostrar si es de la ubicación system
            if (strpos($logpath, '/system/') !== false) {
                echo " [system]";
            }
            echo " ... ";
            
            $pos = "$data_dir/position_" . md5($log) . ".txt";
            [$entries, $errors] = processLog($domain, $log, $pos);
            
            if ($entries) {
                file_put_contents($datafile, $entries, FILE_APPEND);
                echo "✓ " . count($entries) . " entradas\n";
            } else {
                echo "⚠ Sin nuevas entradas\n";
            }
            
            [$a, $c] = analyzeAlerts($domain, $errors);
            $total += count($entries);
            $alerts += $a;
            $criticals += $c;
            $suspicious += count($errors);
        }
        echo "\n";
    }
    
    echo "✅ Procesamiento completado.\n";
    echo str_repeat("=", 60) . "\n";
    echo "RESUMEN:\n";
    echo "  Total de entradas: $total\n";
    echo "  Alertas generadas: $alerts\n";
    echo "  Alertas críticas: $criticals\n";
    echo "  IPs sospechosas: $suspicious\n";
    echo str_repeat("=", 60) . "\n";
    echo "\nArchivos generados:\n";
    echo "  → Datos: $datafile\n";
    echo "  → Alertas: $data_dir/logguardian_alerts.log\n";
    echo "  → Críticos: $data_dir/logguardian_critical.log\n";
    
} catch (Throwable $e) {
    logError("Error fatal: " . $e->getMessage());
    echo "✗ ERROR: " . $e->getMessage() . "\n";
    exit(1);
}
?>
