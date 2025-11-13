<?php
/**
 * LogGuardianSF Parser v3.8 ENTERPRISE - Universal Multi-Plesk
 * Compatible con múltiples versiones de Plesk y configuraciones
 * Auto-detecta estructura de directorios y formatos de log
 */

// ============================================================================
// CONFIGURACIÓN AUTO-DETECTABLE
// ============================================================================

$data_dir = '/var/modules/logguardianSF';

// Crear directorio si no existe
if (!is_dir($data_dir)) {
    @mkdir($data_dir, 0755, true);
}

// Detectar ubicación base de vhosts automáticamente
$possible_vhost_bases = [
    '/var/www/vhosts',           // Plesk en Linux estándar
    '/usr/local/psa/var/vhosts', // Plesk versiones antiguas
    '/home/vhosts',              // Algunas configuraciones personalizadas
];

$vhosts_base = null;
foreach ($possible_vhost_bases as $base) {
    if (is_dir($base) && is_readable($base)) {
        $vhosts_base = $base;
        break;
    }
}

if (!$vhosts_base) {
    die("✗ ERROR: No se pudo detectar la ubicación de vhosts de Plesk\n");
}

// Patrones de búsqueda ampliados
$log_name_patterns = [
    'access',
    'access_log',
    'access-log',
    'access_ssl_log',
    'access_ssl',
    'error',
    'error_log',
    'error-log',
    'error_ssl_log',
    'proxy',
    'proxy_access',
    'proxy_access_log',
    'proxy_access_ssl_log',
    'proxy_error_log',
    'ssl_access_log',
    'ssl_error_log',
    'httpd_access',
    'httpd_error',
    'nginx_access',
    'nginx_error'
];

// Configuración
$retention_days = 7;
$alert_error_threshold = 10;
$critical_error_threshold = 20;
$suspicious_ip_threshold = 2;

// ============================================================================
// FUNCIONES DE UTILIDAD
// ============================================================================

function logError($msg) {
    global $data_dir;
    $ts = date('Y-m-d H:i:s');
    file_put_contents("$data_dir/parser_errors.log", "[$ts] $msg\n", FILE_APPEND);
}

function logDebug($msg) {
    global $data_dir;
    $ts = date('Y-m-d H:i:s');
    file_put_contents("$data_dir/parser_debug.log", "[$ts] $msg\n", FILE_APPEND);
}

/* ---------------------------------------------------
 * Detectar versión de Plesk
 * --------------------------------------------------- */
function detectPleskVersion() {
    $version_file = '/usr/local/psa/version';
    if (file_exists($version_file)) {
        $content = file_get_contents($version_file);
        if (preg_match('/^(\d+\.\d+)/', $content, $m)) {
            return $m[1];
        }
    }
    return 'unknown';
}

/* ---------------------------------------------------
 * Buscar logs en múltiples ubicaciones posibles
 * --------------------------------------------------- */
function findDomains($base, $patterns) {
    $result = [];
    
    if (!is_dir($base) || !is_readable($base)) {
        logError("No se puede acceder a $base");
        return $result;
    }
    
    logDebug("Buscando dominios en: $base");
    
    foreach (scandir($base) ?: [] as $dir) {
        if ($dir[0] === '.' || $dir === 'system' || $dir === 'default' || $dir === 'chroot') {
            continue;
        }
        
        $domain_path = "$base/$dir";
        if (!is_dir($domain_path)) continue;
        
        // Lista de posibles ubicaciones de logs para cada dominio
        $possible_log_locations = [
            "$domain_path/logs",                    // Ubicación estándar
            "$base/system/$dir/logs",               // Ubicación system
            "$domain_path/statistics/logs",         // Logs de estadísticas
            "$domain_path/var/log",                 // Ubicación alternativa
        ];
        
        foreach ($possible_log_locations as $path) {
            if (!is_dir($path) || !is_readable($path)) continue;
            
            logDebug("Escaneando: $path");
            
            foreach (scandir($path) ?: [] as $file) {
                // Saltar archivos comprimidos por ahora
                if (preg_match('/\.(gz|bz2|zip)$/i', $file)) {
                    continue;
                }
                
                // Buscar coincidencia con patrones
                foreach ($patterns as $p) {
                    if (stripos($file, $p) !== false) {
                        $f = "$path/$file";
                        $size = @filesize($f);
                        
                        // Solo agregar si es legible y tiene contenido
                        if (is_file($f) && is_readable($f) && $size > 0) {
                            // Marcar ubicación especial
                            $location_type = 'standard';
                            if (strpos($path, '/system/') !== false) {
                                $location_type = 'system';
                            } elseif (strpos($path, '/statistics/') !== false) {
                                $location_type = 'statistics';
                            }
                            
                            $result[$dir][] = [
                                'path' => $f,
                                'size' => $size,
                                'type' => $location_type
                            ];
                            
                            logDebug("Encontrado: $f ($size bytes) [$location_type]");
                            break;
                        }
                    }
                }
            }
        }
    }
    
    return $result;
}

/* ---------------------------------------------------
 * Procesar log de acceso con múltiples formatos
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
    
    // Múltiples patrones de regex para diferentes formatos
    $patterns = [
        // Apache/Nginx Combined Log Format
        '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/',
        // Apache Common Log Format
        '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)/',
        // Nginx error log con IP
        '/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) .*?client: (\S+)/',
    ];
    
    while (($line = fgets($fp)) !== false) {
        $matched = false;
        
        foreach ($patterns as $regex) {
            if (preg_match($regex, $line, $m)) {
                $matched = true;
                
                // Extraer datos según el formato
                if (count($m) >= 7) {
                    // Formato completo
                    [$ip, $dt, $method, $url, $code, $bytes, $ref, $ua] =
                        [$m[1], $m[2], $m[3], $m[4], (int)$m[5], $m[6], $m[7] ?? '-', $m[8] ?? '-'];
                } else {
                    // Formato simplificado
                    $ip = $m[1];
                    $dt = $m[2] ?? date('d/M/Y:H:i:s O');
                    $method = $m[3] ?? '-';
                    $url = $m[4] ?? '-';
                    $code = isset($m[5]) ? (int)$m[5] : 0;
                    $bytes = $m[6] ?? '-';
                    $ref = '-';
                    $ua = '-';
                }
                
                $ts = date('Y-m-d H:i:s', strtotime($dt));
                $entries[] = "$ts | $domain | $ip | $method | $url | $code | $bytes | $ref | $ua\n";
                
                // Análisis de amenazas
                $is_error = in_array($code, [400,401,403,404,405,408,429,500,502,503]);
                $is_tool = preg_match('/sqlmap|wpscan|burp|acunetix|nmap|masscan|nikto|metasploit|havij|grabber/i', $ua);
                $is_bot = ($ref === '-' && preg_match('/bot|crawler|spider|scraper|scanner/i', $ua));
                
                if ($is_error || $is_tool || $is_bot) {
                    $errors[$ip]['times'][] = strtotime($dt);
                    if ($is_tool) $errors[$ip]['flags'][] = 'tool';
                    if ($is_bot)  $errors[$ip]['flags'][] = 'bot';
                    if ($is_error) $errors[$ip]['flags'][] = 'error';
                }
                
                break;
            }
        }
        
        // Si no coincide con ningún patrón, registrar para debug
        if (!$matched && strlen(trim($line)) > 10) {
            logDebug("Línea no procesada en $file: " . substr($line, 0, 100));
        }
    }
    
    file_put_contents($posfile, ftell($fp));
    fclose($fp);
    
    return [$entries, $errors];
}

/* ---------------------------------------------------
 * Procesar log de errores
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
        // Múltiples formatos de error log
        $patterns = [
            '/\[(.*?)\].*?client[:\s]+(\S+)/',           // Apache error log
            '/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}).*?client: (\S+)/', // Nginx error
        ];
        
        $matched = false;
        foreach ($patterns as $regex) {
            if (preg_match($regex, $line, $m)) {
                $dt = $m[1];
                $ip = $m[2];
                $ts = date('Y-m-d H:i:s', strtotime($dt));
                
                $entries[] = "$ts | $domain | $ip | ERROR | - | - | - | - | " . trim($line) . "\n";
                
                $errors[$ip]['times'][] = strtotime($dt);
                $errors[$ip]['flags'][] = 'error';
                
                $matched = true;
                break;
            }
        }
        
        if (!$matched && strlen(trim($line)) > 10) {
            // Error sin IP identificable
            $ts = date('Y-m-d H:i:s');
            $entries[] = "$ts | $domain | - | ERROR | - | - | - | - | " . trim($line) . "\n";
        }
    }
    
    file_put_contents($posfile, ftell($fp));
    fclose($fp);
    
    return [$entries, $errors];
}

/* ---------------------------------------------------
 * Procesar log (auto-detectar tipo)
 * --------------------------------------------------- */
function processLog($domain, $file, $posfile) {
    $filename = basename($file);
    
    if (stripos($filename, 'error') !== false) {
        return processErrorLog($domain, $file, $posfile);
    } else {
        return processAccessLog($domain, $file, $posfile);
    }
}

/* ---------------------------------------------------
 * Analizar y generar alertas
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

// ============================================================================
// EJECUCIÓN PRINCIPAL
// ============================================================================

try {
    $plesk_version = detectPleskVersion();
    
    echo "=== LogGuardianSF v3.8 ENTERPRISE ===\n";
    echo "Sistema: Plesk $plesk_version\n";
    echo "Ubicación vhosts: $vhosts_base\n";
    echo "Patrones de búsqueda: " . count($log_name_patterns) . " patrones\n\n";
    
    $domains = findDomains($vhosts_base, $log_name_patterns);
    
    if (!$domains) {
        echo "⚠ ADVERTENCIA: No se encontraron logs procesables.\n";
        echo "\nPosibles causas:\n";
        echo "  • No hay dominios configurados en Plesk\n";
        echo "  • Los logs están en ubicaciones no estándar\n";
        echo "  • Permisos insuficientes\n";
        echo "\nRevisa: $data_dir/parser_debug.log\n";
        exit(1);
    }
    
    echo "Dominios encontrados: " . count($domains) . "\n\n";
    
    $total = 0;
    $alerts = 0;
    $criticals = 0;
    $suspicious = 0;
    $datafile = "$data_dir/logguardian_data.log";
    
    foreach ($domains as $domain => $logs) {
        echo "--- Procesando: $domain ---\n";
        
        foreach ($logs as $log_info) {
            $log = $log_info['path'];
            $logname = basename($log);
            $type = $log_info['type'];
            $size = $log_info['size'];
            
            echo "  $logname [$type] (" . number_format($size) . " bytes) ... ";
            
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
    echo str_repeat("=", 70) . "\n";
    echo "RESUMEN:\n";
    echo "  Total de entradas procesadas: $total\n";
    echo "  Alertas generadas: $alerts\n";
    echo "  Alertas críticas: $criticals\n";
    echo "  IPs sospechosas únicas: $suspicious\n";
    echo str_repeat("=", 70) . "\n";
    echo "\nArchivos generados:\n";
    echo "  → Datos: $datafile\n";
    echo "  → Alertas: $data_dir/logguardian_alerts.log\n";
    echo "  → Críticos: $data_dir/logguardian_critical.log\n";
    echo "  → Debug: $data_dir/parser_debug.log\n";
    
} catch (Throwable $e) {
    logError("Error fatal: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    echo "✗ ERROR FATAL: " . $e->getMessage() . "\n";
    echo "Revisa: $data_dir/parser_errors.log\n";
    exit(1);
}
?>
