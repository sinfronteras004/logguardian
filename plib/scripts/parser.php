<?php
/**
 * LogGuardianSF Parser v3.9 FINAL - Universal + ModSecurity Critical Detection
 * Combina: Patrones amplios de v3.8 + Detección ModSecurity mejorada
 */
$vhosts_base = '/var/www/vhosts';
$data_dir = '/var/modules/logguardianSF';

// Crear directorio si no existe
if (!is_dir($data_dir)) {
    @mkdir($data_dir, 0755, true);
}

// PATRONES AMPLIOS DE v3.8 - Máxima compatibilidad
$log_name_patterns = [
    'access',
    'access_log',
    'access-log',              // v3.8
    'access_ssl_log',
    'access_ssl',              // v3.8
    'error',
    'error_log',
    'error-log',               // v3.8
    'error_ssl_log',
    'proxy',
    'proxy_access',
    'proxy_access_log',
    'proxy_access_ssl_log',
    'proxy_error_log',
    'ssl_access_log',
    'ssl_error_log',
    'httpd_access',            // v3.8 - Apache
    'httpd_error',             // v3.8 - Apache
    'nginx_access',            // v3.8 - Nginx
    'nginx_error'              // v3.8 - Nginx
];

// Configuración general
$retention_days = 7;
$alert_error_threshold = 10;
$critical_error_threshold = 20;
$suspicious_ip_threshold = 2;

function logError($msg) {
    global $data_dir;
    $ts = date('Y-m-d H:i:s');
    file_put_contents("$data_dir/parser_errors.log", "[$ts] $msg\n", FILE_APPEND);
}

/* ---------------------------------------------------
 * Buscar dominios - v3.8 style (múltiples ubicaciones)
 * --------------------------------------------------- */
function findDomains($base, $patterns) {
    $result = [];
    
    if (!is_dir($base) || !is_readable($base)) {
        logError("No se puede acceder a $base");
        return $result;
    }
    
    foreach (scandir($base) ?: [] as $dir) {
        if ($dir[0] === '.' || $dir === 'system' || $dir === 'default' || $dir === 'chroot') {
            continue;
        }
        
        $domain_path = "$base/$dir";
        if (!is_dir($domain_path)) continue;
        
        // Múltiples ubicaciones posibles (v3.8)
        $possible_log_locations = [
            "$domain_path/logs",
            "$base/system/$dir/logs",
            "$domain_path/statistics/logs",
            "$domain_path/var/log",
        ];
        
        foreach ($possible_log_locations as $path) {
            if (!is_dir($path) || !is_readable($path)) continue;
            
            foreach (scandir($path) ?: [] as $file) {
                // Saltar archivos comprimidos
                if (preg_match('/\.(gz|bz2|zip)$/i', $file)) {
                    continue;
                }
                
                foreach ($patterns as $p) {
                    if (stripos($file, $p) !== false) {
                        $f = "$path/$file";
                        if (is_file($f) && is_readable($f) && filesize($f) > 0) {
                            $result[$dir][] = $f;
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
 * Procesar log de acceso - v3.8 style
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
    
    // Múltiples patrones (v3.8)
    $patterns = [
        '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/',
        '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)/',
    ];
    
    while (($line = fgets($fp)) !== false) {
        $matched = false;
        
        foreach ($patterns as $regex) {
            if (preg_match($regex, $line, $m)) {
                $matched = true;
                
                if (count($m) >= 7) {
                    [$ip, $dt, $method, $url, $code, $bytes, $ref, $ua] =
                        [$m[1], $m[2], $m[3], $m[4], (int)$m[5], $m[6], $m[7] ?? '-', $m[8] ?? '-'];
                } else {
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
                
                $is_error = in_array($code, [400,401,403,404,405,408,429,500,502,503]);
                $is_tool = preg_match('/sqlmap|wpscan|burp|acunetix|nmap|masscan|nikto|metasploit|havij|grabber|nessus|openvas|qualys|nexpose|rapid7/i', $ua);
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
    }
    
    file_put_contents($posfile, ftell($fp));
    fclose($fp);
    
    return [$entries, $errors];
}

/* ---------------------------------------------------
 * Procesar log de errores - v3.9 MEJORADO con ModSecurity
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
    
    // Lista ampliada de herramientas de hacking
    $attack_tools = [
        'sqlmap', 'nikto', 'wpscan', 'burp', 'acunetix', 
        'nmap', 'masscan', 'metasploit', 'havij', 'grabber',
        'nessus', 'openvas', 'qualys', 'nexpose', 'rapid7',
        'w3af', 'skipfish', 'arachni', 'zap', 'vega'
    ];
    
    while (($line = fgets($fp)) !== false) {
        $matched = false;
        
        // PATRÓN 1: ModSecurity blocking con client IP (CRÍTICO para v3.9)
        if (preg_match('/\[(.*?)\].*?\[client\s+(\S+?):\d*\].*?ModSecurity/i', $line, $m)) {
            $dt = $m[1];
            $ip = $m[2];
            $ts = date('Y-m-d H:i:s', strtotime($dt));
            
            // Detectar herramienta de hacking
            $is_attack_tool = false;
            $detected_tool = '';
            foreach ($attack_tools as $tool) {
                if (stripos($line, $tool) !== false) {
                    $is_attack_tool = true;
                    $detected_tool = $tool;
                    break;
                }
            }
            
            if ($is_attack_tool) {
                $entries[] = "$ts | $domain | $ip | BLOCKED | MODSECURITY | - | - | - | Herramienta detectada: $detected_tool\n";
                $errors[$ip]['times'][] = strtotime($dt);
                $errors[$ip]['flags'][] = 'tool';
                $errors[$ip]['flags'][] = 'modsecurity_block';
                $matched = true;
            } else {
                $entries[] = "$ts | $domain | $ip | BLOCKED | MODSECURITY | - | - | - | ModSecurity block\n";
                $errors[$ip]['times'][] = strtotime($dt);
                $errors[$ip]['flags'][] = 'modsecurity_block';
                $matched = true;
            }
        }
        // PATRÓN 2: Error log estándar con client
        elseif (preg_match('/\[(.*?)\].*?client[:\s]+(\S+)/', $line, $m)) {
            $dt = $m[1];
            $ip = $m[2];
            $ts = date('Y-m-d H:i:s', strtotime($dt));
            
            $entries[] = "$ts | $domain | $ip | ERROR | - | - | - | - | " . substr($line, 0, 200) . "\n";
            $errors[$ip]['times'][] = strtotime($dt);
            $errors[$ip]['flags'][] = 'error';
            $matched = true;
        }
        // PATRÓN 3: Nginx error log
        elseif (preg_match('/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}).*?client: (\S+)/', $line, $m)) {
            $dt = $m[1];
            $ip = $m[2];
            $ts = date('Y-m-d H:i:s', strtotime($dt));
            
            $entries[] = "$ts | $domain | $ip | ERROR | NGINX | - | - | - | " . substr($line, 0, 200) . "\n";
            $errors[$ip]['times'][] = strtotime($dt);
            $errors[$ip]['flags'][] = 'error';
            $matched = true;
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
 * Analizar errores - v3.9 MEJORADO
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
        
        // CRÍTICO: herramienta O ModSecurity block O muchos errores
        if (in_array('tool', $flags) || in_array('modsecurity_block', $flags) || $count >= $critical_error_threshold) {
            $reason = '';
            if (in_array('tool', $flags)) {
                $reason = "herramienta de ataque detectada";
            } elseif (in_array('modsecurity_block', $flags)) {
                $reason = "bloqueado por ModSecurity (posible ataque)";
            } else {
                $reason = "$count errores en 10 minutos";
            }
            
            $msg = "$ts | [$domain] $ip | CRÍTICO: $reason\n";
            file_put_contents($crit_file, $msg, FILE_APPEND);
            $criticals++;
        } 
        elseif ($count >= $alert_error_threshold || in_array('bot', $flags)) {
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
    echo "=== LogGuardianSF v3.9 FINAL - Universal + ModSecurity ===\n";
    echo "Buscando logs en: $vhosts_base\n";
    echo "Patrones: " . count($log_name_patterns) . " tipos de log\n";
    echo "Ubicaciones: /logs, /system/logs, /statistics/logs, /var/log\n";
    echo "Detección: ModSecurity + Herramientas + Bots\n\n";
    
    $domains = findDomains($vhosts_base, $log_name_patterns);
    
    if (!$domains) {
        echo "⚠ ADVERTENCIA: No se encontraron logs.\n";
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
            
            if (strpos($logpath, '/system/') !== false) {
                echo " [system]";
            } elseif (strpos($logpath, '/statistics/') !== false) {
                echo " [stats]";
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
    
} catch (Throwable $e) {
    logError("Error fatal: " . $e->getMessage());
    echo "✗ ERROR: " . $e->getMessage() . "\n";
    exit(1);
}
?>
