<?php
/**
 * LogGuardianSF Parser v3.8 (fix duplicados)
 * Basado 100% en v3.7 original
 * Fixes:
 *   ✔ Manejo correcto de rotación de logs (inode)
 *   ✔ Reinicio del offset cuando el log se trunca o rota
 *   ✔ Nunca volver a procesar líneas previas
 */

$vhosts_base = '/var/www/vhosts';
$data_dir = '/var/modules/logguardianSF';

if (!is_dir($data_dir)) {
    @mkdir($data_dir, 0755, true);
}

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

$retention_days = 7;
$alert_error_threshold = 10;
$critical_error_threshold = 20;
$suspicious_ip_threshold = 2;

function logError($msg) {
    global $data_dir;
    $ts = date('Y-m-d H:i:s');
    file_put_contents("$data_dir/parser_errors.log", "[$ts] $msg\n", FILE_APPEND);
}

/* ================================================
 * FIX PRINCIPAL: Leer offset seguro con inode
 * ================================================ */
function getSafeOffset($file, $posfile) {

    $inode_file = $posfile . "_inode";
    $current_inode = fileinode($file);
    $saved_inode = file_exists($inode_file) ? (int)file_get_contents($inode_file) : 0;

    // Rotación detectada → reiniciar
    if ($saved_inode !== $current_inode) {
        file_put_contents($inode_file, $current_inode);
        return 0;
    }

    // Leer offset guardado
    $last = file_exists($posfile) ? (int)file_get_contents($posfile) : 0;

    // Si el log se achicó (truncado/rotado), reiniciar
    $size = filesize($file);
    if ($last > $size) $last = 0;

    file_put_contents($inode_file, $current_inode);

    return $last;
}

/* ================================================
 * Buscar todos los logs del dominio
 * ================================================ */
function findDomains($base, $patterns) {

    $result = [];

    if (!is_dir($base) || !is_readable($base)) {
        logError("No se puede acceder a $base");
        return [];
    }

    foreach (scandir($base) ?: [] as $dir) {
        if ($dir[0] === '.' || $dir === 'system') continue;

        $path1 = "$base/$dir/logs";
        $path2 = "$base/system/$dir/logs";

        $paths = [];

        if (is_dir($path1)) $paths[] = $path1;
        if (is_dir($path2)) $paths[] = $path2;

        foreach ($paths as $path) {
            foreach (scandir($path) ?: [] as $file) {
                foreach ($patterns as $p) {
                    if (stripos($file, $p) !== false) {

                        $f = "$path/$file";

                        if (is_file($f) && is_readable($f) && filesize($f) > 0) {
                            $result[$dir][] = $f;
                        }

                        break;
                    }
                }
            }
        }
    }

    return $result;
}

/* ================================================
 * Procesar ACCESS LOG
 * ================================================ */
function processAccessLog($domain, $file, $posfile) {

    $entries = [];
    $errors = [];
    $size = @filesize($file);

    if (!$size) return [$entries, $errors];

    // FIX antiduplicados
    $last = getSafeOffset($file, $posfile);

    $fp = @fopen($file, 'r');
    if (!$fp) return [$entries, $errors];

    fseek($fp, $last);

    //$regex = '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/';
    $regex = '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) (.*?) (HTTP\/[\d\.]+|HTTP\/\d)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"/';

    while (($line = fgets($fp)) !== false) {

        if (preg_match($regex, $line, $m)) {

            [$ip, $dt, $method, $url, $code, $bytes, $ref, $ua] =
                [$m[1], $m[2], $m[3], $m[4], (int)$m[5], $m[6], $m[7] ?? '-', $m[8] ?? '-'];

            $ts = date('Y-m-d H:i:s', strtotime($dt));
            $entries[] = "$ts | $domain | $ip | $method | $url | $code | $bytes | $ref | $ua\n";

            $is_error = in_array($code, [400,401,403,404,405,408,429,500,502,503]);
            $is_tool  = preg_match('/sqlmap|wpscan|burp|acunetix|nmap|masscan|nikto|metasploit/i', $ua);
            $is_bot   = ($ref === '-' && preg_match('/bot|crawler|spider|scraper/i', $ua));

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

/* ================================================
 * Procesar ERROR LOG
 * ================================================ */
function processErrorLog($domain, $file, $posfile) {

    $entries = [];
    $errors = [];

    if (!filesize($file)) return [$entries, $errors];

    // FIX antiduplicados
    $last = getSafeOffset($file, $posfile);

    $fp = @fopen($file, 'r');
    if (!$fp) return [$entries, $errors];

    fseek($fp, $last);

    while (($line = fgets($fp)) !== false) {

        if (preg_match('/\[(.*?)\].*?client[:\s]+(\S+)/', $line, $m)) {

            $dt = $m[1];
            $ip = $m[2];
            $ts = date('Y-m-d H:i:s', strtotime($dt));

            $entries[] = "$ts | $domain | $ip | ERROR | - | - | - | - | Error: " . trim($line) . "\n";

            $errors[$ip]['times'][] = strtotime($dt);
            $errors[$ip]['flags'][] = 'error';

        } else {

            $ts = date('Y-m-d H:i:s');
            $entries[] = "$ts | $domain | - | ERROR | - | - | - | - | " . trim($line) . "\n";
        }
    }

    file_put_contents($posfile, ftell($fp));
    fclose($fp);

    return [$entries, $errors];
}

/* ================================================
 * Elegir tipo de log
 * ================================================ */
function processLog($domain, $file, $posfile) {
    return (stripos(basename($file), 'error') !== false)
        ? processErrorLog($domain, $file, $posfile)
        : processAccessLog($domain, $file, $posfile);
}

/* ================================================
 * Alertas
 * ================================================ */
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
            file_put_contents($crit_file, "$ts | [$domain] $ip | errores recientes ($count en 10min)\n", FILE_APPEND);
            $criticals++;
        } elseif ($count >= $alert_error_threshold || in_array('bot', $flags)) {
            file_put_contents($alert_file, "$ts | [$domain] $ip | actividad sospechosa ($count errores)\n", FILE_APPEND);
            $alerts++;
        }
    }

    return [$alerts, $criticals];
}

/* ================================================
 * MAIN
 * ================================================ */
try {

    echo "=== LogGuardianSF v3.8 (anti-duplicados) ===\n";

    $domains = findDomains($vhosts_base, $log_name_patterns);

    if (!$domains) {
        echo "⚠ No se encontraron logs.\n";
        exit(1);
    }

    $datafile = "$data_dir/logguardian_data.log";
    $total = $alerts = $criticals = $suspicious = 0;

    foreach ($domains as $domain => $logs) {

        echo "--- Procesando dominio: $domain ---\n";

        foreach ($logs as $log) {

            $logname = basename($log);
            $pos = "$data_dir/position_" . md5($log) . ".txt";

            echo "  Procesando $logname ... ";

            [$entries, $errors] = processLog($domain, $log, $pos);

            if ($entries) {
                file_put_contents($datafile, $entries, FILE_APPEND);
                echo count($entries) . " nuevas\n";
            } else {
                echo "0 nuevas\n";
            }

            [$a, $c] = analyzeAlerts($domain, $errors);

            $total += count($entries);
            $alerts += $a;
            $criticals += $c;
            $suspicious += count($errors);
        }
        echo "\n";
    }

    echo "✔ Procesamiento completado.\n";

} catch (Throwable $e) {
    logError("Fatal: " . $e->getMessage());
    echo "✗ ERROR: " . $e->getMessage() . "\n";
    exit(1);
}

?>
