<?php
/**
 * LogGuardianSF Parser v3.5 - Multi-Dominio + Detección Crítica
 * Compatible con el dashboard (formato “|”) y con manejo avanzado de alertas.
 */

$vhosts_base = '/var/www/vhosts';
$data_dir = '/var/modules/logguardianSF';

// Crear directorio si no existe
if (!is_dir($data_dir)) {
    @mkdir($data_dir, 0755, true);
}

// Patrones comunes de logs
$log_name_patterns = ['access', 'proxy', 'ssl', 'access_log', 'proxy_access', 'proxy_access_ssl'];

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
 * --------------------------------------------------- */
function findDomains($base, $patterns) {
    $result = [];
    foreach (scandir($base) ?: [] as $dir) {
        if ($dir[0] === '.' || $dir === 'system') continue;
        $path = "$base/$dir/logs";
        if (!is_dir($path)) continue;

        foreach (scandir($path) ?: [] as $file) {
            foreach ($patterns as $p) {
                if (stripos($file, $p) !== false) {
                    $f = "$path/$file";
                    if (is_file($f) && is_readable($f))
                        $result[$dir][] = $f;
                }
            }
        }
    }
    return $result;
}

/* ---------------------------------------------------
 * Procesar un log y extraer errores/sospechas
 * --------------------------------------------------- */
function processLog($domain, $file, $posfile) {
    $entries = [];
    $errors = [];
    $size = @filesize($file);
    if (!$size) return [$entries, $errors];

    $last = file_exists($posfile) ? (int)file_get_contents($posfile) : 0;
    if ($last > $size) $last = 0;

    $fp = @fopen($file, 'r');
    if (!$fp) return [$entries, $errors];
    fseek($fp, $last);

    $regex = '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/';
    while (($line = fgets($fp)) !== false) {
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
            }
        }
    }

    file_put_contents($posfile, ftell($fp));
    fclose($fp);
    return [$entries, $errors];
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
    echo "=== Iniciando procesamiento multi-dominio ===\n";
    $domains = findDomains($vhosts_base, $log_name_patterns);
    if (!$domains) exit("No se encontraron logs.\n");

    $total = 0; $alerts = 0; $criticals = 0; $suspicious = 0;
    $datafile = "$data_dir/logguardian_data.log";

    foreach ($domains as $domain => $logs) {
        echo "--- Procesando dominio: $domain ---\n";
        foreach ($logs as $log) {
            $pos = "$data_dir/position_" . md5($log) . ".txt";
            [$entries, $errors] = processLog($domain, $log, $pos);
            if ($entries) file_put_contents($datafile, $entries, FILE_APPEND);
            [$a, $c] = analyzeAlerts($domain, $errors);

            $total += count($entries);
            $alerts += $a;
            $criticals += $c;
            $suspicious += count($errors);
        }
    }

    echo "✅ Procesamiento completado.\n";
    echo "Activity Summary: Total: $total | Errors: $alerts | Critical: $criticals | Suspicious IPs: $suspicious\n";
    echo "Archivos:\n - $datafile\n - $data_dir/logguardian_alerts.log\n - $data_dir/logguardian_critical.log\n";

} catch (Throwable $e) {
    logError("Error: " . $e->getMessage());
}
?>


