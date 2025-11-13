<?php
/**
 * LogGuardianSF Parser v3.10.5 FINAL
 * - Multi dominio
 * - Sin duplicados (excluye processed/webstat)
 * - Salida estandarizada
 * - Fecha almacenada en UTC siempre
 */

$vhosts_base = '/var/www/vhosts';
$data_dir = '/var/modules/logguardianSF';

if (!is_dir($data_dir)) {
    @mkdir($data_dir, 0755, true);
}

/* ---------------------------------------------
 * Log names a buscar (solo nombres reales de Plesk)
 * --------------------------------------------- */
$log_name_patterns = [
    'access_log',
    'access_ssl_log',
    'proxy_access',
    'proxy_access_ssl',
    'error_log'
];

/* ---------------------------------------------
 * Buscar logs válidos por dominio, excluyendo duplicados
 * --------------------------------------------- */
function findDomains($base, $patterns) {
    $result = [];

    foreach (scandir($base) ?: [] as $dir) {
        if ($dir[0] === '.' || $dir === 'system') continue;

        $path = "$base/$dir/logs";
        if (!is_dir($path)) continue;

        foreach (scandir($path) ?: [] as $file) {
            // ❌ evitar duplicados por archivos innecesarios
            if (str_contains($file, 'processed')) continue;
            if (str_contains($file, 'webstat')) continue;

            foreach ($patterns as $p) {
                if (stripos($file, $p) !== false) {
                    $f = "$path/$file";
                    if (is_file($f) && is_readable($f)) {
                        $result[$dir][] = $f;
                    }
                }
            }
        }
    }

    return $result;
}

/* ---------------------------------------------
 * Procesar log
 * --------------------------------------------- */
function processLog($domain, $file, $posfile) {
    $entries = [];
    $size = @filesize($file);
    if (!$size) return $entries;

    $last = file_exists($posfile) ? (int)file_get_contents($posfile) : 0;
    if ($last > $size) $last = 0;

    $fp = @fopen($file, 'r');
    if (!$fp) return $entries;

    fseek($fp, $last);

    $regex = '/^(\S+) \S+ \S+ \[(.*?)\] "([A-Z]+) ([^"]*) HTTP\/[\d.]+" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/';

    while (($line = fgets($fp)) !== false) {

        if (!preg_match($regex, $line, $m)) {
            continue;
        }

        [$ip, $dt, $method, $url, $code, $bytes, $ref, $ua] = [
            $m[1],
            $m[2],
            $m[3],
            $m[4],
            (int)$m[5],
            $m[6],
            $m[7] ?? '-',
            $m[8] ?? '-'
        ];

        // Convertir fecha del log a UTC standard
        $ts = gmdate('Y-m-d H:i:s', strtotime($dt));

        // Guardar formato EXACTO del parser viejo
        $entries[] = "$ts | $domain | $ip | $method | $url | $code | $bytes | $ref | $ua\n";
    }

    file_put_contents($posfile, ftell($fp));
    fclose($fp);

    return $entries;
}

/* ---------------------------------------------
 * MAIN
 * --------------------------------------------- */
echo "=== LogGuardianSF Parser v3.10.5 FINAL ===\n";

$domains = findDomains($vhosts_base, $log_name_patterns);
if (!$domains) exit("No se encontraron logs.\n");

$datafile = "$data_dir/logguardian_data.log";

foreach ($domains as $domain => $logs) {

    echo "--- Dominio: $domain ---\n";

    foreach ($logs as $log) {

        $pos = "$data_dir/position_" . md5($log) . ".txt";

        $entries = processLog($domain, $log, $pos);

        $count = count($entries);

        echo "Procesando: " . basename($log) . " ... $count nuevas\n";

        if ($count > 0) {
            file_put_contents($datafile, $entries, FILE_APPEND);
        }
    }
}

echo "=== COMPLETADO ===\n";
?>
