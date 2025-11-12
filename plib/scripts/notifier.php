<?php
/**
 * Sistema de Notificaciones por Correo
 * LogGuardianSF
 * 
 * SIEMPRE ENVÍA - Incluso si no hay amenazas (modo "heartbeat")
 * Ejecutar vía CRON cada 6 horas
 */

date_default_timezone_set('UTC');

// Cargar configuración
$config = require_once __DIR__ . '/notifier-config.php';

// Verificar si está habilitado
if (!$config['enabled']) {
    exit(0);
}

// =============================
// LEER LOGS
// =============================
$logFile = $config['log_file'];

$suspiciousIPs = [];
$totalLines = 0;
$cutoffTime = time() - ($config['digest_hours'] * 3600);

if (file_exists($logFile)) {
    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $totalLines = count($lines);
    
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        if (count($parts) < 9) continue;
        
        $datetime = strtotime($parts[0]);
        if ($datetime < $cutoffTime) continue;
        
        $ip = trim($parts[2]);
        $agent = strtolower(trim($parts[8]));
        $request = strtolower(trim($parts[4]));
        $code = trim($parts[5]);
        
        // Verificar whitelist
        if (isWhitelisted($ip, $agent, $config)) continue;
        
        // Detectar nivel
        $level = detectThreatLevel($parts, $config);
        
        if ($level !== 'safe') {
            if (!isset($suspiciousIPs[$ip])) {
                $suspiciousIPs[$ip] = [
                    'level' => $level,
                    'count' => 0,
                    'first_seen' => $parts[0],
                    'last_seen' => $parts[0],
                    'domains' => [],
                    'samples' => []
                ];
            }
            
            $suspiciousIPs[$ip]['count']++;
            $suspiciousIPs[$ip]['last_seen'] = $parts[0];
            $suspiciousIPs[$ip]['domains'][] = $parts[1];
            
            if (count($suspiciousIPs[$ip]['samples']) < $config['max_samples_per_ip']) {
                $suspiciousIPs[$ip]['samples'][] = [
                    'datetime' => $parts[0],
                    'domain' => $parts[1],
                    'method' => $parts[3],
                    'request' => $parts[4],
                    'code' => $code,
                    'agent' => $parts[8]
                ];
            }
            
            // Upgrade threat level if needed
            if ($level === 'critical') {
                $suspiciousIPs[$ip]['level'] = 'critical';
            } elseif ($level === 'high' && $suspiciousIPs[$ip]['level'] === 'suspicious') {
                $suspiciousIPs[$ip]['level'] = 'high';
            }
        }
    }
}

// =============================
// FILTRAR POR UMBRALES
// =============================
$toNotify = [];

foreach ($suspiciousIPs as $ip => $data) {
    $levelConfig = $config['alert_levels'][$data['level']];
    
    if (!$levelConfig['enabled']) continue;
    
    if ($data['count'] >= $levelConfig['min_occurrences']) {
        $toNotify[$ip] = $data;
    }
}

// =============================
// AGRUPAR POR NIVEL
// =============================
$grouped = [
    'critical' => [],
    'high' => [],
    'suspicious' => []
];

foreach ($toNotify as $ip => $data) {
    $grouped[$data['level']][$ip] = $data;
}

// =============================
// GENERAR Y ENVIAR CORREO
// (SIEMPRE - incluso si no hay amenazas)
// =============================
$hasThreats = !empty($toNotify);

if ($hasThreats) {
    // Hay amenazas - enviar alerta normal
    $emailBody = generateEmailBody($grouped, $config, $totalLines);
    $subject = generateSubject($grouped);
} else {
    // NO hay amenazas - enviar reporte de "Todo OK"
    $emailBody = generateSafeEmailBody($config, $totalLines, count($suspiciousIPs));
    $subject = "✅ OK - LogGuardianSF Report - " . gethostname();
}

sendEmail($subject, $emailBody, $config);

// =============================
// REGISTRAR
// =============================
file_put_contents($config['last_notification'], time());

if ($hasThreats) {
    foreach ($toNotify as $ip => $data) {
        $logEntry = sprintf(
            "[%s] IP: %s | Level: %s | Count: %d\n",
            date('Y-m-d H:i:s'),
            $ip,
            $data['level'],
            $data['count']
        );
        file_put_contents($config['notified_log'], $logEntry, FILE_APPEND);
    }
    echo "✓ Alert sent: " . count($toNotify) . " suspicious IPs\n";
} else {
    $logEntry = sprintf(
        "[%s] Status report sent: No threats detected\n",
        date('Y-m-d H:i:s')
    );
    file_put_contents($config['notified_log'], $logEntry, FILE_APPEND);
    echo "✓ Status report sent: All clear\n";
}

// =============================
// FUNCIONES
// =============================

function isWhitelisted($ip, $agent, $config)
{
    if (in_array($ip, $config['whitelist'])) {
        return true;
    }
    
    foreach ($config['whitelist_agents'] as $pattern) {
        if (stripos($agent, strtolower($pattern)) !== false) {
            return true;
        }
    }
    
    return false;
}

function detectThreatLevel($parts, $config)
{
    $code = trim($parts[5]);
    $agent = strtolower(trim($parts[8]));
    $request = strtolower(trim($parts[4]));
    
    // CRITICAL
    $criticalTools = ['masscan', 'nmap', 'sqlmap', 'nikto', 'metasploit', 'attack', 'exploit'];
    foreach ($criticalTools as $tool) {
        if (strpos($agent, $tool) !== false) {
            return 'critical';
        }
    }
    
    if (strpos($request, 'union select') !== false || 
        strpos($request, '<script') !== false ||
        strpos($request, '../') !== false) {
        return 'critical';
    }
    
    // HIGH
    if (strpos($request, 'phpmyadmin') !== false ||
        strpos($request, 'wp-admin') !== false ||
        strpos($request, '.env') !== false) {
        return 'high';
    }
    
    // SUSPICIOUS
    if (strpos($agent, 'bot') !== false ||
        strpos($agent, 'crawler') !== false ||
        strpos($agent, 'scan') !== false) {
        return 'suspicious';
    }
    
    return 'safe';
}

function generateSubject($grouped)
{
    $total = count($grouped['critical']) + count($grouped['high']) + count($grouped['suspicious']);
    
    if (count($grouped['critical']) > 0) {
        return "🚨 CRITICAL: " . count($grouped['critical']) . " Attack IPs - " . gethostname();
    } elseif (count($grouped['high']) > 0) {
        return "⚠️ HIGH: " . count($grouped['high']) . " High-Risk IPs - " . gethostname();
    } else {
        return "⚠️ Alert: " . $total . " Suspicious IPs - " . gethostname();
    }
}

function generateSafeEmailBody($config, $totalLines, $lowPriorityCount)
{
    $period = $config['digest_hours'];
    
    $html = '<!DOCTYPE html>
<html>
<head>
<style>
body{font-family:Arial;line-height:1.6;color:#333;margin:0;padding:0}
.header{background:#4CAF50;color:#fff;padding:20px;text-align:center}
.container{padding:20px;max-width:800px;margin:0 auto}
.safe-section{margin:20px 0;padding:20px;background:#e8f5e9;border-left:4px solid #4CAF50;border-radius:4px}
.info-box{background:#f5f5f5;padding:15px;margin:15px 0;border-radius:4px}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd}
th{background:#e0e0e0}
.footer{margin-top:30px;padding-top:20px;border-top:1px solid #ddd;font-size:12px;color:#666;text-align:center}
</style>
</head>
<body>
<div class="header">
<h1>✅ LogGuardianSF Status Report</h1>
<p>All Clear - No Threats Detected</p>
<p>' . gethostname() . ' - ' . date('Y-m-d H:i:s') . ' UTC</p>
</div>
<div class="container">

<div class="safe-section">
<h2>🛡️ System Status: HEALTHY</h2>
<p>No security threats detected in the last <strong>' . $period . ' hours</strong>.</p>
</div>

<div class="info-box">
<h3>📊 Activity Summary</h3>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Reporting Period</td><td>Last ' . $period . ' hours</td></tr>
<tr><td>Total Log Lines Analyzed</td><td>' . number_format($totalLines) . '</td></tr>
<tr><td>🚨 Critical Threats</td><td><strong>0</strong></td></tr>
<tr><td>⚠️ High-Risk IPs</td><td><strong>0</strong></td></tr>
<tr><td>⚠️ Suspicious IPs</td><td><strong>0</strong></td></tr>
<tr><td>🔍 Low-Priority Detections</td><td>' . $lowPriorityCount . ' (below alert threshold)</td></tr>
</table>
</div>

<div class="info-box">
<h3>✅ What This Means</h3>
<ul>
<li>No attack attempts detected</li>
<li>No malicious scanning activity</li>
<li>All traffic appears legitimate</li>
<li>Server security is functioning normally</li>
</ul>
</div>

<div class="info-box">
<h3>⏰ Next Report</h3>
<p>Next automatic report will be sent in <strong>' . $period . ' hours</strong>.</p>
<p><strong>Next scheduled time:</strong> ' . date('Y-m-d H:i:s', time() + ($period * 3600)) . ' UTC</p>
</div>

<div class="footer">
<p><strong>LogGuardianSF</strong> - Automated Security Monitoring</p>
<p>This is an automated status report. If you did not expect this email, please check your notification settings.</p>
<p>Dashboard: <a href="https://' . gethostname() . ':8443/modules/LogGuardianSF/">View Details</a></p>
</div>

</div>
</body>
</html>';
    
    return $html;
}

function generateEmailBody($grouped, $config, $totalLines)
{
    $period = $config['digest_hours'];
    
    $html = '<!DOCTYPE html>
<html>
<head>
<style>
body{font-family:Arial;line-height:1.6;color:#333;margin:0;padding:0}
.header{background:#d32f2f;color:#fff;padding:20px;text-align:center}
.container{padding:20px;max-width:800px;margin:0 auto}
.section{margin:20px 0;padding:15px;border-left:4px solid #ccc}
.critical{border-left-color:#d32f2f;background:#ffebee}
.high{border-left-color:#f57c00;background:#fff3e0}
.suspicious{border-left-color:#fbc02d;background:#fffde7}
.ip-block{margin:10px 0;padding:10px;background:#fff;border-radius:4px}
.ip{font-weight:bold;font-size:16px;color:#d32f2f}
.details{font-size:13px;color:#666;margin:5px 0}
.sample{background:#f5f5f5;padding:8px;margin:5px 0;font-size:12px;font-family:monospace;word-break:break-all}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd}
th{background:#e0e0e0}
.footer{margin-top:30px;padding-top:20px;border-top:1px solid #ddd;font-size:12px;color:#666;text-align:center}
</style>
</head>
<body>
<div class="header">
<h1>🛡️ LogGuardianSF Security Alert</h1>
<p>Threats Detected</p>
<p>' . gethostname() . ' - ' . date('Y-m-d H:i:s') . ' UTC</p>
</div>
<div class="container">';
    
    $totalCritical = count($grouped['critical']);
    $totalHigh = count($grouped['high']);
    $totalSuspicious = count($grouped['suspicious']);
    $totalAll = $totalCritical + $totalHigh + $totalSuspicious;
    
    $html .= '<h2>📊 Summary (Last ' . $period . ' hours)</h2>
    <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Log Lines</td><td>' . number_format($totalLines) . '</td></tr>
    <tr><td>Total Threats Detected</td><td><strong>' . $totalAll . '</strong></td></tr>
    </table>
    
    <table style="margin-top:15px">
    <tr><th>Threat Level</th><th>Count</th><th>Action Required</th></tr>
    <tr style="background:#ffebee"><td>🚨 CRITICAL</td><td><strong>' . $totalCritical . '</strong></td><td><b>Block immediately</b></td></tr>
    <tr style="background:#fff3e0"><td>⚠️ HIGH</td><td><strong>' . $totalHigh . '</strong></td><td>Review & consider blocking</td></tr>
    <tr style="background:#fffde7"><td>⚠️ SUSPICIOUS</td><td><strong>' . $totalSuspicious . '</strong></td><td>Monitor closely</td></tr>
    </table>';
    
    // CRITICAL
    if (!empty($grouped['critical'])) {
        $html .= '<div class="section critical"><h2>🚨 CRITICAL THREATS (' . count($grouped['critical']) . ')</h2>';
        foreach (array_slice($grouped['critical'], 0, $config['thresholds']['max_ips_per_email']) as $ip => $data) {
            $html .= generateIPBlock($ip, $data, $config);
        }
        $html .= '</div>';
    }

    // HIGH
    if (!empty($grouped['high'])) {
        $html .= '<div class="section high"><h2>⚠️ HIGH RISK (' . count($grouped['high']) . ')</h2>';
        foreach (array_slice($grouped['high'], 0, $config['thresholds']['max_ips_per_email']) as $ip => $data) {
            $html .= generateIPBlock($ip, $data, $config);
        }
        $html .= '</div>';
    }
    
    // SUSPICIOUS
    if (!empty($grouped['suspicious'])) {
        $html .= '<div class="section suspicious"><h2>⚠️ SUSPICIOUS (' . count($grouped['suspicious']) . ')</h2>';
        foreach (array_slice($grouped['suspicious'], 0, $config['thresholds']['max_ips_per_email']) as $ip => $data) {
            $html .= generateIPBlock($ip, $data, $config);
        }
        $html .= '</div>';
    }
    
    $html .= '<div class="footer">
    <p><strong>LogGuardianSF</strong> - Automated Security Monitoring</p>
    <p>Dashboard: <a href="https://' . gethostname() . ':8443/modules/LogGuardianSF/">View Full Report</a></p>
    </div>';
    
    $html .= '</div></body></html>';
    
    return $html;
}


function generateIPBlock($ip, $data, $config)
{
    $html = '<div class="ip-block">
    <div class="ip">' . htmlspecialchars($ip) . '</div>
    <div class="details">
    <b>Level:</b> ' . strtoupper($data['level']) . ' | 
    <b>Occurrences:</b> ' . $data['count'] . ' | 
    <b>First:</b> ' . $data['first_seen'] . ' | 
    <b>Last:</b> ' . $data['last_seen'] . '
    </div>
    <div class="details"><b>Domains:</b> ' . implode(', ', array_unique($data['domains'])) . '</div>';
    
    if ($config['include_log_samples'] && !empty($data['samples'])) {
        $html .= '<div style="margin-top:8px"><b>Sample Requests:</b></div>';
        foreach ($data['samples'] as $sample) {
            $html .= '<div class="sample">';
            $html .= htmlspecialchars($sample['datetime']) . ' | ';
            $html .= htmlspecialchars($sample['method']) . ' ';
            $html .= htmlspecialchars($sample['request']) . ' | ';
            $html .= 'HTTP ' . htmlspecialchars($sample['code']);
            $html .= '</div>';
        }
    }
    
    $html .= '</div>';
    return $html;
}

function sendEmail($subject, $body, $config)
{
    require_once __DIR__ . '/../library/GmailMailer.php';
    
    try {
        $mailer = new GmailMailer();
        $result = $mailer->sendAlert($subject, $body);
        
        if ($result['success']) {
            $logEntry = sprintf(
                "[%s] Email sent: %s\n",
                date('Y-m-d H:i:s'),
                $subject
            );
            file_put_contents($config['email_log'], $logEntry, FILE_APPEND);
        }
    } catch (Exception $e) {
        error_log("Notifier error: " . $e->getMessage());
    }
}


