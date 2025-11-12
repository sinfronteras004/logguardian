<?php
/**
 * Configuración del Sistema de Notificaciones
 * LogGuardianSF
 */

return [
    // =============================
    // ACTIVAR/DESACTIVAR
    // =============================
    'enabled' => true,  // true = activo, false = desactivado
    
    // =============================
    // FRECUENCIA DE NOTIFICACIONES
    // =============================
    'frequency' => 'digest',  // 'digest' = agrupadas
    'digest_hours' => 6,      // Cada 6 horas
    
    // =============================
    // NIVELES DE ALERTA
    // =============================
    'alert_levels' => [
        'critical' => [
            'enabled' => true,
            'immediate' => true,  // Enviar inmediatamente
            'min_occurrences' => 1
        ],
        'high' => [
            'enabled' => true,
            'immediate' => false,
            'min_occurrences' => 3
        ],
        'suspicious' => [
            'enabled' => true,
            'immediate' => false,
            'min_occurrences' => 5
        ]
    ],
    
    // =============================
    // WHITELIST (IPs a ignorar)
    // =============================
    'whitelist' => [
        '127.0.0.1',
        '::1',
    ],
    
    'whitelist_agents' => [
        'Googlebot',
        'Bingbot',
        'facebookexternalhit',
        'Slackbot',
    ],
    
    // =============================
    // UMBRALES
    // =============================
    'thresholds' => [
        'min_suspicious_count' => 1,
        'max_ips_per_email' => 50,
    ],
    
    // =============================
    // ARCHIVOS
    // =============================
    'data_dir' => '/var/modules/logguardianSF/',
    'log_file' => '/var/modules/logguardianSF/logguardian_data.log',
    'notified_log' => '/var/modules/logguardianSF/notified_ips.log',
    'last_notification' => '/var/modules/logguardianSF/last_notification.txt',
    'email_log' => '/var/modules/logguardianSF/email.log',
    
    // =============================
    // FORMATO
    // =============================
    'email_format' => 'html',
    'include_log_samples' => true,
    'max_samples_per_ip' => 3,
];

