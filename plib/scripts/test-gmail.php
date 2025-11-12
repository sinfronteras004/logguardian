<?php
/**
 * Script de prueba de configuración de Gmail
 * LogGuardianSF_Test
 * 
 * Uso:
 * /opt/plesk/php/8.3/bin/php test-gmail.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "\n";
echo "╔════════════════════════════════════════════════════════════╗\n";
echo "║     LogGuardianSF - Gmail Configuration                    ║\n";
echo "╚════════════════════════════════════════════════════════════╝\n";
echo "\n";

// Cargar clase GmailMailer
require_once __DIR__ . '/../library/GmailMailer.php';

try {
    echo "[PASO 1/3] Cargando configuración de Gmail...\n";
    $mailer = new GmailMailer();
    echo "            ✓ Configuración cargada\n";
    
    // Mostrar información
    $info = $mailer->getConfigInfo();
    echo "            • SMTP: " . $info['smtp_host'] . ":" . $info['smtp_port'] . "\n";
    echo "            • From: " . $info['from'] . "\n";
    echo "            • Recipients: " . implode(', ', $info['recipients']) . "\n";
    echo "\n";
    
    echo "[PASO 2/3] Probando conexión SMTP con Gmail...\n";
    $connectionTest = $mailer->testConnection();
    
    if ($connectionTest['success']) {
        echo "            ✓ " . $connectionTest['message'] . "\n";
        echo "            ✓ Autenticación exitosa con Gmail\n";
        echo "\n";
    } else {
        echo "            ✗ " . $connectionTest['message'] . "\n";
        echo "\n";
        echo "╔════════════════════════════════════════════════════════════╗\n";
        echo "║                    ERROR DE CONEXIÓN                       ║\n";
        echo "╚════════════════════════════════════════════════════════════╝\n";
        echo "\n";
        echo "Posibles problemas:\n";
        echo "  1. Verifica gmail_username en gmail-config.php\n";
        echo "  2. Verifica gmail_password (debe ser App Password de 16 caracteres)\n";
        echo "  3. Asegúrate de tener 2FA activado en Gmail\n";
        echo "  4. Verifica que el firewall permite conexión a smtp.gmail.com:587\n";
        echo "  5. Intenta con debug_mode => true en gmail-config.php\n";
        echo "\n";
        echo "Documentación: https://myaccount.google.com/apppasswords\n";
        echo "\n";
        exit(1);
    }

    echo "[PASO 3/3] Enviando email de prueba...\n";
    $emailTest = $mailer->sendTestEmail();
    
    if ($emailTest['success']) {
        echo "            ✓ " . $emailTest['message'] . "\n";
        echo "            ✓ Email enviado a " . $emailTest['recipients'] . " destinatario(s)\n";
        echo "\n";
        
        echo "╔════════════════════════════════════════════════════════════╗\n";
        echo "║              ✓ TEST COMPLETADO EXITOSAMENTE               ║\n";
        echo "╚════════════════════════════════════════════════════════════╝\n";
        echo "\n";
        echo "🎉 ¡Gmail configurado correctamente!\n";
        echo "\n";
        echo "Próximos pasos:\n";
        echo "  1. Revisa tu bandeja de entrada\n";
        echo "  2. Si no ves el email, revisa la carpeta SPAM\n";
        echo "  3. El sistema de notificaciones está listo\n";
        echo "\n";
        
    } else {
        echo "            ✗ " . $emailTest['message'] . "\n";
        echo "\n";
        echo "╔════════════════════════════════════════════════════════════╗\n";
        echo "║                  ERROR AL ENVIAR EMAIL                     ║\n";
        echo "╚════════════════════════════════════════════════════════════╝\n";
        echo "\n";
        echo "Troubleshooting:\n";
        echo "  1. Revisa el error detallado arriba\n";
        echo "  2. Verifica que los emails en 'recipients' sean válidos\n";
        echo "  3. Cuenta Gmail no debe haber alcanzado límite diario (500/día)\n";
        echo "  4. Intenta activar debug_mode en gmail-config.php para más info\n";
        echo "\n";
        exit(1);
    }

} catch (Exception $e) {
    echo "\n";
    echo "╔════════════════════════════════════════════════════════════╗\n";
    echo "║                    ERROR FATAL                             ║\n";
    echo "╚════════════════════════════════════════════════════════════╝\n";
    echo "\n";
    echo "Error: " . $e->getMessage() . "\n";
    echo "\n";
    echo "Verifica que:\n";
    echo "  • PHPMailer está instalado en library/PHPMailer/\n";
    echo "  • gmail-config.php existe y tiene los permisos correctos\n";
    echo "  • Todas las rutas son correctas\n";
    echo "\n";
    exit(1);
}

echo "═══════════════════════════════════════════════════════════════\n";
echo "Gmail está configurado y funcionando correctamente.\n";
echo "Puedes usar el sistema de notificaciones.\n";
echo "═══════════════════════════════════════════════════════════════\n";
echo "\n";


