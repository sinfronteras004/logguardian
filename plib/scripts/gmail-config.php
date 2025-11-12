<?php
/**
 * Configuración de Gmail para LogGuardianSF_Test
 * 
 * IMPORTANTE: 
 * - Usar App Password, NO la contraseña de Gmail normal
 * - Generar App Password en: https://myaccount.google.com/apppasswords
 * - Requiere tener 2FA activado
 */

return [
    // =============================
    // CREDENCIALES DE GMAIL
    // =============================
    
    // Tu dirección de Gmail que enviará las notificaciones
    'gmail_username' => 'sinfronteras004@gmail.com',  // ← CAMBIAR
    
    // App Password (16 caracteres) - NO uses tu contraseña normal
    'gmail_password' => 'czhb hcdu zzii klbb',  // ← CAMBIAR por tu App Password
    
    // =============================
    // DESTINATARIOS
    // =============================
    
    // Nombre que aparece como remitente
    'from_name' => 'LogGuardianSF Security Alert',
    
    // Lista de destinatarios (pueden ser múltiples)
    'recipients' => [
    'luis.reyes.fallas@est.una.ac.cr',
    'anthonny.eras.rivera@est.una.ac.cr',
    'eduardo.arias.vargas@est.una.ac.cr',
    'eugenia.delgado.castillo@est.una.ac.cr',
     // 'security@example.com',     // Agregar más si necesitas
    ],
    
    // =============================
    // CONFIGURACIÓN SMTP DE GMAIL
    // =============================
    
    'smtp_host' => 'smtp.gmail.com',
    'smtp_port' => 587,                    // Puerto para TLS
    'smtp_encryption' => 'tls',            // TLS o SSL
    'smtp_auth' => true,
    
    // =============================
    // OPCIONES
    // =============================
    
    'debug_mode' => false,                 // true = Ver mensajes de debug
    'timeout' => 30,                       // Timeout en segundos
    'charset' => 'UTF-8',
    
    // =============================
    // LÍMITES
    // =============================
    
    'daily_limit' => 500,                  // Gmail: 500/día (gratis), 2000/día (Workspace)
];
