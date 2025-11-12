<?php
/**
 * Gmail Mailer Helper para LogGuardianSF
 * Wrapper de PHPMailer para facilitar envío con Gmail
 */

// Importar PHPMailer
require_once __DIR__ . '/PHPMailer/PHPMailer.php';
require_once __DIR__ . '/PHPMailer/SMTP.php';
require_once __DIR__ . '/PHPMailer/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class GmailMailer
{
    private $config;
    private $mailer;
    
    /**
     * Constructor
     */
    public function __construct($configPath = null)
    {
        // Cargar configuración
        if ($configPath === null) {
            $configPath = __DIR__ . '/../scripts/gmail-config.php';
        }
        
        if (!file_exists($configPath)) {
            throw new Exception("Gmail config file not found: $configPath");
        }
        
        $this->config = require $configPath;
        $this->initMailer();
    }
    
    /**
     * Inicializar PHPMailer con configuración de Gmail
     */
    private function initMailer()
    {
        $this->mailer = new PHPMailer(true);
        
        try {
            // Configuración del servidor SMTP
            $this->mailer->isSMTP();
            $this->mailer->Host = $this->config['smtp_host'];
            $this->mailer->SMTPAuth = $this->config['smtp_auth'];
            $this->mailer->Username = $this->config['gmail_username'];
            $this->mailer->Password = $this->config['gmail_password'];
            $this->mailer->SMTPSecure = $this->config['smtp_encryption'];
            $this->mailer->Port = $this->config['smtp_port'];
            $this->mailer->CharSet = $this->config['charset'];
            $this->mailer->Timeout = $this->config['timeout'];
            
            // Debug (solo si está activado)
            if ($this->config['debug_mode']) {
                $this->mailer->SMTPDebug = 2;
                $this->mailer->Debugoutput = 'html';
            } else {
                $this->mailer->SMTPDebug = 0;
            }
            
            // Configurar remitente
            $this->mailer->setFrom(
                $this->config['gmail_username'],
                $this->config['from_name']
            );
            
        } catch (Exception $e) {
            throw new Exception("Mailer initialization failed: {$e->getMessage()}");
        }
    }
    /**
     * Enviar correo de alerta de seguridad
     */
    public function sendAlert($subject, $htmlBody, $textBody = null)
    {
        try {
            // Limpiar destinatarios anteriores
            $this->mailer->clearAddresses();
            $this->mailer->clearAttachments();
            
            // Agregar destinatarios
            foreach ($this->config['recipients'] as $recipient) {
                $this->mailer->addAddress($recipient);
            }
            
            // Contenido del correo
            $this->mailer->isHTML(true);
            $this->mailer->Subject = $subject;
            $this->mailer->Body = $htmlBody;
            
            // Versión texto alternativo (para clientes que no soportan HTML)
            if ($textBody !== null) {
                $this->mailer->AltBody = $textBody;
            } else {
                // Generar versión texto automáticamente
                $this->mailer->AltBody = strip_tags($htmlBody);
            }
            
            // Enviar
            $result = $this->mailer->send();
            
            return [
                'success' => true,
                'message' => 'Email sent successfully',
                'recipients' => count($this->config['recipients'])
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => "Email sending failed: {$this->mailer->ErrorInfo}",
                'error' => $e->getMessage()
            ];
        }
    }
    /**
     * Enviar correo de prueba
     */
    public function sendTestEmail()
    {
        $subject = "✓ LogGuardianSF - Gmail Test Successful";
        
        $body = '
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .header { background: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 4px; margin-bottom: 20px; }
                .content { line-height: 1.6; color: #333; }
                .info-box { background: #e8f5e9; border-left: 4px solid #4CAF50; padding: 15px; margin: 15px 0; }
                .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; text-align: center; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2 style="margin: 0;">✓ Gmail Configuration Successful!</h2>
                </div>
                
                <div class="content">
                    <p><strong>Congratulations!</strong></p>
                    <p>This is a test email from <strong>LogGuardianSF</strong>.</p>
                    
                    <div class="info-box">
                        <strong>Server Information:</strong><br>
                        • Hostname: ' . gethostname() . '<br>
                        • Date/Time: ' . date('Y-m-d H:i:s') . ' UTC<br>
                        • From: ' . htmlspecialchars($this->config['gmail_username']) . '
                    </div>
                    
                    <p>If you received this email, it means:</p>
                    <ul>
                        <li>Gmail SMTP connection is working correctly</li>
                        <li>App Password is configured properly</li>
                        <li>Email delivery is functional</li>
                        <li>You will now receive security alerts</li>
                    </ul>
                    
                    <p style="color: #4CAF50;"><strong>✓ System is ready to send notifications!</strong></p>
                </div>
                
                <div class="footer">
                    <p><strong>LogGuardianSF</strong> - Security Monitoring System</p>
                    <p>Access dashboard: <a href="https://' . gethostname() . ':8443/modules/LogGuardianSF">View Logs</a></p>
                </div>
            </div>
        </body>
        </html>
        ';
        
        return $this->sendAlert($subject, $body);
    }
    
    /**
     * Verificar conexión SMTP
     */
    public function testConnection()
    {
        try {
            // Intentar conectar al servidor SMTP
            $this->mailer->smtpConnect();
            $this->mailer->smtpClose();
            
            return [
                'success' => true,
                'message' => 'SMTP connection successful'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'SMTP connection failed: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Obtener información de configuración (sin credenciales)
     */
    public function getConfigInfo()
    {
        return [
            'smtp_host' => $this->config['smtp_host'],
            'smtp_port' => $this->config['smtp_port'],
            'smtp_encryption' => $this->config['smtp_encryption'],
            'from' => $this->config['gmail_username'],
            'from_name' => $this->config['from_name'],
            'recipients' => $this->config['recipients'],
            'daily_limit' => $this->config['daily_limit']
        ];
    }
}
