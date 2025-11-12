<?php

pm_Context::init('LogGuardianSF_v1'); // 👈 Esto garantiza que el módulo se registre

class IndexController extends pm_Controller_Action
{
    public function indexAction()
    {
        $this->view->pageTitle = 'LogGuardianSF - Recent Activity';

        $logFile = '/var/modules/logguardianSF/logguardian_data.log';
        $utcTz   = new DateTimeZone('UTC');
        $localTz = new DateTimeZone(date_default_timezone_get());
        $lines = [];
        $totalLines = 0;
        $invalidLines = 0;

        $today = new DateTime('now', $localTz);
        $todayDisplay = $today->format('d/m/Y');

        $fromParam = $this->getRequest()->getParam('from');
        $toParam   = $this->getRequest()->getParam('to');

        if (empty($fromParam) || empty($toParam)) {
            $fromDisplay = $todayDisplay;
            $toDisplay   = $todayDisplay;
            $from = $today->format('Y-m-d');
            $to   = $today->format('Y-m-d');
        } else {
            $fromParts = explode('/', $fromParam);
            $toParts   = explode('/', $toParam);
            $from = "{$fromParts[2]}-{$fromParts[1]}-{$fromParts[0]}";
            $to   = "{$toParts[2]}-{$toParts[1]}-{$toParts[0]}";
            $fromDisplay = $fromParam;
            $toDisplay   = $toParam;
        }

        $ipFilter      = trim($this->getRequest()->getParam('ip', ''));
        $codeFilter    = trim($this->getRequest()->getParam('code', ''));
        $keywordFilter = trim($this->getRequest()->getParam('keyword', ''));
        $summaryFilter = trim($this->getRequest()->getParam('summary', ''));

        $fromLocal = DateTime::createFromFormat('Y-m-d H:i:s', $from . ' 00:00:00', $localTz);
        $toLocal   = DateTime::createFromFormat('Y-m-d H:i:s', $to . ' 23:59:59', $localTz);

        $fromUtc = clone $fromLocal;
        $fromUtc->setTimezone($utcTz);
        $toUtc = clone $toLocal;
        $toUtc->setTimezone($utcTz);

        $this->view->fromDate = $fromDisplay;
        $this->view->toDate   = $toDisplay;
        $this->view->fromDateLocal = $fromLocal->format('Y-m-d');
        $this->view->toDateLocal   = $toLocal->format('Y-m-d');
        $this->view->fromDateUTC = $fromUtc->format('Y-m-d');
        $this->view->toDateUTC   = $toUtc->format('Y-m-d');


        if (file_exists($logFile)) {
            $allLines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $totalLines = count($allLines);

            foreach ($allLines as $line) {
                $parts = explode('|', $line);
                if (count($parts) < 9) {
                    $invalidLines++;
                    continue;
                }

                $datetimeStr = trim($parts[0]);
                if (empty($datetimeStr)) {
                    $invalidLines++;
                    continue;
                }

                try {
                    $dtUtc = new DateTime($datetimeStr, $utcTz);
                } catch (Exception $e) {
                    $invalidLines++;
                    continue;
                }

                $dtLocal = clone $dtUtc;
                $dtLocal->setTimezone($localTz);

                if ($dtUtc < $fromUtc || $dtUtc > $toUtc) continue;

                $ip = trim($parts[2]);
                $code = trim($parts[5]);
                $text = strtolower($line);
                $agent = strtolower(trim($parts[8]));
                $referer = strtolower(trim($parts[7]));
                $request = strtolower(trim($parts[4]));

                if ($ipFilter && stripos($ip, $ipFilter) === false) continue;
                if ($codeFilter && stripos($code, $codeFilter) === false) continue;
                if ($keywordFilter && stripos($text, strtolower($keywordFilter)) === false) continue;

                $isError = (strpos($code, '4') === 0 || strpos($code, '5') === 0);
                $isCritical = (strpos($agent, 'attack') !== false);
                $isSuspicious = (strpos($referer, 'scan') !== false || strpos($agent, 'crawler') !== false || strpos($request, 'phpmyadmin') !== false);

                if ($summaryFilter === 'errors' && !$isError) continue;
                if ($summaryFilter === 'critical' && !$isCritical) continue;
                if ($summaryFilter === 'suspicious' && !$isSuspicious) continue;

                $lines[] = [
                    'datetime_local' => $dtLocal->format('Y-m-d H:i:s'),
                    'datetime_utc'   => $dtUtc->format('Y-m-d H:i:s'),
                    'domain'         => $parts[1],
                    'ip'             => $ip,
                    'method'         => $parts[3],
                    'request'        => $parts[4],
                    'code'           => $code,
                    'size'           => $parts[6],
                    'referer'        => $parts[7],
                    'agent'          => $parts[8],
                ];
            }
        }

        usort($lines, function ($a, $b) {
            return strcmp($b['datetime_utc'], $a['datetime_utc']);
        });

        $totalParsed = count($lines);
        
        $allLinesForStats = [];
        if (file_exists($logFile)) {
            $allLines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($allLines as $line) {
                $parts = explode('|', $line);
                if (count($parts) < 9) continue;
                $datetimeStr = trim($parts[0]);
                if (empty($datetimeStr)) continue;
                try {
                    $dtUtc = new DateTime($datetimeStr, $utcTz);
                } catch (Exception $e) {
                    continue;
                }
                if ($dtUtc < $fromUtc || $dtUtc > $toUtc) continue;
                
                $allLinesForStats[] = [
                    'code' => trim($parts[5]),
                    'agent' => strtolower(trim($parts[8])),
                    'referer' => strtolower(trim($parts[7])),
                    'request' => strtolower(trim($parts[4]))
                ];
            }
        }

        $errors = count(array_filter($allLinesForStats, fn($r) => strpos($r['code'], '4') === 0 || strpos($r['code'], '5') === 0));
        

        $suspicious = count(array_filter($allLinesForStats, fn($r) =>
            strpos($r['referer'], 'scan') !== false ||
            strpos($r['agent'], 'crawler') !== false ||
            strpos($r['request'], 'phpmyadmin') !== false
        ));

        $this->view->entries       = $lines;
        $this->view->totalLines    = $totalLines;
        $this->view->invalidLines  = $invalidLines;
        $this->view->errorCount    = $errors;
        $this->view->criticalCount = $critical;
        $this->view->suspiciousCount = $suspicious;
        $this->view->ipFilter = $ipFilter;
        $this->view->codeFilter = $codeFilter;
        $this->view->keywordFilter = $keywordFilter;
        $this->view->summaryFilter = $summaryFilter;
        $this->view->totalAll = count($allLinesForStats);
    }

    public function blockIpAction()
    {
    	// === Configurar respuesta JSON sin plantilla ===
    	$this->_helper->viewRenderer->setNoRender(true);
    	$this->_helper->layout->disableLayout();
    	$this->getResponse()->setHeader('Content-Type', 'application/json; charset=UTF-8');

    	// === Validar parámetro IP ===
    	$ip = trim($this->getRequest()->getParam('ip', ''));
    	if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        	echo json_encode([
            		'ok' => false,
            		'error' => 'IP inválida',
            		'recibido' => $ip
        	]);
        	return;
    	}

    	// === Comando ipset exacto (con rutas absolutas) ===
    	$cmd = "/usr/bin/sudo /usr/sbin/ipset add blacklist1 " . escapeshellarg($ip) . " timeout 86400 -exist";
    	$out = [];
    	$rc = 0;

    	// Ejecutar y capturar salida + código de retorno
    	exec($cmd . ' 2>&1', $out, $rc);

   	 // === Respuesta detallada para depuración ===
    	echo json_encode([
        	'ok' => ($rc === 0),
        	'msg' => ($rc === 0)
            		? "✅ IP $ip bloqueada en blacklist1"
            		: "❌ Falló ipset (código $rc)",
        	'rc' => $rc,
        	'cmd' => $cmd,
        	'detalle' => $out,
        	'whoami' => trim(shell_exec('whoami')),
        	'pwd' => trim(shell_exec('pwd')),
        	'php_user' => get_current_user(),
    	], JSON_PRETTY_PRINT);
    	return;
    }

    public function testAction()
    {
      // desactiva la vista por si acaso
      $this->_helper->viewRenderer->setNoRender(true);
      $this->_helper->layout->disableLayout();

      header('Content-Type: text/plain; charset=UTF-8');
      echo "OK test";
      exit;
    }


}
