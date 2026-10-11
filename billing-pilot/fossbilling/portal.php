<?php
declare(strict_types=1);
// Never bootstrap privileged FOSSBilling APIs before authenticating the service caller.
header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
$token = getenv('PORTAL_BRIDGE_TOKEN') ?: '';
if (strlen($token) < 32 || !hash_equals('Bearer ' . $token, $_SERVER['HTTP_AUTHORIZATION'] ?? '')) {
    http_response_code(401); echo '{"error":"Unauthorized"}'; exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { http_response_code(405); exit; }
$raw = file_get_contents('php://input', false, null, 0, 8193);
if (strlen($raw) > 8192) { http_response_code(413); exit; }
try {
    $r = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($r)) { throw new InvalidArgumentException(); }
    chdir('/var/www/html'); require 'load.php'; $di['translate']();
    require '/opt/pilot/PortalBridge.php';
    $bridge = new PortalBridge(new FossPortal($di), '/var/www/html/data/portal');
    echo json_encode($bridge->handle($r), JSON_THROW_ON_ERROR);
} catch (InvalidArgumentException|JsonException $e) {
    http_response_code(400); echo '{"error":"Invalid request"}';
} catch (OutOfBoundsException $e) {
    http_response_code(404); echo '{"error":"Order not found"}';
} catch (DomainException $e) {
    http_response_code(409); echo '{"error":"Order unavailable or identity conflict"}';
} catch (Throwable $e) {
    // No raw exception text: upstream exceptions can contain credentials/requests.
    http_response_code(503); echo '{"error":"Provisioning temporarily unavailable; retry same reference"}';
}
