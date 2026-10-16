<?php
declare(strict_types=1);
header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
$token = getenv('ADMIN_PORTAL_BRIDGE_TOKEN') ?: '';
$ownerToken = getenv('PORTAL_BRIDGE_TOKEN') ?: '';
if (strlen($token) < 32 || hash_equals($ownerToken, $token) || !hash_equals('Bearer ' . $token, $_SERVER['HTTP_AUTHORIZATION'] ?? '')) {
    http_response_code(401); echo '{"error":"Unauthorized"}'; exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { http_response_code(405); exit; }
$raw = file_get_contents('php://input', false, null, 0, 131073);
if (strlen($raw) > 131072) { http_response_code(413); exit; }
try {
    $adminRequest = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($adminRequest)) { throw new InvalidArgumentException(); }
    require '/opt/pilot/AdminBridge.php';
    AdminBridge::actor($adminRequest['actor'] ?? null);
    chdir('/var/www/html'); require 'load.php'; $di['translate']();
    $bridge = new AdminBridge(new FossAdmin($di), new EngineGateway(), '/var/www/html/data/portal');
    echo json_encode($bridge->handle($adminRequest), JSON_THROW_ON_ERROR);
} catch(InvalidArgumentException|JsonException $e) {
    http_response_code(400); echo '{"error":"Invalid admin request"}';
} catch(OutOfBoundsException $e) {
    http_response_code(404); echo '{"error":"Record not found"}';
} catch(DomainException $e) {
    http_response_code(409); echo '{"error":"Operation or identity conflict"}';
} catch(Throwable $e) {
    $category = match ($e->getMessage()) {
        'Bridge busy' => 'bridge_busy',
        'Engine unavailable', 'Engine temporarily unavailable' => 'engine_unavailable',
        'Invalid engine response' => 'invalid_engine_response',
        default => get_class($e),
    };
    error_log('safehost-admin-unavailable: ' . $category);
    http_response_code(503); echo '{"error":"Admin service temporarily unavailable"}';
}
