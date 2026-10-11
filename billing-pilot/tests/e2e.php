<?php
declare(strict_types=1);
$completed = false;
register_shutdown_function(static function () use (&$completed): void { if (!$completed) { exit(1); } });
chdir('/var/www/html');
require 'load.php';
$di['translate']();
$di['loggedin_admin'] = $di['db']->getExistingModelById('Admin', 1);
$api = $di['api_admin'];
function check(bool $ok, string $message): void {
    if (!$ok) { throw new RuntimeException($message); }
}
function mock(): array {
    return json_decode(file_get_contents('http://mock:8090/'), true, 512, JSON_THROW_ON_ERROR);
}
$catalog = json_decode(file_get_contents('data/pilot-catalog.json'), true, 512, JSON_THROW_ON_ERROR);
$mail = $api->extension_config_get(['ext' => 'email']);
check($mail['mailer'] === 'custom' && $mail['custom_dsn'] === 'null://null', 'Outbound mail must be disabled');
$run = bin2hex(random_bytes(5));
// FOSSBilling checks domain DNS even for a synthetic account; the null transport above prevents delivery.
$clientId = $api->client_create(['email' => 'safehost-pilot-' . $run . '@gmail.com', 'first_name' => 'Pilot',
    'last_name' => 'Test', 'password' => 'Test1!' . $run, 'send_welcome_email' => false]);
$key = 'ssh-ed25519 ' . base64_encode(pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . str_repeat('A', 32));
$before = mock()['clones'];
$owner = $di['db']->getExistingModelById('Client', $clientId);
$clientApi = new \FOSSBilling\Api\Proxy($owner);
$clientApi->setDi($di);
session_id('pilot-' . $run);
$di['session']->set('client_id', $clientId);
$di['api_guest']->cart_add_item(['id' => $catalog['products']['mini'], 'period' => '1M', 'ssh_key' => $key]);
$checkout = $clientApi->cart_checkout(['gateway_id' => $catalog['gateway_id']]);
$orderId = (int) $checkout['order_id'];
// Simulate a new HTTP request: legacy invoice writes otherwise leave Doctrine entities stale.
$di['em']->clear();
$order = $api->order_get(['id' => $orderId]);
check($order['status'] === 'pending_setup', 'Unpaid order must remain pending_setup');
check(mock()['clones'] === $before, 'An unpaid order created a VM');
$invoiceId = (int) $order['unpaid_invoice_id'];
check($invoiceId > 0, 'Invoice was not issued');
$api->invoice_mark_as_paid(['id' => $invoiceId, 'gateway_id' => $catalog['gateway_id'],
    'transactionId' => 'TEST-' . $run, 'execute' => true]);
// Simulate a new HTTP request: legacy invoice writes otherwise leave Doctrine entities stale.
$di['em']->clear();
$order = $api->order_get(['id' => $orderId]);
check($order['status'] === 'active', 'Paid order did not activate');
check(mock()['clones'] === $before + 1, 'Payment did not create exactly one VM');
$legacy = $di['db']->getExistingModelById('ClientOrder', $orderId);
$di['mod_service']('servicecustom')->action_activate($legacy);
check(mock()['clones'] === $before + 1, 'Retry created a duplicate VM');
$owner = $di['db']->getExistingModelById('Client', $clientId);
$clientApi = new \FOSSBilling\Api\Proxy($owner);
$clientApi->setDi($di);
$connection = $clientApi->servicecustom_call(['order_id' => $orderId, 'method' => 'connection',
    'client_id' => 999999, 'action' => 'cancel']);
check($connection['status'] === 'running' && $connection['user'] === 'vpsadmin', 'Connection metadata is invalid');
check($connection['auth_mode'] === 'key', 'Existing key access changed');
$otherId = $api->client_create(['email' => 'safehost-other-' . $run . '@gmail.com', 'first_name' => 'Other',
    'password' => 'Other1!' . $run, 'send_welcome_email' => false]);
$otherApi = new \FOSSBilling\Api\Proxy($di['db']->getExistingModelById('Client', $otherId));
$otherApi->setDi($di);
$denied = false;
try { $otherApi->servicecustom_call(['order_id' => $orderId, 'method' => 'connection']); }
catch (\FOSSBilling\Exception $e) { $denied = true; }
check($denied, 'Another client accessed this VPS');
foreach (['activate', 'Activate', 'Cancel', 'Suspend', 'UnSuspend', 'DeLeTe', 'Renew', 'UnCancel'] as $method) {
    $denied = false;
    try { $clientApi->servicecustom_call(['order_id' => $orderId, 'method' => $method]); }
    catch (\FOSSBilling\Exception $e) { $denied = true; }
    check($denied, 'Client could invoke lifecycle directly: ' . $method);
}
check(mock()['states'][(string) $connection['vmid']] === 'running', 'Denied lifecycle call changed VM');
$api->order_suspend(['id' => $orderId, 'reason' => 'TEST']);
check(mock()['states'][(string) $connection['vmid']] === 'stopped', 'Suspend did not stop VM');
$api->order_unsuspend(['id' => $orderId]);
check(mock()['states'][(string) $connection['vmid']] === 'running', 'Unsuspend did not start VM');
$api->order_cancel(['id' => $orderId, 'reason' => 'TEST']);
$after = mock();
check($after['states'][(string) $connection['vmid']] === 'stopped', 'Cancellation did not stop VM');
check(isset($after['vms'][(string) $connection['vmid']]['scsi0']), 'Cancellation removed disk');
// A second order leaves the optional SSH field empty and receives a generated password.
$di['session']->set('client_id', $clientId);
$di['api_guest']->cart_add_item(['id' => $catalog['products']['mini'], 'period' => '1M']);
$checkout = $clientApi->cart_checkout(['gateway_id' => $catalog['gateway_id']]);
$passwordOrder = (int) $checkout['order_id'];
$di['em']->clear();
$passwordData = $api->order_get(['id' => $passwordOrder]);
check($passwordData['status'] === 'pending_setup', 'Unpaid password order activated');
$denied = false;
try { $clientApi->servicecustom_call(['order_id' => $passwordOrder, 'method' => 'initial_password']); }
catch (\FOSSBilling\Exception $e) { $denied = true; }
check($denied, 'Unpaid order exposed a password');
$api->invoice_mark_as_paid(['id' => (int) $passwordData['unpaid_invoice_id'], 'gateway_id' => $catalog['gateway_id'],
    'transactionId' => 'PASSWORD-' . $run, 'execute' => true]);
$di['em']->clear();
$passwordData = $api->order_get(['id' => $passwordOrder]);
check($passwordData['status'] === 'active', 'Password order did not activate');
$passwordConnection = $clientApi->servicecustom_call(['order_id' => $passwordOrder, 'method' => 'connection']);
check($passwordConnection['auth_mode'] === 'password' && !isset($passwordConnection['password']), 'Connection leaks credentials');
$password = $clientApi->servicecustom_call(['order_id' => $passwordOrder, 'method' => 'initial_password']);
check(strlen($password['password']) >= 28 && $password['user'] === 'vpsadmin', 'Generated credentials invalid');
$twig = new \Twig\Environment(new \Twig\Loader\FilesystemLoader('/var/www/html/modules/Servicecustom/templates/client'), ['autoescape' => 'html']);
$html = $twig->render('mod_servicecustom_manage.html.twig', ['order' => $passwordData, 'client' => $clientApi]);
check(str_contains($html, 'safehost-password-button') && !str_contains($html, $password['password']), 'Password leaked into rendered HTML');
$legacy = $di['db']->getExistingModelById('ClientOrder', $passwordOrder);
$di['mod_service']('servicecustom')->action_activate($legacy);
$again = $clientApi->servicecustom_call(['order_id' => $passwordOrder, 'method' => 'initial_password']);
check($again === $password, 'Activation retry changed password');
$denied = false;
try { $otherApi->servicecustom_call(['order_id' => $passwordOrder, 'method' => 'initial_password', 'client_id' => $clientId]); }
catch (\FOSSBilling\Exception $e) { $denied = true; }
check($denied, 'Other client accessed generated credentials');
check(mock()['clones'] === $before + 2, 'Password activation created duplicate VM');
echo "PASS: key and password orders; unpaid isolation, paid activation, credential ownership, retry, suspend/resume, retained disk\n";

require '/opt/pilot/PortalBridge.php';
$bridge = new PortalBridge(new FossPortal($di), '/var/www/html/data/portal');
$reference = 'aaaaaaaa-aaaa-4aaa-8aaa-' . bin2hex(random_bytes(6));
$account = 'bbbbbbbb-bbbb-4bbb-8bbb-' . bin2hex(random_bytes(6));
$request = ['action' => 'create', 'reference' => $reference, 'account' => $account, 'plan' => 'mini'];
$beforePortal = mock()['clones'];
$created = $bridge->handle($request); echo "Portal created\n";
check($created['phase'] === 'ready', 'Portal VM not SSH-ready');
check($created === $bridge->handle($request), 'Portal retry differs');
check(mock()['clones'] === $beforePortal + 1, 'Portal duplicated VM');
$free = $api->order_get(['id' => $created['order_id']]);
check((float) $free['price'] === 0.0 && !$free['unpaid_invoice_id'], 'Free order created a charge');
$request['action'] = 'password';
check(strlen($bridge->handle($request)['password']) >= 28, 'Portal password missing'); echo "Portal credentials verified\n";
$request['action'] = 'stop';check($bridge->handle($request)['phase'] === 'suspended', 'Portal stop did not suspend billing');
$request['action'] = 'start';check($bridge->handle($request)['phase'] === 'ready', 'Portal start failed');
$context = stream_context_create(['http' => ['ignore_errors' => true]]);
file_get_contents('http://127.0.0.1/portal.php', false, $context);
check(str_contains(http_get_last_response_headers()[0], '401'), 'Anonymous portal access allowed');
$context = stream_context_create(['http' => ['ignore_errors' => true, 'method' => 'POST', 'header' => 'Content-Type: application/json'."\r\n".'Authorization: Bearer '.getenv('PORTAL_BRIDGE_TOKEN'), 'content' => '{}']]);
$invalid = file_get_contents('http://127.0.0.1/portal.php', false, $context);
check(str_contains(http_get_last_response_headers()[0], '400') && str_contains($invalid, 'Invalid request'), 'Service authentication/header routing broken');
$context = stream_context_create(['http' => ['ignore_errors' => true, 'method' => 'POST', 'header' => 'Content-Type: application/json'."\r\n".'Authorization: Bearer '.getenv('PORTAL_BRIDGE_TOKEN'), 'content' => json_encode(['action'=>'status','account'=>$account,'reference'=>$reference])]]);
// The authenticated HTTP endpoint must recover the same persisted mapping.
$status = json_decode(file_get_contents('http://127.0.0.1/portal.php', false, $context), true);
check(str_contains(http_get_last_response_headers()[0], '200') && $status['order_id'] === $created['order_id'] && !isset($status['password']), 'HTTP status contract failed');
echo "PASS: real FOSSBilling bridge -> zero-price order -> one VM -> password -> stop/start, anonymous denial
";
$completed = true;
