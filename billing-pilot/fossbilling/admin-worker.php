<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }
chdir('/var/www/html'); require 'load.php'; $di['translate']();
require '/opt/pilot/AdminBridge.php';
$bridge = new AdminBridge(new FossAdmin($di), new EngineGateway(), '/var/www/html/data/portal');
do {
    try { $bridge->processOne(); } catch(Throwable $e) { fwrite(STDERR, "Admin worker unavailable; persisted operation retained\n"); }
    if (($argv[1] ?? '') === '--once') { break; }
    sleep(3);
} while (true);
