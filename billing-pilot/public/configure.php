<?php
declare(strict_types=1);
$completed = false;
register_shutdown_function(static function () use (&$completed): void { if (!$completed) { exit(1); } });
chdir('/var/www/html');
require 'load.php';
$gateway = $argv[1] ?? '';
if (!filter_var($gateway, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    throw new RuntimeException('Invalid Docker gateway');
}
$config = require '/var/www/html/config.php';
$config['url'] = '80.249.131.4/';
$config['security']['force_https'] = true;
$config['security']['trusted_proxies'] = ['enabled' => true,
    'proxies' => [$gateway, '127.0.0.1'], 'headers' => 'x_forwarded'];
\FOSSBilling\Config::setConfig($config);
echo "Public URL configured: https://80.249.131.4/\n";
$completed = true;
