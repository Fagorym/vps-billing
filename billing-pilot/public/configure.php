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
$publicHost=$argv[2]??'';
if(!filter_var($publicHost,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)&&!filter_var($publicHost,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME))throw new RuntimeException('Invalid public hostname');
$config = require '/var/www/html/config.php';
$config['url'] = $publicHost.'/';
$config['security']['force_https'] = true;
$config['security']['trusted_proxies'] = ['enabled' => true,
    'proxies' => [$gateway, '127.0.0.1'], 'headers' => 'x_forwarded'];
\FOSSBilling\Config::setConfig($config);
echo "Public URL configured: https://{$publicHost}/\n";
$completed = true;
