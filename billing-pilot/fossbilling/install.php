<?php
declare(strict_types=1);
$completed = false;
register_shutdown_function(static function () use (&$completed): void { if (!$completed) { exit(1); } });

// Credentials enter through stdin, never argv or a URL. Official installer owns the schema.
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
chdir('/var/www/html');
if (is_file('config.php')) {
    $completed = true;
    echo "FOSSBilling уже установлен\n";
    exit(0);
}
$_SERVER['REQUEST_METHOD'] = 'POST';
$_SERVER['HTTP_HOST'] = '127.0.0.1:8088';
$_SERVER['REQUEST_URI'] = '/install/install.php?a=install';
$_SERVER['SERVER_NAME'] = '127.0.0.1';
$_SERVER['SERVER_PORT'] = '8088';
$_GET = ['a' => 'install'];
$_POST = [
    'system_url' => 'http://127.0.0.1:8088/',
    'database_hostname' => 'db', 'database_port' => '3306',
    'database_name' => 'fossbilling', 'database_username' => 'fossbilling',
    'database_password' => $input['database_password'],
    'admin_name' => 'Safehost TEST', 'admin_email' => 'admin@example.test',
    'admin_password' => $input['admin_password'],
    'currency_code' => 'RUB', 'error_reporting' => '0',
];
require 'install/install.php';
$response = $installer->run('install');
if ($response->getStatusCode() !== 200 || !is_file('config.php')) {
    file_put_contents('/var/www/html/data/log/pilot-install.html', $response->getContent());
    fwrite(STDERR, "Установка не завершилась. Проверьте data/log/pilot-install.html внутри контейнера; БД не сбрасывается.\n");
    exit(1);
}
echo "FOSSBilling установлен\n";
$completed = true;
