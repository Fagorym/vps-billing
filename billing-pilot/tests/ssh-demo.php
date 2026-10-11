#!/usr/local/bin/php
<?php
declare(strict_types=1);
// Explicit demo override. The production image uses OpenSSH + forced command.
$body = stream_get_contents(STDIN);
$context = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\n",
    'content' => $body, 'timeout' => 30, 'ignore_errors' => true]]);
$result = file_get_contents('http://mock:8090/', false, $context);
echo $result ?: '{"ok":false,"error":"Demo backend unavailable"}';
exit(($result && (json_decode($result, true)['ok'] ?? false)) ? 0 : 1);
