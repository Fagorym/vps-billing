<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }
$root = '/var/www/html';
$path = $root . '/.htaccess';
$text = file_get_contents($path);
foreach (['portal.php', 'admin-portal.php'] as $endpoint) {
    copy('/opt/pilot/' . $endpoint, $root . '/' . $endpoint);
    chmod($root . '/' . $endpoint, 0644);
    $rule = '    RewriteRule ^' . preg_quote($endpoint, '/') . "$ - [L]\n";
    if (!str_contains($text, $rule)) {
        $anchor = '    # Allow access to the index.php';
        if (!str_contains($text, $anchor)) { throw new RuntimeException('Unknown FOSSBilling rewrite rules'); }
        $text = str_replace($anchor, $rule . $anchor, $text);
    }
}
file_put_contents($path, $text);
echo "Portal endpoint installed\n";
