<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }
$root = '/var/www/html';
copy('/opt/pilot/portal.php', $root . '/portal.php');
$path = $root . '/.htaccess';
$text = file_get_contents($path);
$rule = "    RewriteRule ^portal\\.php$ - [L]\n";
if (!str_contains($text, $rule)) {
    $anchor = '    # Allow access to the index.php';
    if (!str_contains($text, $anchor)) { throw new RuntimeException('Unknown FOSSBilling rewrite rules'); }
    file_put_contents($path, str_replace($anchor, $rule . $anchor, $text));
}
chmod($root . '/portal.php', 0644);
echo "Portal endpoint installed\n";
