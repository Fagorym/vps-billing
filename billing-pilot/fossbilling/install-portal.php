<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }
$root = '/var/www/html';
$data = stat($root . '/data');
if ($data === false) { throw new RuntimeException('FOSSBilling data directory is missing'); }
$portal = $root . '/data/portal';
if (is_link($portal)) { throw new RuntimeException('Portal directory must not be a symlink'); }
if (!is_dir($portal) && !mkdir($portal, 0700)) { throw new RuntimeException('Cannot create portal directory'); }
if (!chown($portal, $data['uid']) || !chgrp($portal, $data['gid'])) {
    throw new RuntimeException('Cannot set portal directory ownership');
}
// Root maintenance must not create locks that the web server and worker cannot open.
foreach (['operation.lock', 'admin-queue.lock', 'admin-worker.lock'] as $name) {
    $lockPath = $portal . '/' . $name;
    if (is_link($lockPath)) { throw new RuntimeException('Portal lock must not be a symlink'); }
    $lock = fopen($lockPath, 'c');
    if ($lock === false) { throw new RuntimeException('Cannot open portal lock'); }
    try {
        // Preserve the inode: an active worker may hold a lock on this file.
        if (!chown($lockPath, $data['uid']) || !chgrp($lockPath, $data['gid']) || !chmod($lockPath, 0600)) {
            throw new RuntimeException('Cannot set portal lock permissions');
        }
    } finally {
        fclose($lock);
    }
}
$module=$root.'/modules/Safehostfinance';if(!is_dir($module))mkdir($module,0755,true);
foreach(['Service.php','manifest.json']as$file){copy('/opt/pilot/Safehostfinance/'.$file,$module.'/'.$file);chmod($module.'/'.$file,0644);}
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
