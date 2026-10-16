<?php
declare(strict_types=1);

// Run only in a disposable FOSSBilling container as root; no production volumes.
$portal = '/var/www/html/data/portal';
$names = ['operation.lock', 'admin-queue.lock', 'admin-worker.lock'];
function permissionsCheck(bool $ok, string $message): void
{
    if (!$ok) { throw new RuntimeException($message); }
}
if (($argv[1] ?? '') === 'web-check') {
    foreach ($names as $name) {
        $lock = @fopen($portal . '/' . $name, 'c');
        permissionsCheck($lock !== false, 'Web user cannot open ' . $name);
        try {
            $acquired = flock($lock, LOCK_EX | LOCK_NB);
            $heldByInstallerTest = $name === 'admin-queue.lock' && ($argv[2] ?? '') === 'held';
            permissionsCheck($acquired !== $heldByInstallerTest, 'Unexpected lock state: ' . $name);
            if ($acquired) { flock($lock, LOCK_UN); }
        } finally {
            fclose($lock);
        }
    }
    exit;
}
function checkAsWebUser(bool $held = false): int
{
    $command = 'php /tests/portal-permissions.php web-check' . ($held ? ' held' : '');
    $process = proc_open(['su', '-s', '/bin/sh', 'www-data', '-c', $command], [STDIN, STDOUT, STDERR], $pipes);
    permissionsCheck(is_resource($process), 'Cannot start web user check');
    return proc_close($process);
}
function installPortal(): void
{
    $process = proc_open([PHP_BINARY, '/opt/pilot/install-portal.php'], [STDIN, STDOUT, STDERR], $pipes);
    permissionsCheck(is_resource($process), 'Cannot start portal installer');
    permissionsCheck(proc_close($process) === 0, 'Portal installer failed');
}
permissionsCheck(posix_geteuid() === 0, 'Fixture setup requires root');
permissionsCheck(!file_exists($portal), 'Disposable container with no portal data required');
chown('/var/www/html/data', 33);
chgrp('/var/www/html/data', 33);

installPortal();
permissionsCheck(checkAsWebUser() === 0, 'Fresh installation is inaccessible');
$queue = $portal . '/admin-queue.lock';
file_put_contents($queue, 'preserve existing lock contents');
chown($queue, 0);
chgrp($queue, 0);
chmod($queue, 0644);
clearstatcache();
$before = stat($queue);
permissionsCheck(checkAsWebUser() !== 0, 'Root-owned lock must reproduce the incident');

$held = fopen($queue, 'c');
flock($held, LOCK_EX);
try {
    installPortal();
    clearstatcache();
    $after = stat($queue);
    permissionsCheck($after['ino'] === $before['ino'], 'Installer replaced an active lock');
    permissionsCheck($after['uid'] === 33 && $after['gid'] === 33, 'Incorrect service ownership');
    permissionsCheck(($after['mode'] & 0777) === 0600, 'Incorrect lock permissions');
    permissionsCheck(file_get_contents($queue) === 'preserve existing lock contents', 'Installer truncated the lock');
    permissionsCheck(checkAsWebUser(true) === 0, 'Installer broke an existing exclusive lock');
} finally {
    flock($held, LOCK_UN);
    fclose($held);
}
permissionsCheck(checkAsWebUser() === 0, 'Repaired locks are inaccessible');
echo "PASS: fresh installation, root-owned lock repair, web-user access, inode/content/held-lock preservation\n";
