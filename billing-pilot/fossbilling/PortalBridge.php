<?php
declare(strict_types=1);

/** Narrow, server-to-server contract. Durable mapping precedes activation. */
final class PortalBridge
{
    private PDO $db;
    public function __construct(private object $foss, private string $directory)
    {
        if (!is_dir($directory)) { mkdir($directory, 0700, true); }
        $this->db = new PDO('sqlite:' . $directory . '/portal.sqlite');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec('PRAGMA busy_timeout=30000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS client (account TEXT PRIMARY KEY, client_id INTEGER NOT NULL UNIQUE)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS orders (reference TEXT PRIMARY KEY, account TEXT NOT NULL, plan TEXT NOT NULL, order_id INTEGER UNIQUE)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS retired_orders (reference TEXT PRIMARY KEY, account TEXT NOT NULL, plan TEXT NOT NULL, order_id INTEGER UNIQUE)');
        foreach (['orders','retired_orders'] as $table) {
            $columns = $this->db->query('PRAGMA table_info('.$table.')')->fetchAll(PDO::FETCH_COLUMN,1);
            if (!in_array('network_mode',$columns,true)) { $this->db->exec("ALTER TABLE ".$table." ADD COLUMN network_mode TEXT NOT NULL DEFAULT 'nat'"); }
            if (!in_array('lease_id',$columns,true)) { $this->db->exec('ALTER TABLE '.$table.' ADD COLUMN lease_id TEXT'); }
            if (!in_array('disk_gb',$columns,true)) { $this->db->exec('ALTER TABLE '.$table.' ADD COLUMN disk_gb INTEGER'); }
        }
        $this->allowMultipleOrders();
        // Run after the legacy account-quota migration, whose schema is exact.
        foreach (['orders', 'retired_orders'] as $table) {
            $columns = $this->db->query('PRAGMA table_info('.$table.')')->fetchAll(PDO::FETCH_COLUMN, 1);
            if (!in_array('os', $columns, true)) {
                $this->db->exec("ALTER TABLE ".$table." ADD COLUMN os TEXT NOT NULL DEFAULT 'Ubuntu 24.04'");
            }
            if (!in_array('ssh_key', $columns, true)) {
                $this->db->exec('ALTER TABLE '.$table.' ADD COLUMN ssh_key TEXT');
            }
        }
        chmod($directory . '/portal.sqlite', 0600);
        file_put_contents($directory . '/.htaccess', "Require all denied\n");
    }
    private function hasAccountQuota(): bool
    {
        foreach ($this->db->query('PRAGMA index_list(orders)')->fetchAll(PDO::FETCH_ASSOC) as $index) {
            if (!(bool) $index['unique']) { continue; }
            $name = str_replace('"', '""', $index['name']);
            $columns = $this->db->query('PRAGMA index_info("'.$name.'")')->fetchAll(PDO::FETCH_COLUMN, 2);
            if ($columns === ['account']) { return true; }
        }
        return false;
    }
    /** Preserve all existing bindings; only the account uniqueness rule changes. */
    private function allowMultipleOrders(): void
    {
        if (!$this->hasAccountQuota()) { return; }
        $lock = fopen($this->directory . '/operation.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX)) { throw new RuntimeException('Bridge unavailable'); }
        try {
            if (!$this->hasAccountQuota()) { return; }
            $this->db->beginTransaction();
            try {
                $columns = $this->db->query('PRAGMA table_info(orders)')->fetchAll(PDO::FETCH_COLUMN, 1);
                if ($columns !== ['reference','account','plan','order_id','network_mode','lease_id','disk_gb']) {
                    throw new RuntimeException('Unexpected portal orders schema');
                }
                $this->db->exec("CREATE TABLE orders_multiple_vms (reference TEXT PRIMARY KEY, account TEXT NOT NULL, plan TEXT NOT NULL, order_id INTEGER UNIQUE, network_mode TEXT NOT NULL DEFAULT 'nat', lease_id TEXT, disk_gb INTEGER)");
                $this->db->exec('INSERT INTO orders_multiple_vms SELECT * FROM orders');
                $this->db->exec('DROP TABLE orders');
                $this->db->exec('ALTER TABLE orders_multiple_vms RENAME TO orders');
                $this->db->commit();
            } catch (Throwable $e) { $this->db->rollBack(); throw $e; }
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    private function row(string $sql, array $args): array|false
    {
        $s = $this->db->prepare($sql); $s->execute($args); return $s->fetch(PDO::FETCH_ASSOC);
    }
    private function write(string $sql, array $args): void
    {
        $s = $this->db->prepare($sql); $s->execute($args);
    }
    private function sshKey(mixed $value): ?string
    {
        if ($value === null || is_string($value) && trim($value) === '') { return null; }
        if (!is_string($value) || strlen($value) >= 1000 || str_contains($value, "\n") || str_contains($value, "\r")) {
            throw new InvalidArgumentException('Expected one public Ed25519 SSH key');
        }
        $parts = preg_split('/\s+/', trim($value));
        if (count($parts) < 2 || $parts[0] !== 'ssh-ed25519') { throw new InvalidArgumentException('Expected ssh-ed25519'); }
        $blob = base64_decode($parts[1], true);
        if ($blob === false || strlen($blob) !== 51 || substr($blob, 0, 4) !== pack('N', 11)
            || substr($blob, 4, 11) !== 'ssh-ed25519' || substr($blob, 15, 4) !== pack('N', 32)) {
            throw new InvalidArgumentException('Invalid Ed25519 SSH key');
        }
        return 'ssh-ed25519 '.base64_encode($blob);
    }
    private function info(int $client, int $id): array
    {
        try {
            $order = $this->foss->get($id);
            if ((int) $order['client_id'] !== $client) { throw new DomainException('Ownership changed'); }
            return $this->foss->call($client, $id, 'readiness');
        } catch (OutOfBoundsException $e) {
            // Native order_delete retains the VM. Only a persisted owner binding may
            // read that engine tombstone; no lifecycle or password call uses this path.
            return $this->foss->boundStatus($client, $id);
        }
    }
    public function handle(array $r): array
    {
        foreach (['account', 'reference'] as $key) {
            if (!isset($r[$key]) || !is_string($r[$key]) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D', $r[$key])) {
                throw new InvalidArgumentException('Invalid identity');
            }
        }
        if (!in_array($r['action'] ?? '', ['create', 'status', 'password', 'metrics', 'start', 'stop', 'restart', 'network_capacity','network_reserve','network_payment_pending','network_release_hold'], true)) {
            throw new InvalidArgumentException('Invalid action');
        }
        if ($r['action'] === 'metrics' && !in_array($r['timeframe'] ?? '', ['day', 'week'], true)) {
            throw new InvalidArgumentException('Invalid metrics period');
        }
        if ($r['action'] === 'restart' && (!is_string($r['operation_id'] ?? null)
            || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D', $r['operation_id']))) {
            throw new InvalidArgumentException('Expected restart operation UUID');
        }
        $sshKey = $r['action'] === 'create' ? $this->sshKey($r['ssh_key'] ?? null) : null;
        $os = $r['os'] ?? 'Ubuntu 24.04';
        if (in_array($r['action'], ['create', 'network_reserve'], true)
            && !in_array($os, ['Ubuntu 24.04', 'Ubuntu 22.04', 'Ubuntu 26.04', 'Debian 13',
                             'Debian 12', 'AlmaLinux 9', 'AlmaLinux 10'], true)) {
            throw new InvalidArgumentException('Invalid operating system');
        }
        if (str_starts_with($r['action'],'network_')) {
            $payload=['action'=>$r['action'],'account'=>$r['account'],'reference'=>$r['reference']];
            if ($r['action'] === 'network_reserve') { $payload['os'] = $os; }
            if(in_array($r['action'],['network_payment_pending','network_release_hold'],true)) {
                if(!is_string($r['lease_id']??null)||!preg_match('/^[0-9a-f-]{36}$/D',$r['lease_id']))throw new InvalidArgumentException('Invalid lease identity');
                $payload['lease_id']=$r['lease_id'];
            }
            if($r['action']==='network_release_hold')$payload['resolved']=($r['resolved']??false)===true;
            return $this->foss->network($payload);
        }
        // Writers serialize reservation and activation. Reads share the lock and refuse a busy
        // writer immediately instead of queueing a credential request behind provisioning.
        $lock = fopen($this->directory . '/operation.lock', 'c');
        $mode = in_array($r['action'], ['status', 'password', 'metrics'], true) ? LOCK_SH | LOCK_NB : LOCK_EX;
        if (!$lock || !flock($lock, $mode)) { throw new RuntimeException('Bridge unavailable'); }
        try {
            $row = $this->row('SELECT * FROM orders WHERE reference=?', [$r['reference']]);
            if (!$row) { $row = $this->row('SELECT * FROM retired_orders WHERE reference=?', [$r['reference']]); }
            if ($r['action'] === 'create') {
                if ($row && $row['os'] !== $os) { throw new DomainException('Operating system reference conflict'); }
                if ($row && $row['ssh_key'] !== $sshKey) { throw new DomainException('SSH key reference conflict'); }
                if (!in_array($r['plan'] ?? '', ['mini', 'small', 'medium'], true)) { throw new InvalidArgumentException('Invalid plan'); }
                [$baseDisk, $maximumDisk] = ['mini'=>[20,40], 'small'=>[50,80], 'medium'=>[80,120]][$r['plan']];
                $disk = $r['disk_gb'] ?? $baseDisk;
                if (!is_int($disk) || $disk < $baseDisk || $disk > $maximumDisk || ($disk - $baseDisk) % 5 !== 0) {
                    throw new InvalidArgumentException('Invalid SSD size');
                }
                if ($row && (int) ($row['disk_gb'] ?? $baseDisk) !== $disk) { throw new DomainException('Disk reference conflict'); }
                $mode=$r['network_mode']??'nat';
                if(!in_array($mode,['nat','public_ipv4'],true))throw new InvalidArgumentException('Invalid network mode');
                if($mode==='public_ipv4'&&(!is_string($r['lease_id']??null)||!preg_match('/^[0-9a-f-]{36}$/D',$r['lease_id'])))throw new InvalidArgumentException('Missing IPv4 lease');
                if($row&&($row['network_mode']!==$mode||$mode==='public_ipv4'&&$row['lease_id']!==$r['lease_id']))throw new DomainException('Network reference conflict');
                if ($row && ($row['account'] !== $r['account'] || $row['plan'] !== $r['plan'])) { throw new DomainException('Reference conflict'); }
                if (!$row) {
                    $this->write('INSERT INTO orders(reference,account,plan,network_mode,lease_id,disk_gb,os,ssh_key) VALUES(?,?,?,?,?,?,?,?)',
                        [$r['reference'], $r['account'], $r['plan'], $mode, $mode==='public_ipv4'?$r['lease_id']:null, $disk, $os, $sshKey]);
                    $row = $this->row('SELECT * FROM orders WHERE reference=?', [$r['reference']]);
                }
            }
            if (!$row || $row['account'] !== $r['account']) { throw new OutOfBoundsException('Order not found'); }
            $client = $this->row('SELECT client_id FROM client WHERE account=?', [$r['account']]);
            if (!$client) {
                if ($r['action'] !== 'create') { throw new OutOfBoundsException('Order not found'); }
                $id = $this->foss->client($r['account']);
                $this->write('INSERT INTO client(account,client_id) VALUES(?,?)', [$r['account'], $id]);
                $client = ['client_id' => $id];
            }
            $clientId = (int) $client['client_id'];
            if (!$row['order_id']) {
                if ($r['action'] !== 'create') { throw new OutOfBoundsException('Order not found'); }
                $serviceConfig = [
                    'disk_gb'=>$row['disk_gb'] === null ? null : (int) $row['disk_gb'],
                    'network_mode'=>$row['network_mode'], 'lease_id'=>$row['lease_id'],
                    'account'=>$r['account'], 'reference'=>$r['reference'], 'os'=>$row['os'],
                ];
                if ($row['ssh_key'] !== null) { $serviceConfig['ssh_key'] = $row['ssh_key']; }
                $id = $this->foss->order($clientId, $r['reference'], $row['plan'], $serviceConfig);
                $this->write('UPDATE orders SET order_id=? WHERE reference=?', [$id, $r['reference']]);
                $row['order_id'] = $id;
            }
            $id = (int) $row['order_id'];
            try { $order = $this->foss->get($id); }
            catch (OutOfBoundsException $e) {
                if (!in_array($r['action'], ['create', 'status'], true)) { throw new DomainException('Native order is unavailable'); }
                $order = null;
            }
            if ($order && (int) $order['client_id'] !== $clientId) { throw new DomainException('Ownership changed'); }
            if ($r['action'] === 'metrics') {
                return $this->foss->metrics($clientId, $id, $r['timeframe']);
            }
            if ($order && $r['action'] === 'create' && in_array($order['status'], ['pending_setup', 'failed_setup'], true)) {
                $this->foss->activate($id); $order = $this->foss->get($id);
            }
            if ($r['action'] === 'password') {
                if ($order['status'] !== 'active') { throw new DomainException('VPS inactive'); }
                if ($row['ssh_key'] !== null) { throw new DomainException('VPS uses an SSH key'); }
                // The adapter checks ownership, VM state and SSH readiness in this same call.
                return $this->foss->call($clientId, $id, 'initial_password');
            }
            if (in_array($r['action'], ['start', 'stop'], true)) {
                if ($order['status'] !== 'active') { throw new DomainException('Owner cannot lift an administrative suspension'); }
                $this->foss->ownerPower($clientId, $id, $r['action'] === 'start');
            }
            if ($r['action'] === 'restart' && $order['status'] !== 'active') {
                throw new DomainException('Owner cannot restart an inactive VPS');
            }
            $info = $r['action'] === 'restart'
                ? $this->foss->ownerRestart($clientId, $id, $r['operation_id']) : $this->info($clientId, $id);
            $phase = $info['phase'] ?? 'ready';
            if ($phase === 'stopped' || ($phase === 'ready' && $info['status'] === 'stopped')) { $phase = 'suspended'; }
            elseif ($phase === 'ready') { $phase = ($info['ready'] ?? false) ? 'ready' : 'preparing'; }
            elseif (!in_array($phase, ['blocked','archived','deleted','cancelled','missing'], true)) { $phase = 'preparing'; }
            return ['order_id' => $id, 'phase' => $phase, 'reason' => $info['reason'] ?? null,
                'status' => $info['status'], 'public_ip' => $info['public_ip'], 'ssh_port' => $info['ssh_port'],
                'user' => $info['user'], 'ssh' => $info['ssh'], 'vmid' => $info['vmid'],
                'auth_mode' => $info['auth_mode'] ?? ($row['ssh_key'] === null ? 'password' : 'key'),
                'network_mode'=>$info['network_mode']??'nat','lease_id'=>$info['lease_id']??null,'lease_generation'=>$info['lease_generation']??null];
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
}

final class FossPortal
{
    private object $api;
    public function __construct(private $di) { $di['loggedin_admin'] = $di['db']->getExistingModelById('Admin', 1); $this->api = $di['api_admin']; }
    public function client(string $account): int
    {
        // Internal identity is stable even if the cabinet email changes. Mail stays disabled.
        $email = 'portal-' . $account . '@safe-host.ru';
        $existing = $this->di['db']->findOne('Client', 'email = :email', ['email' => $email]);
        if ($existing) {
            if ($existing->last_name !== $account) { throw new DomainException('Client identity conflict'); }
            return (int) $existing->id;
        }
        return (int) $this->api->client_create(['email' => $email, 'first_name' => 'Portal', 'last_name' => $account,
            'password' => 'Portal1!' . bin2hex(random_bytes(32)), 'send_welcome_email' => false]);
    }
    public function order(int $client, string $reference, string $plan, array $network=[]): int
    {
        $title = 'Portal ' . $reference;
        $existing = $this->di['db']->findOne('ClientOrder', 'client_id = :client AND title = :title', ['client' => $client, 'title' => $title]);
        $catalog = json_decode(file_get_contents('/var/www/html/data/pilot-catalog.json'), true, 512, JSON_THROW_ON_ERROR);
        $product = (int) $catalog['products'][$plan];
        if ($existing) {
            if ((int) $existing->product_id !== $product || (float) $existing->price !== 0.0) { throw new DomainException('Order identity conflict'); }
            return (int) $existing->id;
        }
        return (int) $this->api->order_create(['client_id' => $client, 'product_id' => $product, 'period' => '1M',
            'title' => $title, 'config' => array_merge(['ssh_key' => '', 'os' => 'Ubuntu 24.04'],$network), 'price' => 0, 'invoice_option' => 'no-invoice', 'activate' => false]);
    }
    public function network(array $request): array
    {
        require_once __DIR__.'/EngineGateway.php';
        return (new EngineGateway())->network($request);
    }
    public function get(int $id): array
    {
        $this->di['em']->clear();
        if (!(int) $this->di['em']->getConnection()->fetchOne('SELECT COUNT(*) FROM client_order WHERE id = ?', [$id])) {
            throw new OutOfBoundsException('Native order not found');
        }
        return $this->api->order_get(['id' => $id]);
    }
    public function boundStatus(int $client, int $order): array
    {
        require_once __DIR__ . '/EngineGateway.php';
        $info = (new EngineGateway())->ownerStatus($client, $order);
        if (!in_array($info['phase'], ['deleted', 'missing'], true)) {
            $info['phase'] = 'cancelled'; $info['ready'] = false;
            $info['reason'] = 'Заказ FOSSBilling удалён; управление доступно только администратору';
        }
        return $info;
    }
    public function activate(int $id): void { $this->api->order_activate(['id' => $id]); }
    public function metrics(int $client, int $order, string $timeframe): array
    {
        $data = $this->get($order);
        if ((int) $data['client_id'] !== $client) { throw new DomainException('Ownership changed'); }
        require_once __DIR__ . '/EngineGateway.php';
        return (new EngineGateway())->metrics($client, $order, $timeframe);
    }
    public function suspend(int $id): void { $this->api->order_suspend(['id' => $id, 'reason' => 'Stopped from owner cabinet']); }
    public function unsuspend(int $id): void { $this->api->order_unsuspend(['id' => $id]); }
    public function ownerPower(int $client, int $id, bool $start): array
    {
        $data = $this->get($id);
        if ((int) $data['client_id'] !== $client || $data['status'] !== 'active') { throw new DomainException('Owner operation unavailable'); }
        if($start){require_once __DIR__.'/FinanceLifecycle.php';FinanceLifecycle::fromDi($this->di)->check($data,'owner_start');}
        require_once __DIR__ . '/EngineGateway.php';
        $result = (new EngineGateway())->ownerPower($client, $id, $start);
        $this->api->order_update(['id' => $id, 'status' => 'active']);
        return $result;
    }
    public function ownerRestart(int $client, int $id, string $operation): array
    {
        $data = $this->get($id);
        if ((int) $data['client_id'] !== $client || $data['status'] !== 'active') { throw new DomainException('Owner operation unavailable'); }
        require_once __DIR__.'/FinanceLifecycle.php';
        FinanceLifecycle::fromDi($this->di)->check($data, 'owner_start');
        require_once __DIR__.'/EngineGateway.php';
        return (new EngineGateway())->ownerRestart($client, $id, $operation);
    }
    public function call(int $client, int $order, string $method): array
    {
        // Core Client customCall disallows even read-only status on suspended orders.
        // Service authentication + durable account mapping + this fresh ownership check
        // replace that gate for these two read-only adapter methods only.
        if (!in_array($method, ['readiness', 'initial_password'], true)) { throw new InvalidArgumentException('Invalid method'); }
        $data = $this->get($order);
        if ((int) $data['client_id'] !== $client) { throw new DomainException('Ownership changed'); }
        require_once '/var/www/html/library/Plugin/SafehostProxmox/SafehostProxmox.php';
        return (new SafehostProxmox())->$method([], $data, ['order_id' => $order, 'method' => $method]);
    }
}
