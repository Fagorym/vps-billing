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
        $this->db->exec('CREATE TABLE IF NOT EXISTS orders (reference TEXT PRIMARY KEY, account TEXT NOT NULL UNIQUE, plan TEXT NOT NULL, order_id INTEGER UNIQUE)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS retired_orders (reference TEXT PRIMARY KEY, account TEXT NOT NULL, plan TEXT NOT NULL, order_id INTEGER UNIQUE)');
        chmod($directory . '/portal.sqlite', 0600);
        file_put_contents($directory . '/.htaccess', "Require all denied\n");
    }
    private function row(string $sql, array $args): array|false
    {
        $s = $this->db->prepare($sql); $s->execute($args); return $s->fetch(PDO::FETCH_ASSOC);
    }
    private function write(string $sql, array $args): void
    {
        $s = $this->db->prepare($sql); $s->execute($args);
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
        if (!in_array($r['action'] ?? '', ['create', 'status', 'password', 'start', 'stop'], true)) {
            throw new InvalidArgumentException('Invalid action');
        }
        // Writers serialize reservation and activation. Reads share the lock and refuse a busy
        // writer immediately instead of queueing a credential request behind provisioning.
        $lock = fopen($this->directory . '/operation.lock', 'c');
        $mode = in_array($r['action'], ['status', 'password'], true) ? LOCK_SH | LOCK_NB : LOCK_EX;
        if (!$lock || !flock($lock, $mode)) { throw new RuntimeException('Bridge unavailable'); }
        try {
            $row = $this->row('SELECT * FROM orders WHERE reference=?', [$r['reference']]);
            if (!$row) { $row = $this->row('SELECT * FROM retired_orders WHERE reference=?', [$r['reference']]); }
            if ($r['action'] === 'create') {
                if (!in_array($r['plan'] ?? '', ['mini', 'small', 'medium'], true)) { throw new InvalidArgumentException('Invalid plan'); }
                if ($row && ($row['account'] !== $r['account'] || $row['plan'] !== $r['plan'])) { throw new DomainException('Reference conflict'); }
                if (!$row) {
                    $previous = $this->row('SELECT * FROM orders WHERE account=?', [$r['account']]);
                    if ($previous) {
                        $binding = $this->row('SELECT client_id FROM client WHERE account=?', [$r['account']]);
                        if (!$binding || !$previous['order_id'] || ($this->info((int) $binding['client_id'], (int) $previous['order_id'])['phase'] ?? '') !== 'deleted') {
                            throw new DomainException('One VPS per account');
                        }
                        $this->db->beginTransaction();
                        try {
                            $this->write('INSERT INTO retired_orders SELECT * FROM orders WHERE reference=?', [$previous['reference']]);
                            $this->write('DELETE FROM orders WHERE reference=?', [$previous['reference']]);
                            $this->write('INSERT INTO orders(reference,account,plan) VALUES(?,?,?)', [$r['reference'], $r['account'], $r['plan']]);
                            $this->db->commit();
                        } catch (Throwable $e) { $this->db->rollBack(); throw $e; }
                    } else {
                    $this->write('INSERT INTO orders(reference,account,plan) VALUES(?,?,?)', [$r['reference'], $r['account'], $r['plan']]);
                    }
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
                $id = $this->foss->order($clientId, $r['reference'], $row['plan']);
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
            if ($order && $r['action'] === 'create' && in_array($order['status'], ['pending_setup', 'failed_setup'], true)) {
                $this->foss->activate($id); $order = $this->foss->get($id);
            }
            if ($r['action'] === 'password') {
                if ($order['status'] !== 'active') { throw new DomainException('VPS inactive'); }
                // The adapter checks ownership, VM state and SSH readiness in this same call.
                return $this->foss->call($clientId, $id, 'initial_password');
            }
            if (in_array($r['action'], ['start', 'stop'], true)) {
                if ($order['status'] !== 'active') { throw new DomainException('Owner cannot lift an administrative suspension'); }
                $this->foss->ownerPower($clientId, $id, $r['action'] === 'start');
            }
            $info = $this->info($clientId, $id);
            $phase = $info['phase'] ?? 'ready';
            if ($phase === 'stopped' || ($phase === 'ready' && $info['status'] === 'stopped')) { $phase = 'suspended'; }
            elseif ($phase === 'ready') { $phase = ($info['ready'] ?? false) ? 'ready' : 'preparing'; }
            elseif (!in_array($phase, ['blocked','archived','deleted','cancelled','missing'], true)) { $phase = 'preparing'; }
            return ['order_id' => $id, 'phase' => $phase, 'reason' => $info['reason'] ?? null,
                'status' => $info['status'], 'public_ip' => $info['public_ip'], 'ssh_port' => $info['ssh_port'],
                'user' => $info['user'], 'ssh' => $info['ssh'], 'vmid' => $info['vmid']];
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
    public function order(int $client, string $reference, string $plan): int
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
            'title' => $title, 'config' => ['ssh_key' => ''], 'price' => 0, 'invoice_option' => 'no-invoice', 'activate' => false]);
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
