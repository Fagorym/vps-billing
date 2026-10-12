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
            if ($r['action'] === 'create') {
                if (!in_array($r['plan'] ?? '', ['mini', 'small', 'medium'], true)) { throw new InvalidArgumentException('Invalid plan'); }
                if ($row && ($row['account'] !== $r['account'] || $row['plan'] !== $r['plan'])) { throw new DomainException('Reference conflict'); }
                if (!$row) {
                    if ($this->row('SELECT * FROM orders WHERE account=?', [$r['account']])) { throw new DomainException('One VPS per account'); }
                    $this->write('INSERT INTO orders(reference,account,plan) VALUES(?,?,?)', [$r['reference'], $r['account'], $r['plan']]);
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
            $order = $this->foss->get($id);
            if ((int) $order['client_id'] !== $clientId) { throw new DomainException('Ownership changed'); }
            if ($r['action'] === 'create' && in_array($order['status'], ['pending_setup', 'failed_setup'], true)) {
                $this->foss->activate($id); $order = $this->foss->get($id);
            }
            if ($r['action'] === 'password') {
                if ($order['status'] !== 'active') { throw new DomainException('VPS inactive'); }
                // The adapter checks ownership, VM state and SSH readiness in this same call.
                return $this->foss->call($clientId, $id, 'initial_password');
            }
            if ($r['action'] === 'stop' && $order['status'] === 'active') { $this->foss->suspend($id); }
            if ($r['action'] === 'start' && $order['status'] === 'suspended') { $this->foss->unsuspend($id); }
            $order = $this->foss->get($id);
            if (!in_array($order['status'], ['active', 'suspended'], true)) { throw new DomainException('VPS unavailable'); }
            $info = $this->foss->call($clientId, $id, 'readiness');
            return ['order_id' => $id, 'phase' => $order['status'] === 'suspended' ? 'suspended' : (($info['ready'] ?? false) ? 'ready' : 'preparing'),
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
    public function get(int $id): array { $this->di['em']->clear(); return $this->api->order_get(['id' => $id]); }
    public function activate(int $id): void { $this->api->order_activate(['id' => $id]); }
    public function suspend(int $id): void { $this->api->order_suspend(['id' => $id, 'reason' => 'Stopped from owner cabinet']); }
    public function unsuspend(int $id): void { $this->api->order_unsuspend(['id' => $id]); }
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
