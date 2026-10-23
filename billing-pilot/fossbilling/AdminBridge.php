<?php
declare(strict_types=1);
require_once __DIR__ . '/EngineGateway.php';
require_once __DIR__ . '/FinanceLifecycle.php';

final class AdminBridge
{
    private PDO $db;
    public function __construct(private object $foss, private object $engine, private string $directory)
    {
        if (!is_dir($directory)) { mkdir($directory, 0700, true); }
        $this->db = new PDO('sqlite:' . $directory . '/portal.sqlite');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec('PRAGMA busy_timeout=30000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS client(account TEXT PRIMARY KEY,client_id INTEGER NOT NULL UNIQUE)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS profile(account TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL,registered_at TEXT NOT NULL)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS admin_operation(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,order_id INTEGER NOT NULL,client_id INTEGER NOT NULL,command TEXT NOT NULL,reason TEXT NOT NULL,actor TEXT NOT NULL,confirm_vmid INTEGER,state TEXT NOT NULL,error TEXT,created_at TEXT NOT NULL,next_attempt TEXT NOT NULL)');
        chmod($directory . '/portal.sqlite', 0600);
        file_put_contents($directory . '/.htaccess', "Require all denied\n");
    }
    private static function uuid(mixed $value): string
    {
        if (!is_string($value) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D', $value)) {
            throw new InvalidArgumentException('UUID required');
        }
        return $value;
    }
    public static function actor(mixed $actor): array
    {
        if (!is_array($actor) || !is_string($actor['email'] ?? null) || strlen($actor['email']) > 254 || !filter_var($actor['email'], FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException('Actor required');
        }
        return ['account' => self::uuid($actor['account'] ?? null), 'email' => strtolower($actor['email'])];
    }
    private static function iso(mixed $value): string
    {
        if (!is_string($value) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$/D', $value)) { throw new InvalidArgumentException('UTC timestamp required'); }
        try { $date = new DateTimeImmutable($value); } catch(Throwable $e) { throw new InvalidArgumentException('Invalid date'); }
        $errors = DateTimeImmutable::getLastErrors();
        if ($errors && ($errors['warning_count'] || $errors['error_count'])) { throw new InvalidArgumentException('Invalid date'); }
        return $date->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
    private static function fossDate(?string $value): ?string
    {
        if (!$value) { return null; }
        return (new DateTimeImmutable($value, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }
    private static function now(): string { return gmdate('Y-m-d\TH:i:s\Z'); }
    private function row(string $sql, array $args): array|false { $q = $this->db->prepare($sql); $q->execute($args); return $q->fetch(PDO::FETCH_ASSOC); }
    private function write(string $sql, array $args): void { $q = $this->db->prepare($sql); $q->execute($args); }
    private function locked(bool $write, callable $call): mixed
    {
        $lock = fopen($this->directory . '/operation.lock', 'c');
        if (!$lock) { throw new RuntimeException('Bridge busy'); }
        try {
            if ($write) {
                if (!flock($lock, LOCK_EX)) { throw new RuntimeException('Bridge busy'); }
            } else {
                // Profile sync and the worker briefly hold the same exclusive lock.
                $deadline = hrtime(true) + 5_000_000_000;
                while (!flock($lock, LOCK_SH | LOCK_NB)) {
                    if (hrtime(true) >= $deadline) { throw new RuntimeException('Bridge busy'); }
                    usleep(10000);
                }
                if (hrtime(true) >= $deadline) { throw new RuntimeException('Bridge busy'); }
            }
            return $call();
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function handle(array $r): array
    {
        $actor = self::actor($r['actor'] ?? null);
        return match ($r['action'] ?? '') {
            'sync_clients' => $this->locked(true, fn() => $this->sync($r)),
            'dashboard' => $this->locked(false, fn() => $this->dashboard($r)),
            'infrastructure' => $this->locked(false, fn() => $this->infrastructure($actor)),
            'infrastructure_metrics' => $this->infrastructureMetrics($r, $actor),
            'action' => $this->enqueue($r, $actor),
            'operation' => $this->operation(self::uuid($r['operationId'] ?? null)),
            default => throw new InvalidArgumentException('Invalid action'),
        };
    }
    private function sync(array $r): array
    {
        $profiles = $r['clients'] ?? null;
        if (!is_array($profiles) || !array_is_list($profiles) || count($profiles) > 200) { throw new InvalidArgumentException('At most 200 profiles'); }
        $validated = [];
        foreach ($profiles as $p) {
            if (!is_array($p) || !is_string($p['name'] ?? null) || mb_strlen(trim($p['name'])) < 1 || mb_strlen($p['name']) > 254 || preg_match('/[\x00-\x1f]/', $p['name']) || !array_key_exists('email',$p) || ($p['email'] !== null && (!is_string($p['email']) || strlen($p['email']) > 254 || !filter_var($p['email'], FILTER_VALIDATE_EMAIL)))) { throw new InvalidArgumentException('Invalid profile'); }
            $validated[] = ['account' => self::uuid($p['account'] ?? null), 'name' => trim($p['name']), 'email' => $p['email'] === null ? null : strtolower($p['email']), 'registeredAt' => self::iso($p['registeredAt'] ?? null)];
        }
        foreach ($validated as $p) {
            $old = $this->row('SELECT * FROM profile WHERE account=?', [$p['account']]);
            if ($old && $old['registered_at'] !== $p['registeredAt']) { throw new DomainException('Registration identity conflict'); }
        }
        foreach ($validated as $p) {
            $mapping = $this->row('SELECT client_id FROM client WHERE account=?', [$p['account']]);
            if (!$mapping) {
                // Stable synthetic identity recovers client_create after a lost response.
                $id = $this->foss->client($p['account']);
                $this->write('INSERT INTO client(account,client_id) VALUES(?,?)', [$p['account'], $id]);
                $mapping = ['client_id' => $id];
            }
            $this->foss->sync((int) $mapping['client_id'], $p);
            $this->write('INSERT INTO profile VALUES(?,?,?,?) ON CONFLICT(account) DO UPDATE SET name=excluded.name,email=excluded.email', [$p['account'], $p['name'], $p['email'] ?? '', $p['registeredAt']]);
        }
        return ['source' => 'FOSSBilling', 'synced' => count($validated)];
    }
    private static function minor(mixed $amount): int
    {
        $text = (string) $amount;
        if (!preg_match('/^(-?)(\d{1,16})(?:\.(\d{1,2}))?$/D', $text, $m)) { throw new RuntimeException('Invalid native balance'); }
        $minor = (int) $m[2] * 100 + (int) str_pad($m[3] ?? '', 2, '0');
        return ($m[1] === '-' ? -1 : 1) * $minor;
    }
    private static function infrastructureRows(array $report): array
    {
        $rows = $report['infrastructure'] ?? null;
        if (!is_array($rows) || !array_is_list($rows)) { throw new RuntimeException('Infrastructure registry unavailable'); }
        $fields = array_flip(['vmid','node','account','name','os','address','publicIpv4','status','phase','cores','memoryMb','diskGb','observedAt']);
        $result = [];
        foreach ($rows as $row) {
            if (!is_array($row) || count(array_intersect_key($row, $fields)) !== count($fields)) { throw new RuntimeException('Invalid infrastructure observation'); }
            self::uuid($row['account']);
            $result[] = array_intersect_key($row, $fields);
        }
        return $result;
    }
    private function infrastructure(array $actor): array
    {
        $rows = self::infrastructureRows($this->engine->monitoring());
        return ['servers' => array_values(array_filter($rows, static fn(array $row): bool => $row['account'] === $actor['account']))];
    }
    private function infrastructureMetrics(array $request, array $actor): array
    {
        $validVmid = is_int($request['vmid'] ?? null) && $request['vmid'] > 0 && $request['vmid'] < 2147483647;
        $validNode = is_string($request['node'] ?? null) && preg_match('/^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$/D', $request['node']);
        $validPeriod = in_array($request['timeframe'] ?? null, ['day','week'], true);
        if (!$validVmid || !$validNode || !$validPeriod) { throw new InvalidArgumentException('Invalid infrastructure metrics request'); }
        return $this->engine->infrastructureMetrics($actor['account'], $request['vmid'], $request['node'], $request['timeframe']);
    }
    private static function infrastructureServer(array $row, array $maps, int $orderId = 0, ?string $createdAt = null): array
    {
        $client = array_search($row['account'], $maps, true);
        return [...$row, 'infrastructure'=>true, 'orderId'=>$orderId, 'clientId'=>$client === false ? 0 : (int)$client,
            'plan'=>'infrastructure', 'reason'=>'Служебный сервер: операции и списания отключены', 'createdAt'=>$createdAt,
            'networkMode'=>$row['publicIpv4'] ? 'public_ipv4' : 'nat', 'leaseId'=>null,
            'publicIp'=>$row['publicIpv4'] ? $row['address'] : null, 'sshPort'=>null,
            'metrics'=>array_fill_keys(['cpuFraction','memoryUsedBytes','memoryTotalBytes','guestDiskUsedBytes','guestDiskTotalBytes'], null)];
    }
    private function dashboard(array $r): array
    {
        $start = self::iso($r['dayStart'] ?? null); $end = self::iso($r['dayEnd'] ?? null);
        if ($end <= $start || strtotime($end) - strtotime($start) > 172800) { throw new InvalidArgumentException('Invalid day interval'); }
        $maps = []; foreach ($this->db->query('SELECT * FROM client') as $m) { $maps[(int) $m['client_id']] = $m['account']; }
        $profiles = []; foreach ($this->db->query('SELECT * FROM profile') as $p) { $profiles[$p['account']] = $p; }
        $orders = []; foreach ($this->foss->orders() as $o) { $orders[(int) $o['id']] = $o; }
        $infra = $this->engine->monitoring(); $servers = []; $plans = [];
        $infrastructure = [];
        foreach (self::infrastructureRows($infra) as $row) { $infrastructure[$row['vmid']] = $row; }
        foreach ($infra['servers'] as $s) {
            $order = $orders[(int) $s['orderId']] ?? null;
            if ($order && (int) $order['client_id'] !== (int) $s['clientId']) { continue; }
            if (isset($infrastructure[$s['vmid']])) {
                $row = $infrastructure[$s['vmid']];
                $servers[] = self::infrastructureServer($row, $maps, (int)$s['orderId'], self::fossDate($s['createdAt'] ?? $order['created_at'] ?? null));
                unset($infrastructure[$s['vmid']]);
                continue;
            }
            $client = (int) $s['clientId']; $phase = $s['phase'];
            if (!$order && !in_array($phase, ['deleted','missing','archived'], true)) { $phase = 'cancelled'; }
            if ($phase !== 'deleted') { $plans[$client][$s['plan']] = true; }
            $metrics = []; foreach (['cpuFraction','memoryUsedBytes','memoryTotalBytes','guestDiskUsedBytes','guestDiskTotalBytes'] as $key) { $metrics[$key] = $s['metrics'][$key] ?? null; }
            $servers[] = ['infrastructure'=>false, 'orderId' => (int) $s['orderId'], 'clientId' => $client, 'account' => $maps[$client] ?? null,
                'name' => $order['title'] ?? ('VPS order ' . $s['orderId']), 'plan' => $s['plan'], 'vmid' => $s['vmid'], 'node' => $s['node'], 'phase' => $phase,
                'status' => $s['status'], 'reason' => $order ? ($s['reason'] ?? null) : 'Заказ FOSSBilling удалён; retained VM доступна администратору', 'createdAt' => self::fossDate($s['createdAt'] ?? $order['activated_at'] ?? $order['created_at'] ?? null),
                'networkMode'=>$s['network_mode']??'nat','leaseId'=>$s['lease_id']??null,
                'publicIp' => $s['public_ip'] ?? null, 'sshPort' => $s['ssh_port'] ?? null, 'cores' => $s['cores'], 'memoryMb' => $s['memoryMb'], 'diskGb' => $s['diskGb'], 'metrics' => $metrics];
        }
        foreach ($infrastructure as $row) { $servers[] = self::infrastructureServer($row, $maps); }
        $clients = [];
        foreach ($this->foss->clients() as $c) {
            $id = (int) $c['id']; $account = $maps[$id] ?? null; $p = $profiles[$account ?? ''] ?? null;
            $name = trim(($c['first_name'] ?? '') . ' ' . (($c['last_name'] ?? '') === $account ? '' : ($c['last_name'] ?? '')));
            $clients[] = ['account' => $account, 'clientId' => $id, 'name' => $p['name'] ?? $name,
                'email' => $c['billing_email'] ?: ($account !== null ? '' : $c['email']), 'registeredAt' => self::fossDate($c['created_at']),
                'balanceMinor' => self::minor($c['balance']), 'currency' => $c['currency'], 'plans' => array_keys($plans[$id] ?? [])];
        }
        $hosts = []; foreach ($infra['hosts'] as $h) { $hosts[] = array_intersect_key($h, array_flip(['node','cpuFraction','cpuCores','memoryUsedBytes','memoryTotalBytes','memoryReservedBytes','vcpuReserved','storageUsedBytes','storageTotalBytes','storageFreeBytes','slotsFree'])); }
        $today = static fn(?string $date): bool => $date !== null && $date >= $start && $date < $end;
        $events = [];
        foreach ($this->db->query('SELECT * FROM admin_operation ORDER BY created_at DESC,id DESC LIMIT 100') as $op) {
            $events[] = ['id' => $op['id'], 'orderId' => (int) $op['order_id'], 'action' => $op['command'], 'actor' => json_decode($op['actor'], true)['email'], 'reason' => $op['reason'], 'state' => $op['state'], 'createdAt' => $op['created_at'], 'error' => $op['error']];
        }
        return ['source' => 'FOSSBilling', 'generatedAt' => self::now(), 'stats' => [
            'clientsTotal' => count($clients), 'clientsToday' => count(array_filter($clients, fn($c) => $today($c['registeredAt']))),
            'serversTotal' => count(array_filter($servers, fn($s) => $s['phase'] !== 'deleted')),
            'serversToday' => count(array_filter($servers, fn($s) => $today($s['createdAt'])))],
            'clients' => $clients, 'servers' => $servers, 'hosts' => $hosts, 'events' => $events,'publicIpv4'=>$infra['publicIpv4']??null];
    }
    private function enqueue(array $r, array $actor): array
    {
        $id = self::uuid($r['operationId'] ?? null); $command = $r['command'] ?? '';
        if (!in_array($command, ['start','stop','block','unblock','archive','restore','purge'], true) || !is_int($r['orderId'] ?? null) || $r['orderId'] < 1 || !is_string($r['reason'] ?? null) || mb_strlen(trim($r['reason'])) < 3 || mb_strlen($r['reason']) > 500) { throw new InvalidArgumentException('Invalid operation'); }
        if ($command === 'purge' && (!is_int($r['confirmVmid'] ?? null) || $r['confirmVmid'] < 1)) { throw new InvalidArgumentException('Typed VMID required'); }
        $canonical = ['operationId' => $id, 'orderId' => $r['orderId'], 'command' => $command, 'reason' => trim($r['reason']), 'actor' => $actor, 'confirmVmid' => $command === 'purge' ? $r['confirmVmid'] : null];
        $fingerprint = hash('sha256', json_encode($canonical, JSON_THROW_ON_ERROR));
        $lock = fopen($this->directory . '/admin-queue.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX)) { throw new RuntimeException('Queue unavailable'); }
        try {
            $old = $this->row('SELECT * FROM admin_operation WHERE id=?', [$id]);
            if ($old) {
                if ($old['fingerprint'] !== $fingerprint) { throw new DomainException('Operation identity conflict'); }
                return $this->operationData($old);
            }
            // No side effect: native order lookup only. Claim/execute happens in the CLI worker.
            $order = $this->foss->managedOrder($r['orderId']);
            $this->engine->assertMutable((int)$order['client_id'], $r['orderId']);
            $now = self::now();
            $this->write('INSERT INTO admin_operation VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', [$id,$fingerprint,$r['orderId'],(int) $order['client_id'],$command,trim($r['reason']),json_encode($actor),$canonical['confirmVmid'],'pending',null,$now,$now]);
        } finally { flock($lock, LOCK_UN); fclose($lock); }
        return $this->operation($id);
    }
    private function operationData(array $row): array { return ['id' => $row['id'], 'orderId' => (int) $row['order_id'], 'action' => $row['command'], 'state' => $row['state'], 'error' => $row['error']]; }
    private function operation(string $id): array { $row = $this->row('SELECT * FROM admin_operation WHERE id=?', [$id]); if (!$row) { throw new OutOfBoundsException('Operation not found'); } return $this->operationData($row); }
    public function processOne(bool $force = false): bool
    {
        $worker = fopen($this->directory . '/admin-worker.lock', 'c');
        if (!$worker || !flock($worker, LOCK_EX | LOCK_NB)) { return false; }
        try {
            return $this->locked(true, function() use ($force): bool {
                if(method_exists($this->foss,'recoverNativeFinance')&&$this->foss->recoverNativeFinance($this->engine,$force))return true;
                $query = "SELECT * FROM admin_operation WHERE state IN ('pending','running')" . ($force ? '' : ' AND next_attempt<=?') . ' ORDER BY created_at,id LIMIT 1';
                $row = $this->row($query, $force ? [] : [self::now()]); if (!$row) { return false; }
                $this->write('UPDATE admin_operation SET state=?,error=NULL WHERE id=?', ['running',$row['id']]);
                $request = ['operationId' => $row['id'], 'reason' => $row['reason'], 'actor' => json_decode($row['actor'], true), 'confirmVmid' => $row['confirm_vmid'] === null ? null : (int) $row['confirm_vmid']];
                try {
                    $order = $this->foss->managedOrder((int) $row['order_id']);
                    if ((int) $order['client_id'] !== (int) $row['client_id']) { throw new DomainException('Ownership changed'); }
                    $this->engine->assertMutable((int)$order['client_id'], (int)$row['order_id']);
                    $this->foss->effect($order, $row['command'], $request, $this->engine);
                    $this->write('UPDATE admin_operation SET state=?,error=NULL WHERE id=?', ['done',$row['id']]);
                } catch(DomainException|OutOfBoundsException $e) {
                    $this->write('UPDATE admin_operation SET state=?,error=? WHERE id=?', ['failed','Операция отклонена: проверьте состояние VPS, VMID и доступные ресурсы',$row['id']]);
                } catch(Throwable $e) {
                    $this->write('UPDATE admin_operation SET state=?,error=NULL,next_attempt=? WHERE id=?', ['pending',gmdate('Y-m-d\TH:i:s\Z',time()+30),$row['id']]);
                }
                return true;
            });
        } finally { flock($worker, LOCK_UN); fclose($worker); }
    }
}

final class FossAdmin
{
    private object $api; private array $catalog; private FossPortal $portal; private FinanceLifecycle $finance;
    public function __construct(private $di)
    {
        require_once __DIR__ . '/PortalBridge.php';
        $this->portal = new FossPortal($di); $this->api = $di['api_admin'];
        $this->finance=FinanceLifecycle::fromDi($di);
        $this->catalog = json_decode(file_get_contents('/var/www/html/data/pilot-catalog.json'), true, 512, JSON_THROW_ON_ERROR)['products'];
    }
    public function client(string $account): int { return $this->portal->client($account); }
    public function sync(int $id, array $p): void
    {
        $native = $this->api->client_get(['id'=>$id]);
        if ($native['email'] !== 'portal-' . $p['account'] . '@safe-host.ru' || $native['last_name'] !== $p['account']) { throw new DomainException('Native client identity changed'); }
        $this->api->client_update(['id' => $id, 'first_name' => mb_substr($p['name'],0,100),
            'created_at' => (new DateTimeImmutable($p['registeredAt']))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s')]);
        // Contact was already validated by the Spring/authenticated bridge. FOSS's
        // public update RPC also requires live DNS; registration sync must preserve
        // an accepted address during DNS outages and for private email domains.
        if ($p['email'] !== null) {
            $client = $this->di['em']->getRepository(\Box\Mod\Client\Entity\Client::class)->find($id);
            $client->setBillingEmail($p['email']); $this->di['em']->persist($client); $this->di['em']->flush();
        }
    }
    private function all(string $method): array
    {
        $all = []; $page = 1;
        do { $result = $this->api->$method(['page' => $page++, 'per_page' => 200]); $list = $result['list'] ?? [];
            array_push($all, ...$list);
        } while ($list && count($all) < (int) ($result['total'] ?? count($all)));
        return $all;
    }
    public function clients(): array
    {
        $clients = array_values(array_filter($this->all('client_get_list'), static fn(array $client): bool => ($client['status'] ?? 'active') === 'active'));
        $default = $this->api->currency_get_default();
        foreach ($clients as &$c) {
            // DECIMAL source stays exact; the native API's float total loses precision for large balances.
            $c['balance'] = (string) $this->di['em']->getConnection()->fetchOne('SELECT COALESCE(SUM(amount),0) FROM client_balance WHERE client_id=?', [(int) $c['id']]);
            $c['currency'] = $c['currency'] ?: $default['code'];
        }
        return $clients;
    }
    public function orders(): array
    {
        $plans = array_flip($this->catalog); $orders = [];
        foreach ($this->all('order_get_list') as $o) { if (isset($plans[(int) $o['product_id']])) { $o['plan'] = $plans[(int) $o['product_id']]; $orders[] = $o; } }
        return $orders;
    }
    public function managedOrder(int $id): array
    {
        $this->di['em']->clear();
        try { $order = $this->portal->get($id); }
        catch (OutOfBoundsException $e) {
            // Native delete keeps the allocation. Recovery stays in this server-only
            // gateway and never adds a Client-callable plugin method or a new order.
            foreach ((new EngineGateway())->monitoring()['servers'] as $server) {
                if ((int) $server['orderId'] === $id && isset($this->catalog[$server['plan']])) {
                    return ['id'=>$id,'client_id'=>(int) $server['clientId'],'status'=>'canceled','nativeMissing'=>true];
                }
            }
            throw new OutOfBoundsException('Managed allocation not found');
        }
        $service = $this->api->order_service(['id' => $id]);
        if (!in_array((int) $order['product_id'], array_values($this->catalog), true) || ($service['plugin'] ?? '') !== 'SafehostProxmox') { throw new DomainException('Unmanaged order'); }
        return $order;
    }
    public function effect(array $order, string $command, array $request, object $engine): void
    {
        $id = (int) $order['id'];
        $engine->assertMutable((int)$order['client_id'], $id);
        if (($order['nativeMissing'] ?? false) && !in_array($command, ['archive','restore','purge'], true)) { throw new DomainException('Native order is absent'); }
        if(in_array($command,['archive','purge','restore'],true)){
            $state=$engine->state((int)$order['client_id'],$id);
            if($command==='purge'&&($state['vmid']??null)!==$request['confirmVmid'])throw new DomainException('VMID confirmation mismatch');
            if(($state['ownership']??'')!=='owned'&&!($command==='purge'&&($state['phase']??'')==='deleted'))throw new DomainException('Managed VM unavailable');
            $allowed=match($command){'archive'=>['ready','stopped','blocked','suspended','cancelled','archived','archiving'],'restore'=>['archived','restoring','ready'],default=>null};
            if($allowed!==null&&!in_array($state['phase'],$allowed,true))throw new DomainException('VM state does not permit lifecycle');
            $this->finance->prepare($order,$command,$request);
        }
        elseif(in_array($command,['start','unblock'],true))$this->finance->check($order,$command,$request);
        $result = $engine->action($order, $command, $request);
        if(in_array($command,['archive','purge','restore'],true))$this->finance->complete($order,$command,$request,$result);
        if ($order['nativeMissing'] ?? false) { return; }
        if ($command === 'block' && $order['status'] === 'active') { $this->api->order_suspend(['id'=>$id,'reason'=>$request['reason']]); }
        if ($command === 'unblock' && $order['status'] === 'suspended') { $this->api->order_unsuspend(['id'=>$id]); }
        $status = match($result['phase']) { 'blocked','archived' => 'suspended', 'deleted','cancelled' => 'canceled', default => 'active' };
        $this->api->order_update(['id'=>$id,'status'=>$status]);
    }
    public function recoverNativeFinance(object $engine,bool $force): bool{return $this->finance->processNativeOne($engine,$force);}
}
