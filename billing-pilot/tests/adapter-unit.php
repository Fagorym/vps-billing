<?php
declare(strict_types=1);
namespace FOSSBilling { class InformationException extends \RuntimeException {} }
namespace {
require '/opt/pilot/FinanceLifecycle.php';
require '/opt/pilot/SafehostProxmox.php';
require '/opt/pilot/PortalBridge.php';
function adapterCheck(bool $ok): void { if (!$ok) { throw new RuntimeException('Adapter contract failed'); } }
$directory = sys_get_temp_dir().'/adapter-os-'.bin2hex(random_bytes(6));
$gateway = new class {
    public bool $deny = false;
    public array $calls = [];
    public function exchange(array $request): array {
        $this->calls[] = $request;
        if ($this->deny) { throw new DomainException('Financial activation denied'); }
        return ['ok'=>true, 'paidService'=>false, 'state'=>'prepared'];
    }
};
$finance = new FinanceLifecycle($directory, $gateway, fn(int $id): array => ['email'=>'native@example.test', 'last_name'=>'Native']);
$outgoing = [];
$adapter = new SafehostProxmox(['plan'=>'small'], $finance, function(array $payload) use (&$outgoing): array {
    $outgoing[] = $payload;
    return $payload['action']==='mutation_guard' ? ['mutable'=>true] : ['phase'=>'ready'];
});
$order = ['id'=>17, 'client_id'=>23, 'status'=>'pending_setup'];
$data = ['disk_gb'=>60, 'ssh_key'=>'ssh-ed25519 example', 'network_mode'=>'public_ipv4',
    'lease_id'=>'11111111-1111-4111-8111-111111111111', 'account'=>'22222222-2222-4222-8222-222222222222',
    'reference'=>'33333333-3333-4333-8333-333333333333'];
$operatingSystems = ['Ubuntu 24.04', 'Ubuntu 22.04', 'Ubuntu 26.04', 'Debian 13', 'Debian 12', 'AlmaLinux 9', 'AlmaLinux 10'];
foreach ($operatingSystems as $os) {
    adapterCheck($adapter->activate($data+['os'=>$os], $order));
    adapterCheck(end($outgoing) === ['plan'=>'small', 'disk_gb'=>60, 'os'=>$os, 'ssh_key'=>'ssh-ed25519 example',
        'network_mode'=>'public_ipv4', 'lease_id'=>$data['lease_id'], 'account'=>$data['account'],
        'reference'=>$data['reference'], 'action'=>'create', 'order_id'=>17, 'client_id'=>23]);
}
adapterCheck($adapter->activate([], $order));
adapterCheck(end($outgoing) === ['plan'=>'small', 'disk_gb'=>null, 'os'=>'Ubuntu 24.04', 'ssh_key'=>'',
    'network_mode'=>'nat', 'lease_id'=>null, 'account'=>null, 'reference'=>null,
    'action'=>'create', 'order_id'=>17, 'client_id'=>23]);
$count = count($outgoing);$gateway->deny = true;
try { $adapter->activate($data+['os'=>'Debian 13'], $order);throw new LogicException('Finance denial ignored'); }
catch (DomainException $expected) {}
adapterCheck(count($outgoing) === $count+1 && end($outgoing)['action']==='mutation_guard');$count=count($outgoing);
$gateway->deny = false;
try { $adapter->activate($data, $order, ['method'=>'activate', 'order_id'=>17]);throw new LogicException('Custom lifecycle call accepted'); }
catch (\FOSSBilling\InformationException $expected) {}
adapterCheck(count($outgoing) === $count && count($gateway->calls) === count($operatingSystems) + 2);
$blocked=new SafehostProxmox(['plan'=>'small'],$finance,function(array $payload): array {
    adapterCheck($payload['action']==='mutation_guard');throw new \FOSSBilling\InformationException('Infrastructure is read-only');
});
$callbacks=count($gateway->calls);
foreach(['activate','suspend','unsuspend','cancel','delete','renew','initial_password'] as $method){
    try{$blocked->$method([],['id'=>12,'client_id'=>16,'status'=>'active']);throw new LogicException('Infrastructure lifecycle accepted');}
    catch(\FOSSBilling\InformationException $expected){}
}
adapterCheck(count($gateway->calls)===$callbacks);
$db = new class {
    public ?object $existing = null;
    public function getExistingModelById(string $model, int $id): object { return (object)['id'=>$id]; }
    public function findOne(string $model, string $query, array $args): ?object { return $this->existing; }
};
$api = new class {
    public array $calls = [];
    public function order_create(array $request): int { $this->calls[] = $request;return count($this->calls); }
};
$catalog = json_decode(file_get_contents('/var/www/html/data/pilot-catalog.json'), true, 512, JSON_THROW_ON_ERROR);
$foss = new FossPortal(['db'=>$db, 'api_admin'=>$api]);
foreach ($operatingSystems as $os) {
    $config = $data;unset($config['ssh_key']);$config['os'] = $os;
    $foss->order(23, $data['reference'], 'small', $config);
    adapterCheck(end($api->calls) === ['client_id'=>23, 'product_id'=>(int)$catalog['products']['small'], 'period'=>'1M',
        'title'=>'Portal '.$data['reference'], 'config'=>['ssh_key'=>'', 'os'=>$os]+$config,
        'price'=>0, 'invoice_option'=>'no-invoice', 'activate'=>false]);
}
$foss->order(23, $data['reference'], 'small');
adapterCheck(end($api->calls)['config'] === ['ssh_key'=>'', 'os'=>'Ubuntu 24.04']);
$db->existing = (object)['id'=>91, 'product_id'=>$catalog['products']['small'], 'price'=>0, 'config'=>'historic'];
adapterCheck($foss->order(23, $data['reference'], 'small', ['os'=>'Debian 13']) === 91);
adapterCheck(count($api->calls) === count($operatingSystems) + 1 && $db->existing->config === 'historic');
echo "PASS: adapter full OS/SSD/network/owner create payload, legacy defaults, financial and lifecycle guards\n";
}
