<?php
declare(strict_types=1);
require '/opt/pilot/PortalBridge.php';
function check(bool $ok): void {if(!$ok)throw new RuntimeException('Public portal assertion failed');}
final class PublicFoss {
 public array $config=[];public array $orders=[];public array $phases=[];
 public function network(array $r): array {return ['id'=>'33333333-3333-4333-8333-333333333333','state'=>'held','address'=>'198.51.100.3'];}
 public function client(string $account): int {return 2;}
 public function order(int $client,string $ref,string $plan,array $network=[]): int {$this->config=$network;$id=count($this->orders)+1;$this->orders[$id]=['client_id'=>2,'status'=>'pending_setup'];return $id;}
 public function get(int $id): array {return $this->orders[$id];}
 public function activate(int $id): void {$this->orders[$id]['status']='active';}
 public function call(int $client,int $order,string $method): array {return ['ready'=>true,'phase'=>$this->phases[$order]??'ready','status'=>'running','public_ip'=>'198.51.100.3','ssh_port'=>22,'user'=>'vpsadmin','ssh'=>'ssh vpsadmin@198.51.100.3','vmid'=>1100,'network_mode'=>'public_ipv4','lease_id'=>$this->config['lease_id'],'lease_generation'=>1];}
}
$directory=sys_get_temp_dir().'/public-portal-'.bin2hex(random_bytes(8));
$f=new PublicFoss();$b=new PortalBridge($f,$directory);
$r=['account'=>'11111111-1111-4111-8111-111111111111','reference'=>'22222222-2222-4222-8222-222222222222','plan'=>'mini','network_mode'=>'public_ipv4'];
$lease=$b->handle($r+['action'=>'network_reserve']);check($lease['address']==='198.51.100.3');
try{$b->handle($r+['action'=>'create']);throw new RuntimeException('Missing lease was accepted');}catch(InvalidArgumentException $expected){}
$db=new PDO('sqlite:'.$directory.'/portal.sqlite');
// Interrupt a split reservation after INSERT, before a later network UPDATE.
// RAISE(FAIL) preserves that inserted row, like a process exiting between commits.
$db->exec("CREATE TRIGGER reservation_crash AFTER INSERT ON orders WHEN NEW.network_mode='nat' BEGIN SELECT RAISE(FAIL,'injected reservation crash'); END");
try{$b->handle($r+['action'=>'create','lease_id'=>$lease['id']]);}catch(PDOException $crash){check(str_contains($crash->getMessage(),'injected reservation crash'));}
$result=$b->handle($r+['action'=>'create','lease_id'=>$lease['id']]);check($result['network_mode']==='public_ipv4'&&$result['ssh_port']===22);
check($f->config['account']===$r['account']&&$f->config['reference']===$r['reference']);
check($b->handle($r+['action'=>'create','lease_id'=>$lease['id']])===$result);
try{$b->handle(array_merge($r,['action'=>'create','network_mode'=>'nat']));throw new RuntimeException('Changed network was accepted');}catch(DomainException $expected){}
$f->phases[1]='deleted';
$replacement=array_merge($r,['action'=>'create','reference'=>'44444444-4444-4444-8444-444444444444','lease_id'=>'55555555-5555-4555-8555-555555555555']);
$next=$b->handle($replacement);check($next['order_id']===2&&$next['lease_id']===$replacement['lease_id']);
check($b->handle($replacement)===$next);
check($db->query('SELECT network_mode FROM retired_orders')->fetchColumn()==='public_ipv4');
echo "PASS: atomic public portal lease contract, replacement, immutable network and identity\n";
