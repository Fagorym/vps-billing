<?php
declare(strict_types=1);
require '/opt/pilot/PortalBridge.php';
function check(bool $ok): void {if(!$ok)throw new RuntimeException('Public portal assertion failed');}
final class PublicFoss {
 public array $config=[];public array $orders=[];public array $phases=[];public array $networkCalls=[];
 public function network(array $r): array {$this->networkCalls[]=$r;return ['id'=>'33333333-3333-4333-8333-333333333333','state'=>'held','address'=>'198.51.100.3'];}
 public function client(string $account): int {return 2;}
 public function order(int $client,string $ref,string $plan,array $network=[]): int {$this->config=$network;$id=count($this->orders)+1;$this->orders[$id]=['client_id'=>2,'status'=>'pending_setup'];return $id;}
 public function get(int $id): array {return $this->orders[$id];}
 public function activate(int $id): void {$this->orders[$id]['status']='active';}
 public function call(int $client,int $order,string $method): array {return ['ready'=>true,'phase'=>$this->phases[$order]??'ready','status'=>'running','public_ip'=>'198.51.100.3','ssh_port'=>22,'user'=>'vpsadmin','ssh'=>'ssh vpsadmin@198.51.100.3','vmid'=>1100,'network_mode'=>'public_ipv4','lease_id'=>$this->config['lease_id'],'lease_generation'=>1];}
}
$directory=sys_get_temp_dir().'/public-portal-'.bin2hex(random_bytes(8));
$f=new PublicFoss();$b=new PortalBridge($f,$directory);
$r=['account'=>'11111111-1111-4111-8111-111111111111','reference'=>'22222222-2222-4222-8222-222222222222','plan'=>'mini','disk_gb'=>25,'network_mode'=>'public_ipv4','os'=>'Debian 13'];
$lease=$b->handle($r+['action'=>'network_reserve']);check($lease['address']==='198.51.100.3');
check($f->networkCalls===[['action'=>'network_reserve','account'=>$r['account'],'reference'=>$r['reference'],'os'=>'Debian 13']]);
try{$b->handle(array_merge($r,['action'=>'network_reserve','os'=>'Debian 12']));throw new RuntimeException('Unknown OS reserved a lease');}catch(InvalidArgumentException $expected){}
check(count($f->networkCalls)===1);
try{$b->handle($r+['action'=>'create']);throw new RuntimeException('Missing lease was accepted');}catch(InvalidArgumentException $expected){}
$db=new PDO('sqlite:'.$directory.'/portal.sqlite');
// Interrupt a split reservation after INSERT, before a later network UPDATE.
// RAISE(FAIL) preserves that inserted row, like a process exiting between commits.
$db->exec("CREATE TRIGGER reservation_crash AFTER INSERT ON orders WHEN NEW.network_mode='nat' BEGIN SELECT RAISE(FAIL,'injected reservation crash'); END");
try{$b->handle($r+['action'=>'create','lease_id'=>$lease['id']]);}catch(PDOException $crash){check(str_contains($crash->getMessage(),'injected reservation crash'));}
$result=$b->handle($r+['action'=>'create','lease_id'=>$lease['id']]);check($result['network_mode']==='public_ipv4'&&$result['ssh_port']===22);
check($f->config===['disk_gb'=>25,'network_mode'=>'public_ipv4','lease_id'=>$lease['id'],'account'=>$r['account'],'reference'=>$r['reference'],'os'=>'Debian 13']);
try{$b->handle(array_merge($r,['action'=>'create','lease_id'=>$lease['id'],'os'=>'Ubuntu 24.04']));throw new RuntimeException('Changed OS was accepted');}catch(DomainException $expected){}
try{$b->handle(array_merge($r,['action'=>'create','lease_id'=>$lease['id'],'disk_gb'=>30]));throw new RuntimeException('Changed SSD was accepted');}catch(DomainException $expected){}
try{$b->handle(array_merge($r,['action'=>'create','lease_id'=>$lease['id'],'disk_gb'=>21]));throw new RuntimeException('Invalid SSD was accepted');}catch(InvalidArgumentException $expected){}
check($b->handle($r+['action'=>'create','lease_id'=>$lease['id']])===$result);
try{$b->handle(array_merge($r,['action'=>'create','network_mode'=>'nat']));throw new RuntimeException('Changed network was accepted');}catch(DomainException $expected){}
$f->phases[1]='deleted';
$replacement=array_merge($r,['action'=>'create','reference'=>'44444444-4444-4444-8444-444444444444','lease_id'=>'55555555-5555-4555-8555-555555555555']);
$next=$b->handle($replacement);check($next['order_id']===2&&$next['lease_id']===$replacement['lease_id']);
check($b->handle($replacement)===$next);
check($db->query("SELECT network_mode FROM orders WHERE reference='".$r['reference']."'")->fetchColumn()==='public_ipv4');
echo "PASS: atomic public portal OS/lease contract, replacement, immutable network and identity\n";
