<?php
declare(strict_types=1);
if (!is_file('/opt/pilot/AdminBridge.php')) { throw new RuntimeException('Admin bridge is not implemented'); }
require '/opt/pilot/AdminBridge.php';
function adminCheck(bool $ok): void { if (!$ok) { throw new RuntimeException('Admin contract assertion failed'); } }
function adminDenied(callable $call, string $type): void { try { $call(); throw new RuntimeException('Expected denial'); } catch(Throwable $e) { adminCheck($e instanceof $type); } }
final class AdminFakeFoss {
 public array $clients=[]; public array $orders=[]; public array $calls=[];
 public function client(string $account): int { foreach($this->clients as $c)if($c['last_name']===$account)return $c['id'];$id=count($this->clients)+1;$this->clients[$id]=['id'=>$id,'first_name'=>'Portal','last_name'=>$account,'email'=>'portal-'.$account.'@safe-host.ru','billing_email'=>null,'created_at'=>'2026-10-11 00:00:00','balance'=>'1.25','currency'=>'RUB','api_token'=>'NEVER-RETURN'];return $id; }
 public function sync(int $id,array $p): void {$this->clients[$id]=array_merge($this->clients[$id],['first_name'=>$p['name'],'created_at'=>gmdate('Y-m-d H:i:s',strtotime($p['registeredAt']))]);if($p['email']!==null)$this->clients[$id]['billing_email']=$p['email'];}
 public function clients(): array {return array_values($this->clients);}
 public function orders(): array {return array_values($this->orders);}
 public function managedOrder(int $id): array {if(!isset($this->orders[$id]))throw new OutOfBoundsException();return $this->orders[$id];}
 public function effect(array $order,string $command,array $r,object $engine): void {$this->calls[]=$command;$engine->action($order,$command,$r);}
}
final class AdminFakeEngine {
 public array $calls=[];public bool $lose=true;public string $phase='ready';
 public function action(array $o,string $cmd,array $r): array {$this->calls[]=$r['operationId'];$this->phase=$cmd==='archive'?'archived':($cmd==='purge'?'deleted':($cmd==='block'?'blocked':'ready'));if($this->lose){$this->lose=false;throw new RuntimeException('secret-RAW-EXCEPTION');}return [];}
 public function monitoring(): array {return ['hosts'=>[['node'=>'pve1','cpuFraction'=>0.2,'cpuCores'=>8,'memoryUsedBytes'=>100,'memoryTotalBytes'=>1000,'memoryReservedBytes'=>500,'vcpuReserved'=>2,'storageUsedBytes'=>100,'storageTotalBytes'=>1000,'storageFreeBytes'=>900,'slotsFree'=>9]],'servers'=>[['orderId'=>4,'clientId'=>1,'node'=>'pve1','phase'=>$this->phase,'status'=>'running','plan'=>'mini','vmid'=>1100,'public_ip'=>'80.249.131.4','ssh_port'=>22220,'reason'=>null,'cores'=>1,'memoryMb'=>1024,'diskGb'=>20,'createdAt'=>'2026-10-13T10:00:00+00:00','metrics'=>['cpuFraction'=>0.125,'memoryUsedBytes'=>100,'memoryTotalBytes'=>1024,'guestDiskUsedBytes'=>null,'guestDiskTotalBytes'=>null],'password'=>'NEVER-RETURN']]];}
}
$dir=sys_get_temp_dir().'/admin-'.bin2hex(random_bytes(8));$foss=new AdminFakeFoss();$engine=new AdminFakeEngine();$bridge=new AdminBridge($foss,$engine,$dir);
$actor=['account'=>'11111111-1111-4111-8111-111111111111','email'=>'operator@example.test'];
$profiles=[['account'=>'22222222-2222-4222-8222-222222222222','name'=>'Real User','email'=>'real@example.test','registeredAt'=>'2026-10-13T08:00:00Z'],['account'=>'33333333-3333-4333-8333-333333333333','name'=>'No VM Yet','email'=>'new@example.test','registeredAt'=>'2026-10-12T08:00:00Z']];
$bridge->handle(['action'=>'sync_clients','actor'=>$actor,'clients'=>$profiles]);$bridge->handle(['action'=>'sync_clients','actor'=>$actor,'clients'=>$profiles]);adminCheck(count($foss->clients)===2);
$unknown=['account'=>'66666666-6666-4666-8666-666666666666','name'=>'Legacy Unknown Contact','email'=>null,'registeredAt'=>'2001-01-01T00:00:00Z'];
$bridge->handle(['action'=>'sync_clients','actor'=>$actor,'clients'=>[$unknown]]);
$keepKnown=$profiles[0];$keepKnown['email']=null;$bridge->handle(['action'=>'sync_clients','actor'=>$actor,'clients'=>[$keepKnown]]);
adminCheck($foss->clients[1]['email']==='portal-'.$profiles[0]['account'].'@safe-host.ru');adminCheck($foss->clients[1]['last_name']===$profiles[0]['account']);
$foss->orders[4]=['id'=>4,'client_id'=>1,'title'=>'User VPS','plan'=>'mini','created_at'=>'2026-10-13 09:00:00'];
$dashboard=$bridge->handle(['action'=>'dashboard','actor'=>$actor,'dayStart'=>'2026-10-13T00:00:00Z','dayEnd'=>'2026-10-14T00:00:00Z']);
adminCheck($dashboard['source']==='FOSSBilling'&&$dashboard['stats']['clientsTotal']===3&&$dashboard['stats']['clientsToday']===1);
adminCheck($dashboard['clients'][2]['email']===''&&$foss->clients[1]['billing_email']==='real@example.test');
$invalidContact=$unknown;$invalidContact['email']='';adminDenied(fn()=>$bridge->handle(['action'=>'sync_clients','actor'=>$actor,'clients'=>[$invalidContact]]),InvalidArgumentException::class);
adminCheck($dashboard['stats']['serversToday']===1&&$dashboard['clients'][0]['balanceMinor']===125&&$dashboard['clients'][0]['email']==='real@example.test');
adminCheck($dashboard['clients'][1]['plans']===[]);adminCheck(!str_contains(json_encode($dashboard),'NEVER-RETURN')&&!str_contains(json_encode($dashboard),'api_token'));
$r=['action'=>'action','actor'=>$actor,'operationId'=>'44444444-4444-4444-8444-444444444444','orderId'=>4,'command'=>'archive','reason'=>'Keep disk indefinitely'];
$queued=$bridge->handle($r);adminCheck($queued['state']==='pending'&&$engine->calls===[]);adminCheck($queued===$bridge->handle($r));
$changed=$r;$changed['reason']='Different reason';adminDenied(fn()=>$bridge->handle($changed),DomainException::class);
adminCheck($bridge->processOne());$bridge=new AdminBridge($foss,$engine,$dir);adminCheck($bridge->processOne(true));
$done=$bridge->handle(['action'=>'operation','actor'=>$actor,'operationId'=>$r['operationId']]);adminCheck($done['state']==='done'&&$done['error']===null);
adminCheck($engine->calls===[$r['operationId'],$r['operationId']]);adminCheck($bridge->handle($r)===$done);
adminCheck(!str_contains(json_encode($bridge->handle(['action'=>'dashboard','actor'=>$actor,'dayStart'=>'2026-10-13T00:00:00Z','dayEnd'=>'2026-10-14T00:00:00Z'])),'secret-RAW'));
$bad=$r;$bad['operationId']='55555555-5555-4555-8555-555555555555';$bad['command']='purge';adminDenied(fn()=>$bridge->handle($bad),InvalidArgumentException::class);
$bad=$r;$bad['actor']['account']='not-uuid';adminDenied(fn()=>$bridge->handle($bad),InvalidArgumentException::class);
$bad=$r;$bad['reason']='x';adminDenied(fn()=>$bridge->handle($bad),InvalidArgumentException::class);
echo "PASS: admin profile sync, native balance, registration stats, whitelist, durable recovery, immutable operation, actor/reason/purge gates\n";
