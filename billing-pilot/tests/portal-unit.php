<?php
declare(strict_types=1);
require '/opt/pilot/PortalBridge.php';
function assertPortal(bool $condition): void { if (!$condition) { throw new RuntimeException('Portal assertion failed'); } }
final class FakeFoss {
 public int $clients=0; public int $orders=0; public int $activations=0; public bool $lose=true; public bool $ready=true;
 public array $calls=[];
 public string $power='running';public array $ownerCalls=[];
 public array $phases=[];
 private array $clientIds=[]; private array $orderIds=[]; private array $records=[];
 public function client(string $account): int { return $this->clientIds[$account] ??= ++$this->clients; }
 public function order(int $client,string $reference,string $plan): int {
  $id=$this->orderIds[$reference] ??= ++$this->orders;
  $this->records[$id] ??= ['client_id'=>$client,'status'=>'pending_setup'];
  if($this->lose){$this->lose=false;throw new RuntimeException('Lost order response');}return $id;
 }
 public function get(int $id): array{if(!isset($this->records[$id]))throw new OutOfBoundsException('Missing native order');return $this->records[$id];}
 public function deleteNative(int $id): void {unset($this->records[$id]);$this->phases[$id]='cancelled';}
 public function boundStatus(int $client,int $order): array {return ['ready'=>false,'phase'=>$this->phases[$order]??'cancelled','reason'=>'Retained order','status'=>'stopped','public_ip'=>'80.249.131.4','ssh_port'=>22222,'user'=>'vpsadmin','ssh'=>'ssh','vmid'=>1102];}
 public function activate(int $id): void {$this->activations++;$this->records[$id]['status']='active';}
 public function suspend(int $id): void {$this->records[$id]['status']='suspended';}
 public function unsuspend(int $id): void {$this->records[$id]['status']='active';}
 public function ownerPower(int $client,int $order,bool $start): array {assertPortal($this->records[$order]['client_id']===$client);if($this->records[$order]['status']!=='active')throw new DomainException('Owner cannot unblock');$this->ownerCalls[]=$start;$this->power=$start?'running':'stopped';return [];}
 public function call(int $client,int $order,string $method): array {
  assertPortal($this->records[$order]['client_id']===$client);
  $this->calls[]=$method;
  if($method==='initial_password'&&!$this->ready)throw new DomainException('SSH not ready');
  if($method==='initial_password')return ['user'=>'vpsadmin','password'=>'initial-secret'];
  return ['ready'=>$this->ready&&$this->power==='running','phase'=>$this->phases[$order]??($this->power==='running'?'ready':'stopped'),'status'=>$this->power,'public_ip'=>'80.249.131.4','ssh_port'=>22222,'user'=>'vpsadmin','ssh'=>'ssh','vmid'=>1102];
 }
}
function denied(callable $call,string $class): void {try{$call();throw new RuntimeException('Expected refusal');}catch(Throwable $e){assertPortal($e instanceof $class);}}
if (($argv[1] ?? '') === 'read-child') {
 $f=new FakeFoss();$f->lose=false;$id=$f->client('11111111-1111-4111-8111-111111111111');$order=$f->order($id,'22222222-2222-4222-8222-222222222222','mini');$f->activate($order);
 try {(new PortalBridge($f,$argv[2]))->handle(['action'=>$argv[3],'account'=>'11111111-1111-4111-8111-111111111111','reference'=>'22222222-2222-4222-8222-222222222222']);echo 'OK';}
 catch(RuntimeException $e){echo 'BUSY';}catch(Throwable $e){echo 'ERROR';}
 exit;
}
function readWhileLocked(string $dir, int $mode, string $action): string {
 $held=fopen($dir.'/operation.lock','c');flock($held,$mode);
 $p=proc_open([PHP_BINARY,__FILE__,'read-child',$dir,$action],[['pipe','r'],['pipe','w'],['pipe','w']],$pipes);fclose($pipes[0]);
 $until=microtime(true)+1;
 do {$status=proc_get_status($p);if(!$status['running'])break;usleep(10000);}while(microtime(true)<$until);
 $finished=!$status['running'];if(!$finished)proc_terminate($p);
 flock($held,LOCK_UN);fclose($held);
 $output=stream_get_contents($pipes[1]);fclose($pipes[1]);fclose($pipes[2]);proc_close($p);
 assertPortal($finished);return $output;
}
$dir=sys_get_temp_dir().'/portal-'.bin2hex(random_bytes(6));$foss=new FakeFoss();$bridge=new PortalBridge($foss,$dir);
$r=['action'=>'create','account'=>'11111111-1111-4111-8111-111111111111','reference'=>'22222222-2222-4222-8222-222222222222','plan'=>'mini'];
denied(fn()=>$bridge->handle($r),RuntimeException::class);
$bridge=new PortalBridge($foss,$dir);$first=$bridge->handle($r);assertPortal($first===$bridge->handle($r));
assertPortal($foss->clients===1&&$foss->orders===1&&$foss->activations===1);
$other=$r;$other['reference']='33333333-3333-4333-8333-333333333333';denied(fn()=>$bridge->handle($other),DomainException::class);
$other=$r;$other['account']='44444444-4444-4444-8444-444444444444';$other['action']='password';denied(fn()=>$bridge->handle($other),OutOfBoundsException::class);
$other=$r;$other['plan']='medium';denied(fn()=>$bridge->handle($other),DomainException::class);
assertPortal(!isset($first['password']));$r['action']='password';$foss->calls=[];assertPortal($bridge->handle($r)['password']==='initial-secret');assertPortal($foss->calls===['initial_password']);
assertPortal(readWhileLocked($dir,LOCK_SH,'password')==='OK');
assertPortal(readWhileLocked($dir,LOCK_EX,'password')==='BUSY');
$foss->ready=false;denied(fn()=>$bridge->handle($r),DomainException::class);
$r['action']='stop';assertPortal($bridge->handle($r)['phase']==='suspended');assertPortal($foss->get(1)['status']==='active');
$r['action']='start';assertPortal($bridge->handle($r)['phase']==='preparing');assertPortal($foss->ownerCalls===[false,true]);
$foss->suspend(1);denied(fn()=>$bridge->handle($r),DomainException::class);
$next=$r;$next['action']='create';$next['reference']='55555555-5555-4555-8555-555555555555';
foreach(['blocked','archived','missing','cancelled'] as $phase){$foss->phases[1]=$phase;denied(fn()=>$bridge->handle($next),DomainException::class);}
$foss->phases[1]='deleted';$replacement=$bridge->handle($next);assertPortal($replacement['order_id']===2);
$r['action']='status';assertPortal($bridge->handle($r)['phase']==='deleted');
$r['action']='create';assertPortal($bridge->handle($r)['phase']==='deleted'&&$foss->orders===2);
$r['action']='start';denied(fn()=>$bridge->handle($r),DomainException::class);
$foss->deleteNative(2);$next['action']='status';assertPortal($bridge->handle($next)['phase']==='cancelled');
$next['action']='start';denied(fn()=>$bridge->handle($next),DomainException::class);
$next['action']='create';$next['reference']='66666666-6666-4666-8666-666666666666';denied(fn()=>$bridge->handle($next),DomainException::class);
echo "PASS: portal durable recovery, immutable identity, quota, ownership, readiness, password isolation\n";
