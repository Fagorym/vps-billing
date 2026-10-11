<?php
declare(strict_types=1);
require '/opt/pilot/PortalBridge.php';
function assertPortal(bool $condition): void { if (!$condition) { throw new RuntimeException('Portal assertion failed'); } }
final class FakeFoss {
 public int $clients=0; public int $orders=0; public int $activations=0; public bool $lose=true; public bool $ready=true;
 private array $clientIds=[]; private array $orderIds=[]; private array $records=[];
 public function client(string $account): int { return $this->clientIds[$account] ??= ++$this->clients; }
 public function order(int $client,string $reference,string $plan): int {
  $id=$this->orderIds[$reference] ??= ++$this->orders;
  $this->records[$id] ??= ['client_id'=>$client,'status'=>'pending_setup'];
  if($this->lose){$this->lose=false;throw new RuntimeException('Lost order response');}return $id;
 }
 public function get(int $id): array{return $this->records[$id];}
 public function activate(int $id): void {$this->activations++;$this->records[$id]['status']='active';}
 public function suspend(int $id): void {$this->records[$id]['status']='suspended';}
 public function unsuspend(int $id): void {$this->records[$id]['status']='active';}
 public function call(int $client,int $order,string $method): array {
  assertPortal($this->records[$order]['client_id']===$client);
  if($method==='initial_password')return ['user'=>'vpsadmin','password'=>'initial-secret'];
  return ['ready'=>$this->ready,'status'=>'running','public_ip'=>'80.249.131.4','ssh_port'=>22222,'user'=>'vpsadmin','ssh'=>'ssh','vmid'=>1102];
 }
}
function denied(callable $call,string $class): void {try{$call();throw new RuntimeException('Expected refusal');}catch(Throwable $e){assertPortal($e instanceof $class);}}
$dir=sys_get_temp_dir().'/portal-'.bin2hex(random_bytes(6));$foss=new FakeFoss();$bridge=new PortalBridge($foss,$dir);
$r=['action'=>'create','account'=>'11111111-1111-4111-8111-111111111111','reference'=>'22222222-2222-4222-8222-222222222222','plan'=>'mini'];
denied(fn()=>$bridge->handle($r),RuntimeException::class);
$bridge=new PortalBridge($foss,$dir);$first=$bridge->handle($r);assertPortal($first===$bridge->handle($r));
assertPortal($foss->clients===1&&$foss->orders===1&&$foss->activations===1);
$other=$r;$other['reference']='33333333-3333-4333-8333-333333333333';denied(fn()=>$bridge->handle($other),DomainException::class);
$other=$r;$other['account']='44444444-4444-4444-8444-444444444444';$other['action']='password';denied(fn()=>$bridge->handle($other),OutOfBoundsException::class);
$other=$r;$other['plan']='medium';denied(fn()=>$bridge->handle($other),DomainException::class);
assertPortal(!isset($first['password']));$r['action']='password';assertPortal($bridge->handle($r)['password']==='initial-secret');
$foss->ready=false;denied(fn()=>$bridge->handle($r),DomainException::class);
echo "PASS: portal durable recovery, immutable identity, quota, ownership, readiness, password isolation\n";
