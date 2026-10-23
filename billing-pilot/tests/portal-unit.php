<?php
declare(strict_types=1);
require '/opt/pilot/PortalBridge.php';
function assertPortal(bool $condition): void { if (!$condition) { throw new RuntimeException('Portal assertion failed'); } }
final class FakeFoss {
 public int $clients=0; public int $orders=0; public int $activations=0; public bool $lose=true; public bool $ready=true;
 public array $calls=[];
 public array $configs=[];
 public array $metricCalls=[];
 public function metrics(int $client,int $order,string $timeframe): array {
  assertPortal($this->records[$order]['client_id']===$client);
  $this->metricCalls[]=[$client,$order,$timeframe];
  return ['timeframe'=>$timeframe,'start'=>1,'end'=>86401,'points'=>[]];
 }
 public string $power='running';public array $ownerCalls=[];
 public array $phases=[];
 private array $clientIds=[]; private array $orderIds=[]; private array $records=[];
 public function client(string $account): int { return $this->clientIds[$account] ??= ++$this->clients; }
 public function order(int $client,string $reference,string $plan,array $config=[]): int {
  $id=$this->orderIds[$reference] ??= ++$this->orders;
  $this->configs[$id]=$config;
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
 try {(new PortalBridge($f,$argv[2]))->handle(['action'=>$argv[3],'account'=>'11111111-1111-4111-8111-111111111111','reference'=>'22222222-2222-4222-8222-222222222222','timeframe'=>'day']);echo 'OK';}
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
$other=$r;$other['reference']='33333333-3333-4333-8333-333333333333';$second=$bridge->handle($other);assertPortal($second['order_id']===2&&$foss->clients===1);assertPortal($bridge->handle($other)===$second);
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
$foss->phases[1]='blocked';$replacement=$bridge->handle($next);assertPortal($replacement['order_id']===3);
$r['action']='start';denied(fn()=>$bridge->handle($r),DomainException::class);
$foss->phases[1]='deleted';$r['action']='status';assertPortal($bridge->handle($r)['phase']==='deleted');
$r['action']='create';assertPortal($bridge->handle($r)['phase']==='deleted'&&$foss->orders===3);
$r['action']='start';denied(fn()=>$bridge->handle($r),DomainException::class);
$foss->deleteNative(3);$next['action']='status';assertPortal($bridge->handle($next)['phase']==='cancelled');
$next['action']='start';denied(fn()=>$bridge->handle($next),DomainException::class);
$next['action']='create';$next['reference']='66666666-6666-4666-8666-666666666666';assertPortal($bridge->handle($next)['order_id']===4);
// Upgrade an existing single-account schema without changing current or retired bindings.
$legacyDir=sys_get_temp_dir().'/portal-migration-'.bin2hex(random_bytes(6));mkdir($legacyDir,0700,true);
$legacy=new PDO('sqlite:'.$legacyDir.'/portal.sqlite');$legacy->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
$legacy->exec('CREATE TABLE client(account TEXT PRIMARY KEY,client_id INTEGER NOT NULL UNIQUE)');
$legacy->exec("CREATE TABLE orders(reference TEXT PRIMARY KEY,account TEXT NOT NULL UNIQUE,plan TEXT NOT NULL,order_id INTEGER UNIQUE,network_mode TEXT NOT NULL DEFAULT 'nat',lease_id TEXT,disk_gb INTEGER)");
$legacy->exec("CREATE TABLE retired_orders(reference TEXT PRIMARY KEY,account TEXT NOT NULL,plan TEXT NOT NULL,order_id INTEGER UNIQUE,network_mode TEXT NOT NULL DEFAULT 'nat',lease_id TEXT,disk_gb INTEGER)");
$account='11111111-1111-4111-8111-111111111111';$reference='22222222-2222-4222-8222-222222222222';
$legacy->exec("INSERT INTO client VALUES('$account',1)");$legacy->exec("INSERT INTO orders VALUES('$reference','$account','mini',1,'nat',NULL,NULL)");
$legacy->exec("INSERT INTO retired_orders VALUES('33333333-3333-4333-8333-333333333333','$account','mini',99,'nat',NULL,20)");
$before=$legacy->query('SELECT * FROM orders')->fetchAll(PDO::FETCH_ASSOC);$retired=$legacy->query('SELECT * FROM retired_orders')->fetchAll(PDO::FETCH_ASSOC);
$migratedFoss=new FakeFoss();$migratedFoss->lose=false;$client=$migratedFoss->client($account);$native=$migratedFoss->order($client,$reference,'mini');$migratedFoss->activate($native);
$migrated=new PortalBridge($migratedFoss,$legacyDir);$migrated=new PortalBridge($migratedFoss,$legacyDir);
assertPortal($legacy->query('SELECT reference,account,plan,order_id,network_mode,lease_id,disk_gb FROM orders')->fetchAll(PDO::FETCH_ASSOC)===$before);
assertPortal($legacy->query('SELECT reference,account,plan,order_id,network_mode,lease_id,disk_gb FROM retired_orders')->fetchAll(PDO::FETCH_ASSOC)===$retired);
assertPortal($legacy->query('SELECT os FROM orders')->fetchColumn()==='Ubuntu 24.04');
assertPortal($legacy->query('SELECT os FROM retired_orders')->fetchColumn()==='Ubuntu 24.04');
$existing=['account'=>$account,'reference'=>$reference,'action'=>'create','plan'=>'mini'];assertPortal($migrated->handle($existing)['order_id']===1);
$new=$existing;$new['reference']='44444444-4444-4444-8444-444444444444';assertPortal($migrated->handle($new)['order_id']===2);
assertPortal($migrated->handle($existing)['order_id']===1&&$migratedFoss->clients===1&&$migratedFoss->orders===2);
assertPortal($migrated->handle($existing+['os'=>'Ubuntu 24.04'])['order_id']===1);
denied(fn()=>$migrated->handle($existing+['os'=>'Debian 13']),DomainException::class);
// OS is frozen in the durable reservation even if the native order reply is lost.
$osDir=sys_get_temp_dir().'/portal-os-'.bin2hex(random_bytes(6));$osFoss=new FakeFoss();$osBridge=new PortalBridge($osFoss,$osDir);
$osRequest=['action'=>'create','account'=>$account,'reference'=>$reference,'plan'=>'mini','os'=>'Debian 13'];
denied(fn()=>$osBridge->handle($osRequest),RuntimeException::class);
denied(fn()=>$osBridge->handle(array_merge($osRequest,['os'=>'Ubuntu 24.04'])),DomainException::class);
assertPortal($osFoss->orders===1&&$osFoss->activations===0);
$created=$osBridge->handle($osRequest);assertPortal($created===$osBridge->handle($osRequest));
assertPortal($osFoss->configs[1]===['disk_gb'=>20,'network_mode'=>'nat','lease_id'=>null,'account'=>$account,'reference'=>$reference,'os'=>'Debian 13']);
foreach(['Ubuntu 24.04','Ubuntu 22.04','Ubuntu 26.04','Debian 13'] as $index=>$os){
 $reference=sprintf('77777777-7777-4777-8777-%012d',$index);
 $request=array_merge($osRequest,['reference'=>$reference,'os'=>$os]);$created=$osBridge->handle($request);
 assertPortal($osFoss->configs[$created['order_id']]['os']===$os&&$created===$osBridge->handle($request));
}
$orders=$osFoss->orders;$activations=$osFoss->activations;
foreach(['Ubuntu 20.04','',13,[]] as $os)denied(fn()=>$osBridge->handle(array_merge($osRequest,['os'=>$os])),InvalidArgumentException::class);
denied(fn()=>$osBridge->handle(array_diff_key($osRequest,['os'=>true])),DomainException::class);
$osDb=new PDO('sqlite:'.$osDir.'/portal.sqlite');
$osDb->exec("INSERT INTO retired_orders SELECT * FROM orders WHERE os='Debian 13'");
$osDb->exec("DELETE FROM orders WHERE os='Debian 13'");
denied(fn()=>$osBridge->handle(array_merge($osRequest,['os'=>'Ubuntu 24.04'])),DomainException::class);
assertPortal($osBridge->handle($osRequest)['order_id']===1);
assertPortal($osFoss->orders===$orders&&$osFoss->activations===$activations);
$metricsRequest=['action'=>'metrics','account'=>$account,'reference'=>'77777777-7777-4777-8777-000000000000','timeframe'=>'day'];
assertPortal($osBridge->handle($metricsRequest)===['timeframe'=>'day','start'=>1,'end'=>86401,'points'=>[]]);
$before=count($osFoss->metricCalls);
denied(fn()=>$osBridge->handle(array_merge($metricsRequest,['account'=>'88888888-8888-4888-8888-888888888888'])),OutOfBoundsException::class);
foreach(['year',null,[],1] as $period)denied(fn()=>$osBridge->handle(array_merge($metricsRequest,['timeframe'=>$period])),InvalidArgumentException::class);
assertPortal(count($osFoss->metricCalls)===$before&&$osFoss->orders===$orders&&$osFoss->activations===$activations);
assertPortal(readWhileLocked($dir,LOCK_SH,'metrics')==='OK');
assertPortal(readWhileLocked($dir,LOCK_EX,'metrics')==='BUSY');
echo "PASS: portal durable recovery, immutable OS and identity, legacy migration, multiple VPS, ownership, password isolation, metrics isolation\n";
