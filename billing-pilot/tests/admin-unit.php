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
 public array $calls=[];public bool $lose=true;public string $phase='ready';public array $infrastructure=[];public array $protectedOrders=[];
 public function assertMutable(int $client,int $order): void {if(in_array($order,$this->protectedOrders,true))throw new DomainException('Infrastructure is read-only');}
 public function action(array $o,string $cmd,array $r): array {$this->calls[]=$r['operationId'];$this->phase=$cmd==='archive'?'archived':($cmd==='purge'?'deleted':($cmd==='block'?'blocked':'ready'));if($this->lose){$this->lose=false;throw new RuntimeException('secret-RAW-EXCEPTION');}return [];}
 public function monitoring(): array {return ['infrastructure'=>$this->infrastructure,'hosts'=>[['node'=>'pve1','cpuFraction'=>0.2,'cpuCores'=>8,'memoryUsedBytes'=>100,'memoryTotalBytes'=>1000,'memoryReservedBytes'=>500,'vcpuReserved'=>2,'storageUsedBytes'=>100,'storageTotalBytes'=>1000,'storageFreeBytes'=>900,'slotsFree'=>9]],'servers'=>[['orderId'=>4,'clientId'=>1,'node'=>'pve1','phase'=>$this->phase,'status'=>'running','plan'=>'mini','vmid'=>1100,'public_ip'=>'80.249.131.4','ssh_port'=>22220,'reason'=>null,'cores'=>1,'memoryMb'=>1024,'diskGb'=>20,'createdAt'=>'2026-10-13T10:00:00+00:00','metrics'=>['cpuFraction'=>0.125,'memoryUsedBytes'=>100,'memoryTotalBytes'=>1024,'guestDiskUsedBytes'=>null,'guestDiskTotalBytes'=>null],'password'=>'NEVER-RETURN']]];}
}
if (($argv[1] ?? '') === 'snapshot-child') {
 $bridge=new AdminBridge(new AdminFakeFoss(),new AdminFakeEngine(),$argv[2]);
 echo "READY\n";fflush(STDOUT);
 try {
  $result=$bridge->handle(['action'=>'dashboard','actor'=>['account'=>'11111111-1111-4111-8111-111111111111','email'=>'operator@example.test'],'dayStart'=>'2026-10-13T00:00:00Z','dayEnd'=>'2026-10-14T00:00:00Z']);
  echo $result['source'];
 } catch(RuntimeException $e) {echo $e->getMessage();}
 exit;
}
function snapshotWhileLocked(string $dir,int $mode,?int $releaseAfterMicros,bool $pauseReader=false): array {
 $held=fopen($dir.'/operation.lock','c');flock($held,$mode);
 $process=proc_open([PHP_BINARY,__FILE__,'snapshot-child',$dir],[['pipe','r'],['pipe','w'],['pipe','w']],$pipes);
 fclose($pipes[0]);stream_set_timeout($pipes[1],7);
 try {
  adminCheck(fgets($pipes[1])==="READY\n");$started=microtime(true);
  // Linux SIGSTOP/SIGCONT: emulate a reader descheduled past its deadline.
  if($pauseReader){
   $pid=proc_get_status($process)['pid'];$sleeping=false;
   do {$sleeping=str_contains(trim(file_get_contents('/proc/'.$pid.'/wchan')),'nanosleep');if(!$sleeping)usleep(1000);}while(!$sleeping&&microtime(true)-$started<1);
   adminCheck($sleeping&&proc_terminate($process,19));
  }
  if($releaseAfterMicros!==null){usleep($releaseAfterMicros);flock($held,LOCK_UN);}
  if($pauseReader)adminCheck(proc_terminate($process,18));
  do {$state=proc_get_status($process);if(!$state['running'])break;usleep(10000);}while(microtime(true)-$started<7);
  if($state['running']){proc_terminate($process);throw new RuntimeException('Snapshot lock wait exceeded its deadline');}
  return ['result'=>stream_get_contents($pipes[1]),'seconds'=>microtime(true)-$started];
 } finally {flock($held,LOCK_UN);fclose($held);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);}
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
$infrastructureRow=['vmid'=>101,'node'=>'pve1','account'=>$profiles[0]['account'],'name'=>'safehost billing','os'=>'Ubuntu 24.04','address'=>'10.10.10.11','publicIpv4'=>false,'status'=>'running','phase'=>'ready','cores'=>2,'memoryMb'=>4096,'diskGb'=>40,'observedAt'=>'2026-10-23T00:00:00+00:00'];
$engine->infrastructure=[$infrastructureRow,$infrastructureRow+['password'=>'NEVER-RETURN']];
$engine->infrastructure[1]=array_replace($engine->infrastructure[1],['vmid'=>1100,'account'=>$profiles[1]['account'],'name'=>'safehost site','address'=>'45.9.88.54','publicIpv4'=>true]);
adminCheck($bridge->handle(['action'=>'infrastructure','actor'=>$actor])===['servers'=>[]]);
$ownerActor=['account'=>$profiles[0]['account'],'email'=>'owner@example.test'];
$owned=$bridge->handle(['action'=>'infrastructure','actor'=>$ownerActor]);adminCheck(count($owned['servers'])===1&&$owned['servers'][0]['vmid']===101&&!str_contains(json_encode($owned),'NEVER-RETURN'));
adminCheck($bridge->handle(['action'=>'infrastructure','actor'=>$actor,'account'=>$profiles[0]['account']])===['servers'=>[]]);
adminDenied(fn()=>$bridge->handle(['action'=>'infrastructure','actor'=>['account'=>'bad','email'=>'owner@example.test']]),InvalidArgumentException::class);
$readonlyDashboard=$bridge->handle(['action'=>'dashboard','actor'=>$actor,'dayStart'=>'2026-10-13T00:00:00Z','dayEnd'=>'2026-10-14T00:00:00Z']);
adminCheck(count($readonlyDashboard['servers'])===2&&$readonlyDashboard['servers'][0]['orderId']===4&&$readonlyDashboard['servers'][0]['clientId']===2&&$readonlyDashboard['servers'][0]['account']===$profiles[1]['account']&&$readonlyDashboard['servers'][0]['infrastructure']===true);
adminCheck($readonlyDashboard['servers'][1]['orderId']===0&&$readonlyDashboard['servers'][1]['vmid']===101&&$readonlyDashboard['servers'][1]['infrastructure']===true);
$queueDb=new PDO('sqlite:'.$dir.'/portal.sqlite');$queuedBefore=(int)$queueDb->query('SELECT COUNT(*) FROM admin_operation')->fetchColumn();$engine->protectedOrders=[4];
$protected=$r;$protected['operationId']='77777777-7777-4777-8777-777777777777';adminDenied(fn()=>$bridge->handle($protected),DomainException::class);
adminCheck((int)$queueDb->query('SELECT COUNT(*) FROM admin_operation')->fetchColumn()===$queuedBefore);
$engine->protectedOrders=[];$pending=$r;$pending['operationId']='88888888-8888-4888-8888-888888888888';$bridge->handle($pending);$effectsBefore=$engine->calls;$engine->protectedOrders=[4];
adminCheck($bridge->processOne(true));adminCheck($engine->calls===$effectsBefore&&$bridge->handle(['action'=>'operation','actor'=>$actor,'operationId'=>$pending['operationId']])['state']==='failed');
$engine->protectedOrders=[];$engine->infrastructure=[];
$shared=snapshotWhileLocked($dir,LOCK_SH,null);adminCheck($shared['result']==='FOSSBilling'&&$shared['seconds']<1);
$brief=snapshotWhileLocked($dir,LOCK_EX,200000);
if($brief['result']!=='FOSSBilling')throw new RuntimeException('Snapshot dropped on brief lock contention: '.$brief['result']);
adminCheck($brief['seconds']>=0.15&&$brief['seconds']<2);
$busy=snapshotWhileLocked($dir,LOCK_EX,null);adminCheck($busy['result']==='Bridge busy'&&$busy['seconds']>=4&&$busy['seconds']<6);
$expired=snapshotWhileLocked($dir,LOCK_EX,5100000,pauseReader:true);adminCheck($expired['result']==='Bridge busy'&&$expired['seconds']<6.5);
echo "PASS: admin profile sync, native balance, registration stats, whitelist, durable recovery, immutable operation, actor/reason/purge gates\n";
echo "PASS: concurrent readers, short writer contention, bounded busy deadline\n";
echo "PASS: owner-filtered infrastructure, readonly dashboard attribution, enqueue and recovered-worker protection\n";
