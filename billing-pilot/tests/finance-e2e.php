<?php
declare(strict_types=1);
$completed=false;register_shutdown_function(static function()use(&$completed):void{if(!$completed)exit(1);});
chdir('/var/www/html');require 'load.php';$di['translate']();require_once '/opt/pilot/AdminBridge.php';require_once '/opt/pilot/PortalBridge.php';
function fcheck(bool $ok,string $why):void{if(!$ok)throw new RuntimeException($why);}
function fid():string{return 'dddddddd-dddd-4ddd-8ddd-'.bin2hex(random_bytes(6));}
function fmock(string $path,?array $body=null):array{
 $ctx=stream_context_create(['http'=>['method'=>$body===null?'GET':'POST','ignore_errors'=>true,'header'=>'Content-Type: application/json','content'=>$body===null?'':json_encode($body)]]);
 return json_decode(file_get_contents('http://127.0.0.1:8091/'.$path,false,$ctx),true,512,JSON_THROW_ON_ERROR);
}
function fpve():array{return json_decode(file_get_contents('http://mock:8090/'),true,512,JSON_THROW_ON_ERROR);}
function fcalls(string $id):array{return array_values(array_filter(fmock('state')['calls'],fn($c)=>$c['request']['operationId']===$id));}
$account=fid();$ref=fid();$portal=new PortalBridge(new FossPortal($di),'/var/www/html/data/portal');
$created=$portal->handle(['action'=>'create','account'=>$account,'reference'=>$ref,'plan'=>'mini']);$orderId=$created['order_id'];$vmid=$created['vmid'];
$actor=['account'=>fid(),'email'=>'operator@example.test'];$admin=new AdminBridge(new FossAdmin($di),new EngineGateway(),'/var/www/html/data/portal');
for($i=0;$i<20&&$admin->processOne(true);$i++){}
function operation(string $command,int $orderId,array $actor,array $extra=[]):array{return ['action'=>'action','operationId'=>fid(),'orderId'=>$orderId,'command'=>$command,'reason'=>'Local finance lifecycle test','actor'=>$actor,...$extra];}
function outcome(AdminBridge $admin,array $request):array{return $admin->handle(['action'=>'operation','operationId'=>$request['operationId'],'actor'=>$request['actor']]);}
$archive=operation('archive',$orderId,$actor);$admin->handle($archive);fmock('control',['denyCommand'=>'archive']);$before=fpve();
$admin->processOne(true);fcheck(outcome($admin,$archive)['state']==='failed'&&fpve()===$before,'Finance denial did not precede engine archive');
fmock('control',[]);$archive=operation('archive',$orderId,$actor);$admin->handle($archive);$admin->processOne(true);
fcheck(outcome($admin,$archive)['state']==='done','Financial archive did not complete');$calls=fcalls($archive['operationId']);
fcheck(count($calls)===2&&$calls[0]['request']['stage']==='prepare'&&$calls[1]['request']['stage']==='complete','Archive callback stages incorrect');
fcheck($calls[0]['pve']['states'][(string)$vmid]==='running'&&$calls[1]['pve']['states'][(string)$vmid]==='stopped','Archive callbacks have wrong effect ordering');
fcheck($calls[0]['request']['account']===$account&&$calls[0]['request']['reference']===$ref&&$calls[1]['request']['effect']===['phase'=>'archived','status'=>'stopped'],'Financial identity/effect tuple incorrect');
$restore=operation('restore',$orderId,$actor);$admin->handle($restore);fmock('control',['completeOnce'=>true]);$admin->processOne(true);
fcheck(outcome($admin,$restore)['state']==='pending'&&fpve()['states'][(string)$vmid]==='running','Lost restore completion did not stay retryable');
$clones=fpve()['clones'];$admin=new AdminBridge(new FossAdmin($di),new EngineGateway(),'/var/www/html/data/portal');$admin->processOne(true);
fcheck(outcome($admin,$restore)['state']==='done'&&fpve()['clones']===$clones,'Restore retry changed VM or failed');
$calls=fcalls($restore['operationId']);fcheck($calls[0]['pve']['states'][(string)$vmid]==='stopped'&&end($calls)['request']['effect']===['phase'=>'ready','status'=>'running'],'Restore resumed finances before physical running');
$wrongPurge=operation('purge',$orderId,$actor,['confirmVmid'=>$vmid+1]);$admin->handle($wrongPurge);$admin->processOne(true);
fcheck(outcome($admin,$wrongPurge)['state']==='failed'&&fcalls($wrongPurge['operationId'])===[],'Wrong typed purge affected native finances');
// Before-delete must deny outside core's forceDelete catch, preserving the order and VM.
$api=$di['api_admin'];fmock('control',['denyCommand'=>'cancel']);$before=fpve();$denied=false;
try{$api->order_delete(['id'=>$orderId,'force_delete'=>true]);}catch(Throwable $e){$denied=true;}
fcheck($denied&&(new FossPortal($di))->get($orderId)['id']===$orderId&&fpve()===$before,'forceDelete bypassed financial denial');
fmock('control',['completeOnce'=>true]);$api->order_delete(['id'=>$orderId,'force_delete'=>true]);
fcheck($portal->handle(['action'=>'status','account'=>$account,'reference'=>$ref])['phase']==='cancelled','Native delete lost owner tombstone');
$admin=new AdminBridge(new FossAdmin($di),new EngineGateway(),'/var/www/html/data/portal');
fcheck($admin->processOne(true),'Worker did not recover native completion after forced order removal');
$native=array_values(array_filter(fmock('state')['calls'],fn($c)=>$c['request']['orderId']===$orderId&&$c['request']['command']==='cancel'));
$ids=array_unique(array_map(fn($c)=>$c['request']['operationId'],$native));fcheck(count($ids)===1,'Native delete retry changed operation identity');
fcheck(end($native)['request']['stage']==='complete'&&end($native)['request']['actor']===['source'=>'FOSSBilling'],'Native delete completion/actor missing');
fcheck(!str_contains(json_encode($admin->handle(['action'=>'dashboard','actor'=>$actor,'dayStart'=>gmdate('Y-m-d').'T00:00:00Z','dayEnd'=>gmdate('Y-m-d',time()+86400).'T00:00:00Z'])),'SECRET-'),'Upstream finance error leaked');
echo "PASS: real FOSS financial HTTP identity, prepare/effect/complete ordering, denied effects, lost completion retry, restore running proof, forceDelete financial guard and stable native IDs\n";
$completed=true;
