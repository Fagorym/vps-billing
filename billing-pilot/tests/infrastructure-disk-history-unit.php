<?php
declare(strict_types=1);
require '/opt/pilot/AdminBridge.php';
function historyCheck(bool $ok):void{if(!$ok)throw new RuntimeException('Infrastructure disk history contract failed');}
function historyDenied(callable $call,string $type):void{try{$call();throw new LogicException('Expected refusal');}catch(Throwable $error){historyCheck($error instanceof $type);}}
$owner='9ac2de9e-e907-42f1-b28d-e65a2c1552a8';
$result=['vmid'=>101,'node'=>'pve1','account'=>$owner,'mountpoint'=>'/','timeframe'=>'day','start'=>1799913600,'end'=>1800000000,'step'=>60,'points'=>[]];
for($tick=$result['start']+60;$tick<=$result['end'];$tick+=60)$result['points'][]=['timestamp'=>$tick,'usedBytes'=>null,'totalBytes'=>null];
$engine=new class($owner,$result){
    public array $calls=[];
    public function __construct(private string $owner,private array $result){}
    public function monitoring():array{throw new LogicException('Full monitor forbidden');}
    public function infrastructureDiskHistory(string $account,int $vmid,string $node,string $period):array{
        $this->calls[]=['account'=>$account,'vmid'=>$vmid,'node'=>$node,'timeframe'=>$period];
        if($account!==$this->owner||$vmid!==101||$node!=='pve1')throw new DomainException('Not owned');
        return $this->result;
    }
};
$directory=sys_get_temp_dir().'/infra-disk-history-'.bin2hex(random_bytes(6));
$bridge=new AdminBridge(new stdClass(),$engine,$directory);$before=hash_file('sha256',$directory.'/portal.sqlite');
$request=['action'=>'infrastructure_disk_history','actor'=>['account'=>$owner,'email'=>'owner@example.test'],'vmid'=>101,'node'=>'pve1','timeframe'=>'day'];
historyCheck($bridge->handle($request)===$result);
$spoof=$request;$spoof['account']='11111111-1111-4111-8111-111111111111';$spoof['order_id']=12;$spoof['client_id']=16;
historyCheck($bridge->handle($spoof)===$result);
historyCheck($engine->calls===array_fill(0,2,['account'=>$owner,'vmid'=>101,'node'=>'pve1','timeframe'=>'day']));
$count=count($engine->calls);
foreach([['vmid'=>true],['vmid'=>'101'],['vmid'=>0],['vmid'=>2147483647],['node'=>''],['node'=>['pve1']],['node'=>'pve1/other'],['actor'=>null],['timeframe'=>[]],['timeframe'=>'month']] as $invalid){
    historyDenied(fn()=>$bridge->handle(array_replace($request,$invalid)),InvalidArgumentException::class);
}
historyCheck(count($engine->calls)===$count);
$other=$request;$other['actor']['account']='11111111-1111-4111-8111-111111111111';historyDenied(fn()=>$bridge->handle($other),DomainException::class);
historyDenied(fn()=>$bridge->handle(array_replace($request,['vmid'=>1100])),DomainException::class);
historyDenied(fn()=>$bridge->handle(array_replace($request,['node'=>'other'])),DomainException::class);
historyCheck(hash_file('sha256',$directory.'/portal.sqlite')===$before);
$log=sys_get_temp_dir().'/infra-history-transport-'.bin2hex(random_bytes(6));putenv('SAFEHOST_INFRA_METRICS_LOG='.$log);
$gateway=new EngineGateway();$week=$gateway->infrastructureDiskHistory($owner,101,'pve1','week');
historyCheck(count($week['points'])===10080 && $week['step']===60);
historyCheck($week['points'][0]['timestamp']===$week['start']+60 && $week['points'][10079]['timestamp']===$week['end']);
historyCheck(json_decode(file_get_contents($log),true,512,JSON_THROW_ON_ERROR)===['action'=>'infrastructure_disk_history','account'=>$owner,'vmid'=>101,'node'=>'pve1','timeframe'=>'week']);
historyCheck(strlen(json_encode(['ok'=>true,'result'=>$week],JSON_THROW_ON_ERROR))<1048576);
historyCheck((int)ini_get('max_execution_time')===25);
echo "PASS: actor-only disk history, exact bounded payload, readonly bridge,10080 safe-int minute points under1MiB\n";
