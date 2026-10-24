<?php
declare(strict_types=1);
require '/opt/pilot/AdminBridge.php';
function diskCheck(bool $ok):void{if(!$ok)throw new RuntimeException('Infrastructure disk contract failed');}
function diskDenied(callable $call,string $type):void{try{$call();throw new LogicException('Expected refusal');}catch(Throwable $error){diskCheck($error instanceof $type);}}
$owner='9ac2de9e-e907-42f1-b28d-e65a2c1552a8';
$result=['vmid'=>101,'node'=>'pve1','account'=>$owner,'mountpoint'=>'/','usedBytes'=>1024,'totalBytes'=>4096,'observedAt'=>'2026-10-24T00:00:00+00:00'];
$engine=new class($owner,$result){
    public array $calls=[];
    public function __construct(private string $owner,private array $result){}
    public function monitoring():array{throw new LogicException('Full monitor is forbidden');}
    public function infrastructureDisk(string $account,int $vmid,string $node):array{
        $this->calls[]=[$account,$vmid,$node];
        if($account!==$this->owner||$vmid!==101||$node!=='pve1')throw new DomainException('Not owned');
        return $this->result;
    }
};
$directory=sys_get_temp_dir().'/infra-disk-'.bin2hex(random_bytes(6));
$bridge=new AdminBridge(new stdClass(),$engine,$directory);$before=hash_file('sha256',$directory.'/portal.sqlite');
$request=['action'=>'infrastructure_disk','actor'=>['account'=>$owner,'email'=>'owner@example.test'],'vmid'=>101,'node'=>'pve1'];
diskCheck($bridge->handle($request)===$result);
$spoof=$request;$spoof['account']='11111111-1111-4111-8111-111111111111';$spoof['order_id']=12;$spoof['client_id']=16;
diskCheck($bridge->handle($spoof)===$result);
diskCheck($engine->calls===array_fill(0,2,[$owner,101,'pve1']));
$count=count($engine->calls);
foreach([['vmid'=>true],['vmid'=>'101'],['vmid'=>0],['vmid'=>2147483647],['node'=>''],['node'=>['pve1']],['node'=>'pve1/other'],['actor'=>null]] as $invalid){
    diskDenied(fn()=>$bridge->handle(array_replace($request,$invalid)),InvalidArgumentException::class);
}
diskCheck(count($engine->calls)===$count);
$other=$request;$other['actor']['account']='11111111-1111-4111-8111-111111111111';diskDenied(fn()=>$bridge->handle($other),DomainException::class);
diskDenied(fn()=>$bridge->handle(array_replace($request,['vmid'=>1100])),DomainException::class);
diskDenied(fn()=>$bridge->handle(array_replace($request,['node'=>'other'])),DomainException::class);
diskCheck(hash_file('sha256',$directory.'/portal.sqlite')===$before);
$log=sys_get_temp_dir().'/infra-disk-transport-'.bin2hex(random_bytes(6));putenv('SAFEHOST_INFRA_METRICS_LOG='.$log);
$gateway=new EngineGateway();diskCheck($gateway->infrastructureDisk($owner,101,'pve1')===$result);
diskCheck(json_decode(file_get_contents($log),true,512,JSON_THROW_ON_ERROR)===['action'=>'infrastructure_disk','account'=>$owner,'vmid'=>101,'node'=>'pve1']);
diskCheck((int)ini_get('max_execution_time')===25);
echo "PASS: actor-only disk, strict target, no monitor/DB writes, exact gateway payload and bounded transport\n";
