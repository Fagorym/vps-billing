<?php
declare(strict_types=1);
require '/opt/pilot/AdminBridge.php';
function infraMetricsCheck(bool $ok):void{if(!$ok)throw new RuntimeException('Infrastructure metrics contract failed');}
function infraMetricsDenied(callable $call,string $type):void{try{$call();throw new LogicException('Expected refusal');}catch(Throwable $error){infraMetricsCheck($error instanceof $type);}}
$owner='9ac2de9e-e907-42f1-b28d-e65a2c1552a8';
$result=['timeframe'=>'day','start'=>100,'end'=>86500,'points'=>[['timestamp'=>160,'cpuPercent'=>25,'memoryUsedBytes'=>1024,'memoryTotalBytes'=>4096,'networkInBytesPerSecond'=>30,'networkOutBytesPerSecond'=>40]]];
$engine=new class($owner,$result){
    public array $calls=[];
    public function __construct(private string $owner,private array $result){}
    public function monitoring():array{throw new LogicException('Full monitor must not be called');}
    public function infrastructureMetrics(string $account,int $vmid,string $node,string $timeframe):array{
        $this->calls[]=[$account,$vmid,$node,$timeframe];
        if($account!==$this->owner||$vmid!==101||$node!=='pve1')throw new DomainException('Not owned');
        return $this->result;
    }
};
$bridge=new AdminBridge(new stdClass(),$engine,sys_get_temp_dir().'/infra-metrics-'.bin2hex(random_bytes(6)));
$request=['action'=>'infrastructure_metrics','actor'=>['account'=>$owner,'email'=>'owner@example.test'],'vmid'=>101,'node'=>'pve1','timeframe'=>'day'];
infraMetricsCheck($bridge->handle($request)===$result);
$spoof=$request;$spoof['account']='11111111-1111-4111-8111-111111111111';infraMetricsCheck($bridge->handle($spoof)===$result);
infraMetricsCheck($engine->calls===array_fill(0,2,[$owner,101,'pve1','day']));
$before=count($engine->calls);
foreach([['vmid'=>true],['vmid'=>'101'],['vmid'=>0],['node'=>''],['node'=>['pve1']],['node'=>'pve1/other'],['timeframe'=>'year'],['timeframe'=>[]],['actor'=>null]] as $invalid){
    infraMetricsDenied(fn()=>$bridge->handle(array_replace($request,$invalid)),InvalidArgumentException::class);
}
infraMetricsCheck(count($engine->calls)===$before);
$other=$request;$other['actor']['account']='11111111-1111-4111-8111-111111111111';infraMetricsDenied(fn()=>$bridge->handle($other),DomainException::class);
infraMetricsDenied(fn()=>$bridge->handle(array_replace($request,['vmid'=>1100])),DomainException::class);
infraMetricsDenied(fn()=>$bridge->handle(array_replace($request,['node'=>'other'])),DomainException::class);
$log=sys_get_temp_dir().'/infra-metrics-transport-'.bin2hex(random_bytes(6));putenv('SAFEHOST_INFRA_METRICS_LOG='.$log);
$gateway=new EngineGateway();infraMetricsCheck($gateway->infrastructureMetrics($owner,101,'pve1','day')===$result);
infraMetricsCheck(json_decode(file_get_contents($log),true,512,JSON_THROW_ON_ERROR)===['action'=>'infrastructure_metrics','account'=>$owner,'vmid'=>101,'node'=>'pve1','timeframe'=>'day']);
infraMetricsCheck((int)ini_get('max_execution_time')===25);
infraMetricsCheck($gateway->metrics(2,11,'day')===$result);
infraMetricsCheck(json_decode(file_get_contents($log),true,512,JSON_THROW_ON_ERROR)===['action'=>'metrics','client_id'=>2,'order_id'=>11,'timeframe'=>'day']);
echo "PASS: actor-only infrastructure metrics, strict request validation, no monitor, exact gateway payload and bounded metrics transport\n";
