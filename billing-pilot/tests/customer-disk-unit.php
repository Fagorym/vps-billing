<?php
declare(strict_types=1);
require '/opt/pilot/PortalBridge.php';
require '/opt/pilot/EngineGateway.php';
function diskCheck(bool $ok):void{if(!$ok)throw new RuntimeException('Customer disk contract failed');}
function diskDenied(callable $call,string $type):void{try{$call();throw new LogicException('Expected denial');}catch(Throwable $error){diskCheck($error instanceof $type);}}
$account='11111111-1111-4111-8111-111111111111';$reference='22222222-2222-4222-8222-222222222222';
$foss=new class{
    public int $client=2;public array $calls=[];public bool $missing=false;public bool $change=false;
    public array $result=['client_id'=>2,'order_id'=>11,'vmid'=>1100,'node'=>'pve1','mountpoint'=>'/','usedBytes'=>0,'totalBytes'=>4096,'observedAt'=>'2026-10-24T00:00:00+00:00'];
    public function get(int $id):array{if($this->missing)throw new OutOfBoundsException();return ['id'=>$id,'client_id'=>$this->client,'status'=>'active'];}
    public function disk(int $client,int $order,string $action,?string $period):array{
        $this->calls[]=['client_id'=>$client,'order_id'=>$order,'action'=>$action,'timeframe'=>$period];
        if($this->change)$this->client=3;
        return $this->result;
    }
};
$directory=sys_get_temp_dir().'/customer-disk-'.bin2hex(random_bytes(6));$bridge=new PortalBridge($foss,$directory);
$db=new PDO('sqlite:'.$directory.'/portal.sqlite');
$db->prepare('INSERT INTO client VALUES(?,?)')->execute([$account,2]);
$db->prepare('INSERT INTO orders(reference,account,plan,order_id) VALUES(?,?,?,?)')->execute([$reference,$account,'mini',11]);
$before=hash_file('sha256',$directory.'/portal.sqlite');
$request=['action'=>'disk_usage','account'=>$account,'reference'=>$reference,'timeframe'=>null,'client_id'=>99,'order_id'=>98];
$result=$bridge->handle($request);diskCheck($result['account']===$account&&$result['reference']===$reference&&$result['order_id']===11);
diskCheck($foss->calls===[['client_id'=>2,'order_id'=>11,'action'=>'disk_usage','timeframe'=>null]]);
$foss->result+=['account'=>'untrusted','reference'=>'untrusted'];diskCheck($bridge->handle($request)['account']===$account);
foreach([['account'=>'33333333-3333-4333-8333-333333333333'],['reference'=>'33333333-3333-4333-8333-333333333333']] as $invalid){
    diskDenied(fn()=>$bridge->handle(array_replace($request,$invalid)),OutOfBoundsException::class);
}
foreach([['timeframe'=>'day'],['timeframe'=>[]],['action'=>'disk_history'],['action'=>'disk_history','timeframe'=>'month']] as $invalid){
    diskDenied(fn()=>$bridge->handle(array_replace($request,$invalid)),InvalidArgumentException::class);
}
$valid=$foss->result;
foreach([['client_id'=>3],['client_id'=>'2'],['order_id'=>12],['vmid'=>true],['node'=>'bad/node'],['mountpoint'=>'/data']] as $invalid){
    $foss->result=array_replace($valid,$invalid);diskDenied(fn()=>$bridge->handle($request),DomainException::class);
}
$foss->result=$valid;$foss->client=3;$count=count($foss->calls);
diskDenied(fn()=>$bridge->handle($request),DomainException::class);diskCheck(count($foss->calls)===$count);
$foss->client=2;$foss->missing=true;diskDenied(fn()=>$bridge->handle($request),DomainException::class);$foss->missing=false;
$foss->change=true;diskDenied(fn()=>$bridge->handle($request),DomainException::class);$foss->change=false;$foss->client=2;
diskCheck(hash_file('sha256',$directory.'/portal.sqlite')===$before);
$log=sys_get_temp_dir().'/customer-disk-transport-'.bin2hex(random_bytes(6));putenv('SAFEHOST_CUSTOMER_DISK_LOG='.$log);
$gateway=new EngineGateway();$week=$gateway->disk(2,11,'disk_history','week');
diskCheck(count($week['points'])===10080&&strlen(json_encode(['ok'=>true,'result'=>$week],JSON_THROW_ON_ERROR))<1048576);
diskCheck(json_decode(file_get_contents($log),true,512,JSON_THROW_ON_ERROR)===['action'=>'disk_history','client_id'=>2,'order_id'=>11,'timeframe'=>'week']);
diskCheck((int)ini_get('max_execution_time')===25);
$nativeApi=new class{
    public int $reads=0;public bool $change=false;
    public function order_get(array $request):array{
        $this->reads++;
        return ['id'=>$request['id'],'client_id'=>$this->change&&$this->reads%2===0?3:2];
    }
};
$connection=new class{public function fetchOne(string $sql,array $args):int{return 1;}};
$em=new class($connection){public function __construct(private object $connection){}public function clear():void{}public function getConnection():object{return $this->connection;}};
$nativeDb=new class{public function getExistingModelById(string $type,int $id):object{return (object)['id'=>$id];}};
$di=new ArrayObject(['em'=>$em,'db'=>$nativeDb,'api_admin'=>$nativeApi]);$native=new FossPortal($di);
diskCheck($native->disk(2,11,'disk_history','week')['order_id']===11&&$nativeApi->reads===2);
$nativeApi->change=true;diskDenied(fn()=>$native->disk(2,11,'disk_history','week'),DomainException::class);
echo "PASS: trusted account/reference/native binding, exact root IDs, fresh owner checks, no effects and bounded full-week payload\n";
