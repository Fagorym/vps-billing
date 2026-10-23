<?php
declare(strict_types=1);
namespace FOSSBilling { interface InjectionAwareInterface {} }
namespace Pimple { class Container extends \ArrayObject {} }
namespace {
class Box_Event extends ArrayObject {
    public function __construct(private $di,int $id){parent::__construct(['id'=>$id]);}
    public function getDi(){return $this->di;}
}
require '/opt/pilot/Safehostfinance/Service.php';
function nativeGuardCheck(bool $ok):void{if(!$ok)throw new RuntimeException('Native pre-event guard failed');}
$log=sys_get_temp_dir().'/native-guard-'.bin2hex(random_bytes(6));putenv('SAFEHOST_NATIVE_GUARD_LOG='.$log);
$db=new class{public function getExistingModelById(string $type,int $id):object{return(object)['id'=>$id];}};
$connection=new class{public string $plugin='SafehostProxmox';public function fetchOne(string $sql,array $args):string{return $this->plugin;}};
$em=new class($connection){public function __construct(private $connection){} public function getConnection():object{return $this->connection;}};
$orders=new class{public function toApiArray(object $order):array{return['id'=>$order->id,'client_id'=>16,'status'=>'active'];}};
$di=['db'=>$db,'em'=>$em,'mod_service'=>fn(string $name)=>$orders];
$events=['Activate','Renew','Suspend','Unsuspend','Uncancel','Update','Delete','Cancel'];
foreach($events as $event){
    $method='onBeforeAdminOrder'.$event;$nativeStatus='active';$denied=false;
    try{\Box\Mod\Safehostfinance\Service::$method(new Box_Event($di,12));$nativeStatus='changed';}
    catch(DomainException $expected){$denied=true;}
    nativeGuardCheck($denied&&$nativeStatus==='active');
}
$history=new PDO('sqlite:/var/www/html/data/portal/portal.sqlite');
nativeGuardCheck((int)$history->query('SELECT COUNT(*) FROM finance_native')->fetchColumn()===0);
foreach(['Activate','Renew','Suspend','Unsuspend','Uncancel','Update'] as $event){
    $method='onBeforeAdminOrder'.$event;\Box\Mod\Safehostfinance\Service::$method(new Box_Event($di,11));
}
$before=count(file($log));$connection->plugin='OtherProduct';
foreach($events as $event){$method='onBeforeAdminOrder'.$event;\Box\Mod\Safehostfinance\Service::$method(new Box_Event($di,20));}
nativeGuardCheck(count(file($log))===$before);
echo "PASS: native pre-event guards reject registered lifecycle/update before state or finance changes; ordinary and unmanaged orders retain behavior\n";
}
