<?php
declare(strict_types=1);
$complete=false;register_shutdown_function(static function()use(&$complete){if(!$complete)exit(1);});
chdir('/var/www/html');require 'load.php';$di['translate']();require '/opt/pilot/PortalBridge.php';
function checkPublic(bool $ok,string $message):void{if(!$ok)throw new RuntimeException($message);}
function publicUuid():string{$v=bin2hex(random_bytes(16));return substr($v,0,8).'-'.substr($v,8,4).'-'.substr($v,12,4).'-'.substr($v,16,4).'-'.substr($v,20);}
$bridge=new PortalBridge(new FossPortal($di),'/var/www/html/data/portal');
$r=['account'=>publicUuid(),'reference'=>publicUuid(),'plan'=>'mini','network_mode'=>'public_ipv4'];
$lease=$bridge->handle($r+['action'=>'network_reserve']);$r['lease_id']=$lease['id'];
$bridge->handle($r+['action'=>'network_payment_pending']);
$reply=$bridge->handle($r+['action'=>'create']);checkPublic($reply['network_mode']==='public_ipv4'&&$reply['ssh_port']===22,'Public order did not provision direct SSH');
checkPublic($reply['public_ip']==='198.51.100.3','Engine did not assign pool address');
checkPublic($bridge->handle($r+['action'=>'create'])===$reply,'Public order retry changed binding');
checkPublic($bridge->handle($r+['action'=>'network_capacity'])['assigned']===1,'Lease assignment was lost');
$di['loggedin_admin']=$di['db']->getExistingModelById('Admin',1);$di['api_admin']->order_cancel(['id'=>$reply['order_id']]);
$ended=$bridge->handle($r+['action'=>'status']);checkPublic($ended['phase']==='cancelled'&&$ended['public_ip']===null&&$ended['ssh']===null,'Cancelled order kept public access');
checkPublic($bridge->handle($r+['action'=>'network_capacity'])['free']===1,'Confirmed cancellation did not free public address');
echo "PASS: real FOSSBilling public lease, config propagation, direct SSH, retry and cancellation\n";$complete=true;
