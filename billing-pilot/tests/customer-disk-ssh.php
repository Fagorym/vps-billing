#!/usr/local/bin/php
<?php
declare(strict_types=1);
$payload=json_decode(file_get_contents('php://stdin'),true,512,JSON_THROW_ON_ERROR);
if(!in_array($payload['action']??'',['disk_usage','disk_history'],true)
    ||!in_array('ConnectTimeout=3',$argv,true)||!in_array('ServerAliveInterval=5',$argv,true))throw new RuntimeException('Unexpected disk transport');
file_put_contents(getenv('SAFEHOST_CUSTOMER_DISK_LOG'),json_encode($payload,JSON_THROW_ON_ERROR));
$end=1800000000;$duration=$payload['timeframe']==='week'?604800:86400;
$result=['client_id'=>2,'order_id'=>11,'vmid'=>1100,'node'=>'pve1','mountpoint'=>'/',
         'timeframe'=>$payload['timeframe'],'start'=>$end-$duration,'end'=>$end,'step'=>60,'points'=>[]];
for($tick=$result['start']+60;$tick<=$end;$tick+=60)$result['points'][]=['timestamp'=>$tick,'usedBytes'=>9007199254740991,'totalBytes'=>9007199254740991];
echo json_encode(['ok'=>true,'result'=>$result],JSON_THROW_ON_ERROR);
