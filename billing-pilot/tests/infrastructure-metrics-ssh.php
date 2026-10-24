#!/usr/local/bin/php
<?php
declare(strict_types=1);
$payload=json_decode(file_get_contents('php://stdin'),true,512,JSON_THROW_ON_ERROR);
if(!in_array($payload['action']??'',['metrics','infrastructure_metrics','infrastructure_disk','infrastructure_disk_history'],true)
    ||!in_array('ConnectTimeout=3',$argv,true)||!in_array('ServerAliveInterval=5',$argv,true))throw new RuntimeException('Unexpected metrics transport');
file_put_contents(getenv('SAFEHOST_INFRA_METRICS_LOG'),json_encode($payload,JSON_THROW_ON_ERROR));
$result=$payload['action']==='infrastructure_disk'
    ? ['vmid'=>101,'node'=>'pve1','account'=>'9ac2de9e-e907-42f1-b28d-e65a2c1552a8','mountpoint'=>'/','usedBytes'=>1024,'totalBytes'=>4096,'observedAt'=>'2026-10-24T00:00:00+00:00']
    : ['timeframe'=>'day','start'=>100,'end'=>86500,'points'=>[['timestamp'=>160,'cpuPercent'=>25,'memoryUsedBytes'=>1024,'memoryTotalBytes'=>4096,'networkInBytesPerSecond'=>30,'networkOutBytesPerSecond'=>40]]];
if($payload['action']==='infrastructure_disk_history'){
    $end=1800000000;$duration=$payload['timeframe']==='week'?604800:86400;
    $result=['vmid'=>101,'node'=>'pve1','account'=>'9ac2de9e-e907-42f1-b28d-e65a2c1552a8','mountpoint'=>'/',
        'timeframe'=>$payload['timeframe'],'start'=>$end-$duration,'end'=>$end,'step'=>60,'points'=>[]];
    for($tick=$result['start']+60;$tick<=$end;$tick+=60)$result['points'][]=['timestamp'=>$tick,'usedBytes'=>9007199254740991,'totalBytes'=>9007199254740991];
}
echo json_encode(['ok'=>true,'result'=>$result],JSON_THROW_ON_ERROR);
