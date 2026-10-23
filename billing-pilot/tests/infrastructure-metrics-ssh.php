#!/usr/local/bin/php
<?php
declare(strict_types=1);
$payload=json_decode(file_get_contents('php://stdin'),true,512,JSON_THROW_ON_ERROR);
if(!in_array($payload['action']??'',['metrics','infrastructure_metrics'],true)
    ||!in_array('ConnectTimeout=3',$argv,true)||!in_array('ServerAliveInterval=5',$argv,true))throw new RuntimeException('Unexpected metrics transport');
file_put_contents(getenv('SAFEHOST_INFRA_METRICS_LOG'),json_encode($payload,JSON_THROW_ON_ERROR));
echo json_encode(['ok'=>true,'result'=>['timeframe'=>'day','start'=>100,'end'=>86500,'points'=>[['timestamp'=>160,'cpuPercent'=>25,'memoryUsedBytes'=>1024,'memoryTotalBytes'=>4096,'networkInBytesPerSecond'=>30,'networkOutBytesPerSecond'=>40]]]],JSON_THROW_ON_ERROR);
