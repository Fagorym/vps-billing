#!/usr/local/bin/php
<?php
// Isolated test transport, mounted over SSH only in a network-disabled container.
declare(strict_types=1);
$request=json_decode(file_get_contents('php://stdin'),true,512,JSON_THROW_ON_ERROR);
if(($request['action']??'')!=='mutation_guard')throw new RuntimeException('Unexpected test transport action');
file_put_contents(getenv('SAFEHOST_NATIVE_GUARD_LOG'),json_encode($request)."\n",FILE_APPEND);
if(($request['order_id']??0)===12){echo json_encode(['ok'=>false,'code'=>'refused','error'=>'Infrastructure is read-only']);exit(1);}
echo json_encode(['ok'=>true,'result'=>['mutable'=>true]]);
