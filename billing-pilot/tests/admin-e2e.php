<?php
declare(strict_types=1);
// Real pinned FOSSBilling, HTTP entry point, SQLite queue and root engine; FakePVE only.
$completed = false;
register_shutdown_function(static function () use (&$completed): void { if (!$completed) { exit(1); } });
chdir('/var/www/html'); require 'load.php'; $di['translate']();
require_once '/opt/pilot/AdminBridge.php';
require_once '/opt/pilot/PortalBridge.php';
function verifyAdmin(bool $ok, string $why): void { if (!$ok) { throw new RuntimeException($why); } }
function testUuid(): string { return 'cccccccc-cccc-4ccc-8ccc-' . bin2hex(random_bytes(6)); }
function adminHttp(array $request, ?string $token = null): array {
    $context = stream_context_create(['http'=>['ignore_errors'=>true,'method'=>'POST',
        'header'=>"Content-Type: application/json\r\nAuthorization: Bearer " . ($token ?? getenv('ADMIN_PORTAL_BRIDGE_TOKEN')),
        'content'=>json_encode($request,JSON_THROW_ON_ERROR)]]);
    $body = file_get_contents('http://127.0.0.1/admin-portal.php',false,$context);
    $headers = http_get_last_response_headers();
    return [(int) explode(' ',$headers[0])[1], json_decode($body,true,512,JSON_THROW_ON_ERROR), $headers];
}
function infraTest(): array { return json_decode(file_get_contents('http://mock:8090/'),true,512,JSON_THROW_ON_ERROR); }
final class LoseAdminResponse {
    private bool $lose=true;
    public function __construct(private EngineGateway $engine) {}
    public function action(array $order,string $command,array $r): array {
        $result=$this->engine->action($order,$command,$r);
        if($this->lose){$this->lose=false;throw new RuntimeException('SECRET-RAW-TRANSPORT-FAILURE');}
        return $result;
    }
}
$actor=['account'=>testUuid(),'email'=>'operator@example.test'];
[$code]=adminHttp(['action'=>'dashboard'],getenv('PORTAL_BRIDGE_TOKEN'));
verifyAdmin($code===401,'Owner token authorized admin endpoint');
[$code]=adminHttp(['action'=>'dashboard'],'anonymous'); verifyAdmin($code===401,'Anonymous admin access');
[$code]=adminHttp(['action'=>'dashboard']); verifyAdmin($code===400,'Missing trusted actor accepted');
$account=testUuid();$withoutVm=testUuid();$unknownContact=testUuid();$reference=testUuid();
$start=gmdate('Y-m-d').'T00:00:00Z';$end=gmdate('Y-m-d',time()+86400).'T00:00:00Z';
$profiles=[['account'=>$account,'name'=>'Real Spring Customer','email'=>'actual@example.test','registeredAt'=>$start],
    ['account'=>$withoutVm,'name'=>'Registered Without VM','email'=>'new@example.test','registeredAt'=>'2001-01-01T12:34:56Z'],
    ['account'=>$unknownContact,'name'=>'Legacy Unknown Contact','email'=>null,'registeredAt'=>'2000-01-01T00:00:00Z']];
[$code,$synced]=adminHttp(['action'=>'sync_clients','actor'=>$actor,'clients'=>$profiles]);
verifyAdmin($code===200&&$synced['synced']===3,'Native profile sync with nullable legacy contact failed');
[$code]=adminHttp(['action'=>'sync_clients','actor'=>$actor,'clients'=>$profiles]); verifyAdmin($code===200,'Profile sync replay failed');
[$code]=adminHttp(['action'=>'sync_clients','actor'=>$actor,'clients'=>array_fill(0,201,$profiles[0])]); verifyAdmin($code===400,'Profile chunk bound absent');
$portal=new PortalBridge(new FossPortal($di),'/var/www/html/data/portal');
$create=['action'=>'create','account'=>$account,'reference'=>$reference,'plan'=>'mini'];
$created=$portal->handle($create);$orderId=$created['order_id'];$vmid=$created['vmid'];
$api=$di['api_admin'];$order=$api->order_get(['id'=>$orderId]);$clientId=(int)$order['client_id'];
$native=$api->client_get(['id'=>$clientId]);
verifyAdmin($native['email']==='portal-'.$account.'@safe-host.ru'&&$native['last_name']===$account,'Stable client identity changed');
verifyAdmin($native['billing_email']===$profiles[0]['email']&&$native['first_name']===$profiles[0]['name'],'Real contact was not persisted in FOSS');
verifyAdmin($native['created_at']===str_replace(['T','Z'],[' ',''],$start),'Original registration date was not persisted');
$api->client_update(['id'=>$clientId,'currency'=>'RUB']);
$api->client_balance_add_funds(['id'=>$clientId,'amount'=>12.34,'description'=>'LOCAL TEST native balance']);
$dashboardRequest=['action'=>'dashboard','actor'=>$actor,'dayStart'=>$start,'dayEnd'=>$end];
[$code,$dashboard,$headers]=adminHttp($dashboardRequest); verifyAdmin($code===200,'Real dashboard contract failed');
verifyAdmin(in_array('Cache-Control: no-store',$headers,true),'Admin dashboard is cacheable');
$customer=array_values(array_filter($dashboard['clients'],fn($c)=>$c['account']===$account))[0];
$noVm=array_values(array_filter($dashboard['clients'],fn($c)=>$c['account']===$withoutVm))[0];
$legacy=array_values(array_filter($dashboard['clients'],fn($c)=>$c['account']===$unknownContact))[0];
verifyAdmin($legacy['email']===''&&$legacy['registeredAt']==='2000-01-01T00:00:00Z','Unknown legacy contact became a synthetic real contact');
$knownWithNull=$profiles[0];$knownWithNull['email']=null;
[$code]=adminHttp(['action'=>'sync_clients','actor'=>$actor,'clients'=>[$knownWithNull]]);verifyAdmin($code===200,'Known native contact cannot accept null Spring email');
[$code,$retainedDashboard]=adminHttp($dashboardRequest);
$retained=array_values(array_filter($retainedDashboard['clients'],fn($c)=>$c['account']===$account))[0];
verifyAdmin($code===200&&$retained['email']==='actual@example.test','Null Spring email erased known native billing email');
verifyAdmin($customer['balanceMinor']===1234&&$customer['currency']==='RUB','Native balance/currency source incorrect');
verifyAdmin($customer['email']==='actual@example.test'&&$customer['plans']===['mini']&&$noVm['plans']===[],'Dashboard client identity or grouping incorrect');
verifyAdmin($noVm['registeredAt']==='2001-01-01T12:34:56Z'&&$dashboard['stats']['clientsToday']>=1,'Registration stats lost original date');
verifyAdmin($dashboard['stats']['serversToday']>=1&&$dashboard['hosts'][0]['slotsFree']>=1,'Infrastructure statistics unavailable');
verifyAdmin(!str_contains(json_encode($dashboard),'api_token')&&!str_contains(json_encode($dashboard),'password'),'Dashboard leaks credentials');
$owner=$di['db']->getExistingModelById('Client',$clientId);$clientApi=new \FOSSBilling\Api\Proxy($owner);$clientApi->setDi($di);
$before=infraTest();
foreach(['admin','Admin','archive','restore','purge','monitor','ownerPower','action'] as $method){
    $denied=false;try{$clientApi->servicecustom_call(['order_id'=>$orderId,'method'=>$method,'admin'=>true,'command'=>'purge','confirm_vmid'=>$vmid]);}catch(Throwable $e){$denied=true;}
    verifyAdmin($denied,'Public customCall reached privileged method '.$method);
}
verifyAdmin(infraTest()===$before,'Rejected customCall changed VM');
function queueAdmin(string $command,int $orderId,array $actor,array $extra=[]): array {
    $r=['action'=>'action','operationId'=>testUuid(),'orderId'=>$orderId,'command'=>$command,'reason'=>'Local isolated admin test','actor'=>$actor,...$extra];
    [$code,$op]=adminHttp($r);verifyAdmin($code===200&&$op['state']==='pending','Operation was not durably accepted');return $r;
}
function finishAdmin(AdminBridge $worker,array $r): array {
    verifyAdmin($worker->processOne(true),'Worker did not claim operation');
    [$code,$op]=adminHttp(['action'=>'operation','operationId'=>$r['operationId'],'actor'=>$r['actor']]);
    verifyAdmin($code===200,'Operation status contract failed');return $op;
}
$foss=new FossAdmin($di);$worker=new AdminBridge($foss,new EngineGateway(),'/var/www/html/data/portal');
$r=queueAdmin('block',$orderId,$actor);verifyAdmin(infraTest()['states'][(string)$vmid]==='running','Enqueue performed external mutation');
[$code,$again]=adminHttp($r);verifyAdmin($code===200&&$again['state']==='pending','Same operation did not replay');
$changed=$r;$changed['reason']='Changed payload';[$code]=adminHttp($changed);verifyAdmin($code===409,'Operation UUID changed payload accepted');
verifyAdmin(finishAdmin($worker,$r)['state']==='done','Block worker failed');
$status=['action'=>'status','account'=>$account,'reference'=>$reference];verifyAdmin($portal->handle($status)['phase']==='blocked','Owner block phase absent');
$denied=false;try{$api->order_unsuspend(['id'=>$orderId]);}catch(\FOSSBilling\Exception $e){$denied=true;}
verifyAdmin($denied&&$portal->handle($status)['phase']==='blocked'&&infraTest()['states'][(string)$vmid]==='stopped','Native FOSS unsuspend lifted explicit administrative block');
foreach(['start','password'] as $action){$denied=false;try{$portal->handle([...$status,'action'=>$action]);}catch(DomainException $e){$denied=true;}verifyAdmin($denied,'Owner lifted block or retrieved password');}
$r=queueAdmin('stop',$orderId,$actor);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Stop on block failed');
verifyAdmin((new FossPortal($di))->get($orderId)['status']==='suspended','Stop cleared native administrative block');
$r=queueAdmin('unblock',$orderId,$actor);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Unblock failed');
$r=queueAdmin('stop',$orderId,$actor);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Ordinary admin stop failed');
[$code,$stoppedDashboard]=adminHttp($dashboardRequest);
$stoppedServer=array_values(array_filter($stoppedDashboard['servers'],fn($s)=>$s['orderId']===$orderId))[0];
verifyAdmin($stoppedServer['phase']==='stopped'&&$portal->handle($status)['phase']==='suspended','Admin and owner stopped phase contracts differ');
$r=queueAdmin('start',$orderId,$actor);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Ordinary admin start failed');
// Lost reply after real engine effect must replay the same root receipt, never clone.
$r=queueAdmin('archive',$orderId,$actor);$lostWorker=new AdminBridge($foss,new LoseAdminResponse(new EngineGateway()),'/var/www/html/data/portal');
verifyAdmin(finishAdmin($lostWorker,$r)['state']==='pending','Lost response did not remain retryable');
verifyAdmin($portal->handle($status)['phase']==='archived'&&isset(infraTest()['vms'][(string)$vmid]['scsi0']),'Archive removed disk');
$worker=new AdminBridge(new FossAdmin($di),new EngineGateway(),'/var/www/html/data/portal');
verifyAdmin(finishAdmin($worker,$r)['state']==='done','Durable worker recovery failed');
$r=queueAdmin('restore',$orderId,$actor);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Restore failed');
verifyAdmin($portal->handle($status)['phase']==='ready','Restore readiness absent');
$r=queueAdmin('purge',$orderId,$actor,['confirmVmid'=>$vmid+1]);$failed=finishAdmin($worker,$r);
verifyAdmin($failed['state']==='failed'&&isset(infraTest()['vms'][(string)$vmid]),'Wrong typed VMID mutated VM');
[$code,$dashboard]=adminHttp($dashboardRequest);
$event=array_values(array_filter($dashboard['events'],fn($e)=>$e['id']===$r['operationId']))[0];
verifyAdmin($event['actor']===$actor['email']&&is_string($event['actor'])&&$event['reason']===$r['reason']&&$event['error']!==null,'Audit identity/reason/error missing');
verifyAdmin(!str_contains(json_encode($dashboard),'SECRET-RAW'),'Raw exception leaked into audit');
$r=queueAdmin('purge',$orderId,$actor,['confirmVmid'=>$vmid]);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Purge failed');
verifyAdmin(!isset(infraTest()['vms'][(string)$vmid])&&$portal->handle($status)['phase']==='deleted','Purge did not release managed VM');
$replacement=$portal->handle([...$create,'reference'=>testUuid()]);
verifyAdmin($replacement['vmid']===$vmid&&$replacement['order_id']!==$orderId,'Safe released slot was not reused');
$before=infraTest();[$code,$op]=adminHttp($r);verifyAdmin($code===200&&$op['state']==='done'&&infraTest()===$before,'Old purge replay touched reused slot');
verifyAdmin($portal->handle($status)['phase']==='deleted','Old owner reference touched reused VM');
// Native delete still retains disk. Owner cannot resume it; admin can clean the orphan.
$replacementOrder=$replacement['order_id'];$api->order_delete(['id'=>$replacementOrder]);
$db=new PDO('sqlite:/var/www/html/data/portal/portal.sqlite');$replacementRef=$db->query('SELECT reference FROM orders WHERE order_id='.$replacementOrder)->fetchColumn();
$orphanStatus=['action'=>'status','account'=>$account,'reference'=>$replacementRef];
verifyAdmin($portal->handle($orphanStatus)['phase']==='cancelled'&&isset(infraTest()['vms'][(string)$vmid]['scsi0']),'Native delete became an outage or removed disk');
$denied=false;try{$portal->handle([...$orphanStatus,'action'=>'start']);}catch(DomainException $e){$denied=true;}verifyAdmin($denied,'Owner restored deleted native order');
$r=queueAdmin('archive',$replacementOrder,$actor);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Admin could not archive retained orphan');
$r=queueAdmin('restore',$replacementOrder,$actor);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Admin could not restore retained orphan');
verifyAdmin($portal->handle($orphanStatus)['phase']==='cancelled','Native-deleted owner gained controls after admin restore');
$r=queueAdmin('purge',$replacementOrder,$actor,['confirmVmid'=>$vmid]);verifyAdmin(finishAdmin($worker,$r)['state']==='done','Admin could not safely purge retained orphan');
echo "PASS: real FOSS admin HTTP tokens, profile dates/native balance, privileged customCall/native unsuspend isolation, durable queue/audit, archive recovery, typed purge, tombstones/slot reuse, retained orphan cleanup\n";
$completed=true;
