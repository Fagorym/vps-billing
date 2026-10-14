<?php
declare(strict_types=1);
require '/opt/pilot/FinanceLifecycle.php';
function financeAssert(bool $ok): void {if(!$ok)throw new RuntimeException('Finance contract failed');}
function financeDenied(callable $call,string $type): void {try{$call();throw new LogicException('Expected failure');}catch(Throwable $e){financeAssert($e instanceof $type);}}
final class FakeFinance {
 public array $calls=[];public bool $deny=false;public bool $loseComplete=false;public $verify;
 public function exchange(array $r): array {
  if($this->verify)($this->verify)($r);$this->calls[]=$r;
  if($this->deny)throw new DomainException('denied');
  if($this->loseComplete&&$r['stage']==='complete'){$this->loseComplete=false;throw new RuntimeException('SECRET-upstream');}
  return ['ok'=>true,'paidService'=>true,'state'=>$r['stage']==='complete'?'done':'prepared'];
 }
}
$dir=sys_get_temp_dir().'/finance-'.bin2hex(random_bytes(6));$gateway=new FakeFinance();
$lookup=fn(int $id)=>['email'=>$id===8?'portal-11111111-1111-4111-8111-111111111111@safe-host.ru':'real@example.test','last_name'=>$id===10?'11111111-1111-4111-8111-111111111111':'Native'];
$f=new FinanceLifecycle($dir,$gateway,$lookup);$db=new PDO('sqlite:'.$dir.'/portal.sqlite');
$db->exec("INSERT INTO client VALUES('11111111-1111-4111-8111-111111111111',7);INSERT INTO orders VALUES('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','mini',4)");
$gateway->verify=function($r)use($db){$db->exec('BEGIN IMMEDIATE');$db->exec('ROLLBACK');};
$order=['id'=>4,'client_id'=>7,'status'=>'active','activated_at'=>'2026-10-13 00:00:00'];
$ctx=['operationId'=>'33333333-3333-4333-8333-333333333333','reason'=>'Archive requested','actor'=>['account'=>'44444444-4444-4444-8444-444444444444','email'=>'operator@example.test']];
$f->prepare($order,'archive',$ctx);$f->complete($order,'archive',$ctx,['phase'=>'archived','status'=>'stopped']);
financeAssert($gateway->calls[0]['account']==='11111111-1111-4111-8111-111111111111'&&$gateway->calls[0]['reference']==='22222222-2222-4222-8222-222222222222');
financeAssert($gateway->calls[1]['operationId']===$ctx['operationId']&&$gateway->calls[1]['effect']===['phase'=>'archived','status'=>'stopped']);
financeDenied(fn()=>$f->prepare(['id'=>4,'client_id'=>9],'purge',$ctx),DomainException::class);
financeDenied(fn()=>$f->check(['id'=>5,'client_id'=>8],'activate'),DomainException::class);
financeDenied(fn()=>$f->check(['id'=>5,'client_id'=>10],'activate'),DomainException::class);
$f->check(['id'=>5,'client_id'=>9],'activate');financeAssert(end($gateway->calls)['account']===null&&end($gateway->calls)['reference']===null);
$gateway->deny=true;financeDenied(fn()=>$f->prepare($order,'purge',$ctx),DomainException::class);$gateway->deny=false;
$native=$f->prepareNative($order,'delete');financeAssert($native['actor']===['source'=>'FOSSBilling']);
$effects=0;$gateway->loseComplete=true;
financeDenied(function()use($f,$order,&$effects){$f->native($order,'delete',function()use(&$effects){$effects++;return ['phase'=>'cancelled','status'=>'stopped'];});},RuntimeException::class);
$again=$f->prepareNative($order,'delete');financeAssert($again['operationId']===$native['operationId']);
$f=new FinanceLifecycle($dir,$gateway,$lookup);
financeAssert($f->processNativeOne(new class{public function cancel(int $c,int $o):array{throw new LogicException('Effect was already persisted');}},true));
financeAssert($effects===1);$done=end($gateway->calls);financeAssert($done['stage']==='complete'&&$done['operationId']===$native['operationId']);
$cancel=$f->prepareNative($order,'cancel');financeAssert($cancel['operationId']!==$native['operationId']);
$db->exec('CREATE TABLE admin_operation(id TEXT,order_id INTEGER,command TEXT,state TEXT,created_at TEXT)');
$db->exec("INSERT INTO admin_operation VALUES('55555555-5555-4555-8555-555555555555',4,'restore','done','2026-10-14T00:00:00Z')");
$later=$f->prepareNative($order,'delete');financeAssert($later['operationId']!==$native['operationId']);
putenv('ADMIN_FINANCE_URL=http://example.test/api');putenv('ADMIN_FINANCE_TOKEN=finance-test-token-that-is-long-enough');
financeDenied(fn()=>(new FinanceGateway())->exchange([]),RuntimeException::class);
putenv('ADMIN_FINANCE_URL=http://127.0.0.1/api');putenv('PORTAL_BRIDGE_TOKEN=finance-test-token-that-is-long-enough');
financeDenied(fn()=>(new FinanceGateway())->exchange([]),RuntimeException::class);
echo "PASS: finance identity/fail-closed gates, immutable native IDs, durable completion recovery, separate secret and URL constraints, no SQLite transaction across callback\n";
