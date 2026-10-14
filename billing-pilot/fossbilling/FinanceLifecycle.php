<?php
declare(strict_types=1);
require_once __DIR__.'/FinanceGateway.php';

/** Not a Servicecustom adapter: no Client customCall surface. */
final class FinanceLifecycle
{
    private PDO $db; private object $gateway;
    public function __construct(private string $directory,?object $gateway=null,private ?Closure $clientLookup=null)
    {
        if(!is_dir($directory))mkdir($directory,0700,true);
        $this->db=new PDO('sqlite:'.$directory.'/portal.sqlite');$this->db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
        $this->db->exec('PRAGMA busy_timeout=30000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS client(account TEXT PRIMARY KEY,client_id INTEGER NOT NULL UNIQUE)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS orders(reference TEXT PRIMARY KEY,account TEXT NOT NULL UNIQUE,plan TEXT NOT NULL,order_id INTEGER UNIQUE)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS retired_orders(reference TEXT PRIMARY KEY,account TEXT NOT NULL,plan TEXT NOT NULL,order_id INTEGER UNIQUE)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS finance_native(event_key TEXT PRIMARY KEY,id TEXT NOT NULL UNIQUE,request TEXT NOT NULL,state TEXT NOT NULL,effect TEXT,next_attempt TEXT NOT NULL)');
        chmod($directory.'/portal.sqlite',0600);file_put_contents($directory.'/.htaccess',"Require all denied\n");
        $this->gateway=$gateway??new FinanceGateway();
    }
    public static function fromDi($di): self
    {
        return new self('/var/www/html/data/portal',null,static function(int $id)use($di):array{
            $client=$di['em']->getConnection()->fetchAssociative('SELECT email,last_name FROM client WHERE id=?',[$id]);
            if(!$client)throw new RuntimeException('Native client unavailable');return $client;
        });
    }
    public static function runtime(): self
    {
        global $di;
        if(!isset($di))throw new RuntimeException('Finance context unavailable');return self::fromDi($di);
    }
    private function row(string $sql,array $args): array|false {$q=$this->db->prepare($sql);$q->execute($args);return $q->fetch(PDO::FETCH_ASSOC);}
    private function write(string $sql,array $args): void {$q=$this->db->prepare($sql);$q->execute($args);}
    public function ownsPortalOrder(int $id): bool{return (bool)$this->row('SELECT order_id FROM orders WHERE order_id=? UNION ALL SELECT order_id FROM retired_orders WHERE order_id=?',[$id,$id]);}
    private function identity(int $order,int $client): array
    {
        $q=$this->db->prepare('SELECT o.account,o.reference,c.client_id FROM (SELECT * FROM orders UNION ALL SELECT * FROM retired_orders) o LEFT JOIN client c ON c.account=o.account WHERE o.order_id=?');
        $q->execute([$order]);$rows=$q->fetchAll(PDO::FETCH_ASSOC);
        if($rows){
            if(count($rows)!==1||(int)$rows[0]['client_id']!==$client)throw new DomainException('Finance identity mismatch');
            return ['account'=>$rows[0]['account'],'reference'=>$rows[0]['reference']];
        }
        if($this->row('SELECT account FROM client WHERE client_id=?',[$client]))throw new DomainException('Portal order identity missing');
        if(!$this->clientLookup)throw new RuntimeException('Native identity unavailable');
        $native=($this->clientLookup)($client);$email=strtolower($native['email']??'');
        if((str_starts_with($email,'portal-')&&str_ends_with($email,'@safe-host.ru'))
            ||preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/Di',$native['last_name']??''))throw new DomainException('Portal identity missing');
        return ['account'=>null,'reference'=>null];
    }
    private static function uuid(): string
    {
        $s=bin2hex(random_bytes(16));return substr($s,0,8).'-'.substr($s,8,4).'-4'.substr($s,13,3).'-8'.substr($s,17,3).'-'.substr($s,20,12);
    }
    private function base(array $order,string $command,array $context): array
    {
        return ['operationId'=>$context['operationId'],'orderId'=>(int)$order['id'],'clientId'=>(int)$order['client_id'],
            ...$this->identity((int)$order['id'],(int)$order['client_id']),'command'=>$command,'reason'=>$context['reason'],'actor'=>$context['actor']];
    }
    private function send(array $base,string $stage,?array $effect=null): array
    {
        $r=[...$base,'stage'=>$stage];if($effect!==null)$r['effect']=['phase'=>$effect['phase'],'status'=>$effect['status']];
        return $this->gateway->exchange($r);
    }
    public function prepare(array $order,string $command,array $context): void {$this->send($this->base($order,$command,$context),'prepare');}
    public function complete(array $order,string $command,array $context,array $effect): void {$this->send($this->base($order,$command,$context),'complete',$effect);}
    public function check(array $order,string $command,?array $context=null): void
    {
        $context??=['operationId'=>self::uuid(),'reason'=>'Native FOSSBilling permission check','actor'=>['source'=>'FOSSBilling']];
        $this->send($this->base($order,$command,$context),'check');
    }
    public function prepareNative(array $order,string $event): array
    {
        if(!in_array($event,['cancel','delete'],true))throw new InvalidArgumentException('Invalid native event');
        $state=[];foreach(['status','activated_at','canceled_at','unsuspended_at','updated_at']as$key)$state[$key]=$order[$key]??null;
        if($this->row("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_operation'",[])){
            $restore=$this->row("SELECT id FROM admin_operation WHERE order_id=? AND command='restore' AND state IN ('running','done') ORDER BY created_at DESC,id DESC LIMIT 1",[(int)$order['id']]);
            $state['restoreGeneration']=$restore['id']??null;
        }
        $key=hash('sha256',json_encode([(int)$order['id'],(int)$order['client_id'],$event,$state],JSON_THROW_ON_ERROR));
        $old=$this->row('SELECT * FROM finance_native WHERE event_key=?',[$key]);
        if(!$old){
            $hex=hash('sha256','safehost-finance-native-v1:'.$key);
            $id=substr($hex,0,8).'-'.substr($hex,8,4).'-5'.substr($hex,13,3).'-8'.substr($hex,17,3).'-'.substr($hex,20,12);
            $context=['operationId'=>$id,'reason'=>'Native FOSSBilling '.$event,'actor'=>['source'=>'FOSSBilling']];
            $base=$this->base($order,'cancel',$context);
            $this->write('INSERT OR IGNORE INTO finance_native VALUES(?,?,?,?,?,?)',[$key,$id,json_encode($base,JSON_THROW_ON_ERROR),'pending',null,gmdate('c')]);
            $old=$this->row('SELECT * FROM finance_native WHERE event_key=?',[$key]);
        }
        $base=json_decode($old['request'],true,512,JSON_THROW_ON_ERROR);
        try{$this->send($base,'prepare');}catch(DomainException $e){$this->write('UPDATE finance_native SET state=? WHERE id=?',['denied',$base['operationId']]);throw $e;}
        if(in_array($old['state'],['pending','denied'],true))$this->write('UPDATE finance_native SET state=? WHERE id=?',['prepared',$base['operationId']]);
        return $base;
    }
    public function native(array $order,string $event,callable $effect): void
    {
        $base=$this->prepareNative($order,$event);$row=$this->row('SELECT * FROM finance_native WHERE id=?',[$base['operationId']]);
        if($row['state']!=='effected'){
            $result=$effect();$this->write('UPDATE finance_native SET state=?,effect=? WHERE id=?',['effected',json_encode(['phase'=>$result['phase'],'status'=>$result['status']]),$base['operationId']]);
        }
        $this->finishNative($base);
    }
    private function finishNative(array $base): void
    {
        $row=$this->row('SELECT effect FROM finance_native WHERE id=?',[$base['operationId']]);
        $this->send($base,'complete',json_decode($row['effect'],true,512,JSON_THROW_ON_ERROR));
        $this->write('UPDATE finance_native SET state=? WHERE id=?',['done',$base['operationId']]);
    }
    public function processNativeOne(object $engine,bool $force=false): bool
    {
        $row=$this->row("SELECT * FROM finance_native WHERE state IN ('pending','prepared','effected')".($force?'':' AND next_attempt<=?').' ORDER BY id LIMIT 1',$force?[]:[gmdate('c')]);
        if(!$row)return false;$base=json_decode($row['request'],true,512,JSON_THROW_ON_ERROR);
        try{
            if($row['state']!=='effected'){
                $this->send($base,'prepare');$effect=$engine->cancel($base['clientId'],$base['orderId']);
                $this->write('UPDATE finance_native SET state=?,effect=? WHERE id=?',['effected',json_encode(['phase'=>$effect['phase'],'status'=>$effect['status']]),$base['operationId']]);
            }
            $this->finishNative($base);
        }catch(DomainException $e){$this->write('UPDATE finance_native SET state=? WHERE id=?',['denied',$base['operationId']]);}
        catch(Throwable $e){$this->write('UPDATE finance_native SET next_attempt=? WHERE id=?',[gmdate('c',time()+30),$base['operationId']]);}
        return true;
    }
}
